import json
import shutil

import pytest

from src.pipeline.gate import collect_files
from src.pipeline.spec import TEMPLATE_SCHEMA, build_template_spec
from src.pipeline.synthesize import synthesize
from tests.test_synthesize import FIXTURES, KNOWN_GOOD_RULE, ROOT, write_logs


def test_the_template_schema_allows_exactly_what_the_template_builder_accepts():
    answer = {"message": "m", "event": {"pattern": "free($P)", "variable": "$P"},
              "uses": ["$P->$F", {"pattern": "$F2($P)", "focus": "$P", "not": ["free(...)"], "not_inside": ["free($X)"]}],
              "resets": [{"pattern": "$P = ...", "variable": "$P"}]}
    spec, problems = build_template_spec(answer)
    assert problems == [] and spec["taint"]["sinks"]
    props = TEMPLATE_SCHEMA["properties"]
    assert set(answer) <= set(props) and set(TEMPLATE_SCHEMA["required"]) == {"message", "event", "uses"}
    assert TEMPLATE_SCHEMA["additionalProperties"] is False
    assert set(props["uses"]["items"]["anyOf"][1]["properties"]) == {"pattern", "focus", "not", "not_inside"}


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_grammar_passes_the_schema_to_every_model_call(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    seen = []

    def fake_complete(role, prompt, json_schema=None):
        seen.append(json_schema)
        return json.dumps({"message": "m", "event": {"pattern": "free($P)", "variable": "$P"}, "uses": ["$P[...]"]}), 0.0

    synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0, rules_dir=tmp_path / "rules",
               logs_dir=tmp_path / "synthesis", max_fix_attempts=1, output_format="template", grammar=True)
    assert seen and all(s is TEMPLATE_SCHEMA for s in seen)
    with pytest.raises(ValueError, match="template and form formats only"):
        synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, rules_dir=tmp_path / "rules",
                   logs_dir=tmp_path / "synthesis", output_format="yaml", grammar=True)


FILLED_FORM = '''rules:
  - id: gen-cwe-457
    languages:
      - c
    severity: ERROR
    message: "A variable is used before it is given a value."
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: "$T $X;"
          - focus-metavariable: $X
        by-side-effect: true
    pattern-sinks:
      - patterns:
          - pattern: "$F($X)"
          - pattern-not-inside: "$X = ..."
          - focus-metavariable: $X
    pattern-sanitizers:
      - patterns:
          - pattern: "$X = ..."
          - focus-metavariable: $X
        by-side-effect: true
'''


def test_the_skeleton_and_a_filled_form_are_rules_the_yaml_parser_accepts():
    from src.pipeline.form import SKELETON, grammar
    from src.pipeline.rules import parse_response
    assert "focus-metavariable: $X" in grammar("CWE-457") and "gen-cwe-457" in grammar("CWE-457")
    assert grammar("CWE-457").count("focus-metavariable: $X") == 3  # source, sink, sanitizer: fixed, not a slot
    yaml_text, rule_doc, problems = parse_response(FILLED_FORM, "gen-cwe-457", "CWE-457", set())
    assert problems == [] and rule_doc["rules"][0]["mode"] == "taint"
    assert "<the statement" in SKELETON and "{{FORM}}" in (ROOT / "prompts" / "form_generator.md").read_text(encoding="utf-8")


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_form_format_runs_through_the_loop_and_holds_the_decoder_to_the_grammar(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    seen = []

    def fake_complete(role, prompt, grammar=None):
        seen.append((role, prompt, grammar))
        return FILLED_FORM, 0.0

    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=0,
                     output_format="form", grammar=True)
    role, prompt, held = seen[0]
    assert held and held.startswith("root ::=") and "gen-cwe-416" in held
    assert "The form you fill in" in prompt and "<the statement that puts $X in a state>" in prompt and "{{" not in prompt
    assert run["attempts"][0]["rule_source"].startswith("rules:")


SEARCH_FORM = r'''rules:
  - id: gen-cwe-457
    languages:
      - c
    severity: ERROR
    message: "A variable is used before it is given a value."
    patterns:
      - pattern-either:
          - pattern: "$T $X;\n...\n$F($X);"
      - pattern-not: "$T $X;\n...\n$X = ...;\n...\n$F($X);"
      - focus-metavariable: $X
'''


def test_search_form_is_a_rule_and_the_grammars_compile():
    from src.pipeline.form import SEARCH_SKELETON, grammar, search_grammar
    from src.pipeline.rules import parse_response
    yaml_text, rule_doc, problems = parse_response(SEARCH_FORM, "gen-cwe-457", "CWE-457", set())
    assert problems == [] and "pattern-either" in str(rule_doc)
    assert "pattern-either" in search_grammar("CWE-457") and "\\n" in search_grammar("CWE-457")
    assert "<code that is the weakness>" in SEARCH_SKELETON and "{{FORM}}" in (ROOT / "prompts" / "formsearch_generator.md").read_text(encoding="utf-8")
    try:
        from src.agents.agents_general import Llama  # noqa: F401  (registers the CUDA path first)
        from llama_cpp import LlamaGrammar
    except ImportError:
        pytest.skip("llama_cpp not installed")
    LlamaGrammar.from_string(search_grammar("CWE-457"), verbose=False)
    LlamaGrammar.from_string(grammar("CWE-457"), verbose=False)


def test_fields_walks_the_taint_form_in_document_order():
    from src.pipeline.form import describe_field, fields, get_field
    from src.pipeline.rules import parse_response
    _, rule_doc, problems = parse_response(FILLED_FORM, "gen-cwe-457", "CWE-457", set())
    assert problems == []
    found = fields(rule_doc)
    assert [describe_field(p, k) for p, k, _ in found] == [
        "the taint source: the statement that puts $X in a tainted state",
        "sink 1: a use of $X that is a problem",
        "sink 1's pattern-not-inside: code in which that use does not count",
        "sanitizer 1: a statement that puts $X back in a clean state",
    ]
    assert [v for _, _, v in found] == ["$T $X;", "$F($X)", "$X = ...", "$X = ..."]
    path, key, value = found[0]
    assert get_field(rule_doc, path, key) == value == "$T $X;"


def test_fields_walks_the_search_form_in_document_order():
    from src.pipeline.form import describe_field, fields
    from src.pipeline.rules import parse_response
    _, rule_doc, problems = parse_response(SEARCH_FORM, "gen-cwe-457", "CWE-457", set())
    assert problems == []
    found = fields(rule_doc)
    assert [describe_field(p, k) for p, k, _ in found] == [
        "alternative 1 of the weakness (pattern-either)",
        "a pattern-not: code of the same shape that is safe",
    ]


def test_set_field_changes_only_that_one_field_and_does_not_touch_the_original():
    from src.pipeline.form import fields, set_field
    from src.pipeline.rules import dump_rule, parse_response
    _, rule_doc, _ = parse_response(FILLED_FORM, "gen-cwe-457", "CWE-457", set())
    path, key, old_value = fields(rule_doc)[1]  # sink 1's pattern
    assert old_value == "$F($X)"
    new_doc = set_field(rule_doc, path, key, "$F2($X)")
    assert new_doc["rules"][0]["pattern-sinks"][0]["patterns"][0]["pattern"] == "$F2($X)"
    assert rule_doc["rules"][0]["pattern-sinks"][0]["patterns"][0]["pattern"] == "$F($X)"  # untouched
    assert dump_rule(new_doc) == dump_rule(rule_doc).replace("$F($X)", "$F2($X)")


def test_parse_field_value_accepts_the_grammars_quoting_and_rejects_garbage():
    from src.pipeline.form import parse_field_value
    value, problems = parse_field_value('"int $X;\\n...\\n$X = $X;"\n')  # a trailing newline, as a model answer may have
    assert problems == [] and value == "int $X;\n...\n$X = $X;"
    value, problems = parse_field_value("not a quoted string")
    assert value is None and problems


def test_apply_field_relints_the_spliced_rule():
    from src.pipeline.form import apply_field, fields
    from src.pipeline.rules import parse_response
    _, rule_doc, _ = parse_response(FILLED_FORM, "gen-cwe-457", "CWE-457", set())
    path, key, _ = fields(rule_doc)[1]  # sink 1's pattern
    _, new_doc, problems = apply_field('"free(data)"', rule_doc, path, key, {"data"})
    assert new_doc is not None and new_doc["rules"][0]["pattern-sinks"][0]["patterns"][0]["pattern"] == "free(data)"
    assert any("`data`" in p for p in problems)  # the same lint a full rewrite would get, for an example-specific name
    _, no_doc, problems = apply_field("not a quoted string", rule_doc, path, key, {"data"})
    assert no_doc is None and problems


def test_field_correct_is_defined_for_form_formsearch_and_yaml_only():
    with pytest.raises(ValueError, match="form, formsearch and yaml formats only"):
        synthesize("CWE-416", "A", [], [], [], output_format="template", field_correct=True)


def test_describe_field_distinguishes_pattern_not_from_pattern_not_inside_under_a_sink():
    from src.pipeline.form import describe_field
    assert describe_field(["pattern-sinks", 0, "patterns", 0], "pattern-not") == \
        "sink 1's pattern-not: code of the same shape that does not count"
    assert describe_field(["pattern-sinks", 0, "patterns", 0], "pattern-not-inside") == \
        "sink 1's pattern-not-inside: code in which that use does not count"


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_field_correct_works_on_the_yaml_format_too(tmp_path, monkeypatch):
    """field_correct's field walk is structure-agnostic, so it also applies to a hand-written yaml rule
    (not just the fixed form/formsearch skeletons) - the known-good CWE-416 fixture exercises its nested
    pattern-either/metavariable-pattern shape, which the form/formsearch grammars never produce."""
    from src.pipeline.form import FIELD_GRAMMAR
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    calls = []
    known = KNOWN_GOOD_RULE.read_text()

    def fake_complete(role, prompt, grammar=None):
        calls.append((role, prompt, grammar))
        if len(calls) == 1:
            return f"```yaml\n{known}```", 0.0
        return '"free(data_dup)"', 0.0  # whatever field is asked next gets this new value

    # min_recall above 1.0 can never be reached, so attempt 0 always fails and a correction always happens
    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=1.1,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=1,
                     output_format="yaml", field_correct=True)

    assert len(calls) == 2
    role, prompt, held = calls[1]
    assert role == "corrector" and held == FIELD_GRAMMAR
    assert "Change only this field" in prompt
    attempt0, attempt1 = run["attempts"]
    assert "rule_doc" not in attempt0 and "rule_doc" not in attempt1
    assert attempt1["rule_source"] != attempt0["rule_source"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_field_correct_falls_back_to_a_full_rewrite_when_the_shape_itself_is_wrong(tmp_path, monkeypatch):
    """A field edit can only change what a pattern says, never where an operator sits: a structurally invalid
    rule (metavariable-pattern at the top level, here) cannot be fixed by editing one field's value, so
    field_correct must fall back to the ordinary corrector instead of looping uselessly on a field."""
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    broken = """```yaml
rules:
  - id: x
    languages: [c]
    pattern: free($P)
    metavariable-pattern:
      metavariable: $P
      patterns:
        - pattern-not: "&$Y"
```"""
    calls = []

    def fake_complete(role, prompt, grammar=None):
        calls.append((role, prompt, grammar))
        return broken, 0.0

    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=1,
                     output_format="yaml", field_correct=True)

    assert len(calls) == 2
    role, prompt, held = calls[1]
    assert role == "corrector" and held is None
    assert "write the complete corrected rule" in prompt


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_field_correct_asks_for_one_field_at_a_time_instead_of_the_whole_rule(tmp_path, monkeypatch):
    from src.pipeline.form import FIELD_GRAMMAR
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    calls = []

    def fake_complete(role, prompt, grammar=None):
        calls.append((role, prompt, grammar))
        if len(calls) == 1:
            return FILLED_FORM, 0.0
        return '"$F2($X)"', 0.0  # whatever field is asked next gets this new value

    # min_recall above 1.0 can never be reached, so attempt 0 always fails and a correction always happens
    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=1.1,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=1,
                     output_format="form", field_correct=True)

    assert len(calls) == 2
    assert calls[0][2] is None  # the generator is not grammar-held unless --grammar is also given
    role, prompt, held = calls[1]
    assert role == "corrector" and held == FIELD_GRAMMAR
    assert "Change only this field" in prompt and "the taint source" in prompt  # field 0, by document order, is the source

    attempt0, attempt1 = run["attempts"]
    assert "rule_doc" not in attempt0 and "rule_doc" not in attempt1  # the in-memory splice target is not logged
    assert attempt1["rule_source"] == attempt0["rule_source"].replace("$T $X;", "$F2($X)")
