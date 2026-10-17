import json
import shutil

import pytest

from src.pipeline.gate import collect_files
from src.pipeline.spec import TEMPLATE_SCHEMA, build_template_spec
from src.pipeline.synthesize import synthesize
from tests.test_synthesize import FIXTURES, ROOT, write_logs


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
