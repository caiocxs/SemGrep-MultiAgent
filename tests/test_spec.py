import json
import shutil
from pathlib import Path

import pytest
import yaml

from src.pipeline.gate import collect_files
from src.pipeline.rules import dump_rule
from src.pipeline.spec import extract_json, parse_response
from src.pipeline.synthesize import load_pattern_docs, synthesize
from tests.test_synthesize import FIXTURES, ROOT, write_logs

TAINT_SPEC = {
    "message": "Pointer used after free",
    "taint": {
        "sources": [{"pattern": "free($P)", "focus": "$P", "by_side_effect": True}],
        "sanitizers": [{"pattern": "$P = $E", "focus": "$P", "by_side_effect": True}],
        "sinks": [
            {"pattern": "$X[$I]"},
            {"pattern": "*$X"},           # unquoted in YAML this is an alias: the reason for this mode
            {"pattern": "$X->$FLD"},
            {"pattern": "$F(..., $X, ...)", "focus": "$X", "not": ["free(...)"]},
        ],
    },
}


def parse(spec_or_text):
    text = spec_or_text if isinstance(spec_or_text, str) else f"Plan.\n```json\n{json.dumps(spec_or_text)}\n```"
    return parse_response(text, "gen-cwe-416", "CWE-416", set())


def test_extract_json_from_block_or_bare_object():
    assert json.loads(extract_json('x\n```json\n{"a": 1}\n```')) == {"a": 1}
    assert json.loads(extract_json('answer: {"a": 1} done')) == {"a": 1}
    assert extract_json("no json here") is None


def test_taint_spec_builds_valid_yaml_with_quoted_star():
    spec_text, rule_doc, problems = parse(TAINT_SPEC)
    assert problems == []
    rule = rule_doc["rules"][0]
    assert rule["mode"] == "taint" and rule["languages"] == ["c"] and rule["id"] == "gen-cwe-416"
    assert rule["pattern-sources"] == [
        {"patterns": [{"pattern": "free($P)"}, {"focus-metavariable": "$P"}], "by-side-effect": True}]
    assert {"pattern": "*$X"} in rule["pattern-sinks"]
    assert rule["pattern-sinks"][3]["patterns"][1] == {"pattern-not": "free(...)"}
    # The dumped YAML must load back to the same rule (the `*` is quoted).
    assert yaml.safe_load(dump_rule(rule_doc)) == rule_doc
    assert json.loads(spec_text) == TAINT_SPEC


def test_search_spec_with_exclusions():
    _, rule_doc, problems = parse({
        "message": "m",
        "search": {"pattern": "a($X);\nb($X);", "not": ["b(0);"], "not_inside": ["if (...) {\n...\n}"]},
    })
    assert problems == []
    rule = rule_doc["rules"][0]
    assert rule["patterns"][0] == {"pattern": "a($X);\nb($X);"}
    assert {"pattern-not": "b(0);"} in rule["patterns"] and len(rule["patterns"]) == 3


def test_spec_problems_are_explained():
    assert "No JSON spec" in parse("just words")[2][0]
    assert "JSON syntax error" in parse('```json\n{"a": }\n```')[2][0]
    problems = parse({"message": "m", "taint": {"sources": [{"pattern": "f($X)", "by_side_effect": True}],
                                                "sinks": [{"pattern": ""}], "extra": 1}})[2]
    assert any("`by_side_effect` needs `focus`" in p for p in problems)
    assert any("sinks[0].pattern must be a non-empty" in p for p in problems)
    assert any("unknown keys `extra`" in p for p in problems)
    assert any("Give exactly one of" in p for p in parse({"message": "m"})[2])
    assert any("`taint.sinks` is required" in p for p in parse({"taint": {"sources": [{"pattern": "f($X)"}]}})[2])


def test_spec_rules_go_through_the_same_checks():
    # Missing `;` in a multi-line pattern and example names are still reported.
    problems = parse({"message": "m", "search": {"pattern": "$P = malloc($S)\n...\nfree($P)"}})[2]
    assert any("must end with `;`" in p for p in problems)


def test_pattern_docs_have_no_yaml_schema():
    docs = load_pattern_docs()
    assert docs.startswith("## Pattern syntax") and "Taint mode" not in docs and "rules:" not in docs


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_spec_loop_corrects_and_grades_with_the_gate(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    strict = {**TAINT_SPEC, "taint": {**TAINT_SPEC["taint"], "sinks": TAINT_SPEC["taint"]["sinks"][:3]}}
    responses = iter(["no idea", f"```json\n{json.dumps(strict)}\n```"])
    prompts = []

    def fake_complete(role, prompt):
        prompts.append((role, prompt))
        return next(responses), 0.0

    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=2,
                     output_format="spec")

    assert run["format"] == "spec" and [r for r, _ in prompts] == ["generator", "corrector"]
    assert "JSON spec" in prompts[0][1] and "rules:" not in prompts[0][1]
    assert "No JSON spec found" in prompts[1][1]
    assert run["attempts"][1]["report"]["valid"]
    assert run["accepted"] and run["test_report"] is not None


def test_template_builds_a_taint_by_side_effect_rule():
    from src.pipeline.spec import parse_template_response
    template = {
        "message": "m",
        "event": {"pattern": "free($P)", "variable": "$P"},
        "uses": ["*$X", {"pattern": "$F(..., $X, ...)", "focus": "$X", "not": ["free(...)"]}],
        "resets": [{"pattern": "$P = $E", "variable": "$P"}],
    }
    text = f"```json\n{json.dumps(template)}\n```"
    _, rule_doc, problems = parse_template_response(text, "gen-cwe-415", "CWE-415", set())
    assert problems == []
    rule = rule_doc["rules"][0]
    assert rule["mode"] == "taint"
    assert rule["pattern-sources"] == [
        {"patterns": [{"pattern": "free($P)"}, {"focus-metavariable": "$P"}], "by-side-effect": True}]
    assert rule["pattern-sanitizers"][0]["by-side-effect"] is True
    assert rule["pattern-sinks"][0] == {"pattern": "*$X"}
    assert rule["pattern-sinks"][1]["patterns"][1] == {"pattern-not": "free(...)"}
    assert yaml.safe_load(dump_rule(rule_doc)) == rule_doc


def test_template_problems_are_explained():
    from src.pipeline.spec import parse_template_response

    def problems(template):
        return parse_template_response(f"```json\n{json.dumps(template)}\n```", "g", "CWE-415", set())[2]

    assert any("`event` is required" in p for p in problems({"uses": ["f($X)"]}))
    assert any("does not appear in the pattern" in p for p in
               problems({"event": {"pattern": "free($P)", "variable": "$Q"}, "uses": ["f($X)"]}))
    assert any("`uses` must be a non-empty list" in p for p in
               problems({"event": {"pattern": "free($P)", "variable": "$P"}}))
    assert any("unknown keys `taint`" in p or "Unknown top-level keys `taint`" in p for p in
               problems({"event": {"pattern": "free($P)", "variable": "$P"}, "uses": ["f($X)"], "taint": {}}))


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_template_loop_runs_end_to_end(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    answer = {"message": "m", "event": {"pattern": "free($P)", "variable": "$P"},
              "uses": ["*$X", "$X[$I]", "$X->$FLD"], "resets": [{"pattern": "$P = $E", "variable": "$P"}]}
    responses = iter(["nothing", f"```json\n{json.dumps(answer)}\n```"])
    prompts = []

    def fake_complete(role, prompt):
        prompts.append(prompt)
        return next(responses), 0.0

    run = synthesize("CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
                     rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=2,
                     output_format="template")
    assert run["format"] == "template" and "strategy you fill in" in prompts[0]
    assert "No JSON spec found" in prompts[1]
    assert run["attempts"][1]["report"]["valid"] and run["accepted"]


def test_duplicate_json_keys_are_reported_instead_of_overwritten():
    # Qwen3-4B wrote `"uses"` twice in a real template run; json.loads silently keeps the last one.
    text = '```json\n{"message": "m", "search": {"pattern": "a($X)"}, "search": {"pattern": "b($X)"}}\n```'
    problems = parse(text)[2]
    assert len(problems) == 1 and "duplicate keys: `search`" in problems[0]
    assert "JSON syntax error" in parse('```json\n{"a": }\n```')[2][0]


def build(template):
    from src.pipeline.spec import parse_template_response
    _, rule_doc, problems = parse_template_response(f"```json\n{json.dumps(template)}\n```", "gen-x", "CWE-416", set())
    return rule_doc, problems


def test_not_inside_becomes_pattern_not_inside_after_the_exclusions():
    rule_doc, problems = build({
        "message": "m", "event": {"pattern": "mark($X)", "variable": "$X"},
        "uses": [{"pattern": "$Y->...", "focus": "$Y", "not": ["safe($Y)"], "not_inside": ["mark(...)", "outer(...)"]},
                 {"pattern": "g($Y)", "not_inside": ["mark(...)"]}],
    })

    assert problems == []
    first, second = rule_doc["rules"][0]["pattern-sinks"]
    assert first["patterns"] == [{"pattern": "$Y->..."}, {"pattern-not": "safe($Y)"},
                                 {"pattern-not-inside": "mark(...)"}, {"pattern-not-inside": "outer(...)"},
                                 {"focus-metavariable": "$Y"}]
    assert second == {"patterns": [{"pattern": "g($Y)"}, {"pattern-not-inside": "mark(...)"}]}
    assert yaml.safe_load(dump_rule(rule_doc)) == rule_doc


def test_not_inside_problems_are_explained_and_the_unknown_key_message_lists_it():
    _, problems = build({"event": {"pattern": "m($X)", "variable": "$X"},
                         "uses": [{"pattern": "u($X)", "not_inside": []}]})
    assert any("uses[0].not_inside" not in p and "taint.sinks[0].not_inside must be a non-empty list" in p for p in problems)

    _, problems = build({"event": {"pattern": "m($X)", "variable": "$X"}, "uses": [{"pattern": "u($X)", "nope": 1}]})
    assert any("allowed: `pattern`, `focus`, `by_side_effect`, `not`, `not_inside`" in p for p in problems)


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_not_inside_excludes_the_use_inside_the_marking_call_where_not_cannot(tmp_path):
    from src.pipeline.gate import evaluate
    from src.pipeline.rules import write_rule
    code = tmp_path / "real" / "code.c"
    code.parent.mkdir()
    code.write_text("void f(struct s *p)\n{\n\tmark(p);\n\tmark(p->a);\n\tuse(p->b);\n}\n", encoding="utf-8")

    def alert_lines(exclusion):
        rule_doc, problems = build({"message": "m", "event": {"pattern": "mark($X)", "variable": "$X"},
                                    "uses": [{"pattern": "$Y->...", "focus": "$Y", **exclusion}]})
        assert problems == []
        report = evaluate(write_rule(rule_doc, tmp_path / "rule.yaml"), [], [], negative_files=[code])
        return [m.line for m in report.negative_matches]

    # the use `p->a` is the argument of the second mark(): the match is `p->a`, not `mark(p->a)`
    assert alert_lines({"not": ["mark(...)"]}) == [4, 5]       # `not` is only for matches equal to the pattern
    assert alert_lines({"not_inside": ["mark(...)"]}) == [5]   # `not_inside` removes it, use(p->b) stays
