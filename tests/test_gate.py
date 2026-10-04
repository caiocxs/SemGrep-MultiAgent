import shutil
from pathlib import Path

import pytest

from src.pipeline.gate import case_id, collect_files, evaluate, function_role

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "juliet" / "cwe416"
KNOWN_GOOD_RULE = ROOT / "tests" / "fixtures" / "rules" / "cwe416_uaf.yaml"
PREFIX = "CWE416_Use_After_Free__"

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def bad_files():
    return collect_files([FIXTURES / "bad"])


def good_files():
    return collect_files([FIXTURES / "good"])


def write_rule(tmp_path, body):
    rule = tmp_path / "rule.yaml"
    rule.write_text(body, encoding="utf-8")
    return rule


def test_case_id_merges_split_variants():
    assert case_id(f"{PREFIX}malloc_free_long_63a_bad.c") == f"{PREFIX}malloc_free_long_63"
    assert case_id(f"{PREFIX}malloc_free_long_63b_bad.c") == f"{PREFIX}malloc_free_long_63"
    assert case_id(f"{PREFIX}malloc_free_char_01_good.c") == f"{PREFIX}malloc_free_char_01"


def test_function_role():
    assert function_role(f"{PREFIX}malloc_free_char_01_bad") == "bad"
    assert function_role("helperBad") == "bad"
    assert function_role("goodB2G1") == "good"
    assert function_role("helperGood") == "good"
    assert function_role("staticReturnsTrue") is None
    assert function_role(None) is None


@needs_semgrep
def test_known_good_rule_passes():
    report = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files())

    assert report.valid
    assert report.passed()
    assert report.false_positives == []
    assert report.detected_cases == [
        f"{PREFIX}malloc_free_char_01",
        f"{PREFIX}malloc_free_int_07",
        f"{PREFIX}return_freed_ptr_01",
    ]
    # The free and the use sit in different files: out of reach of an intraprocedural rule.
    assert report.missed_cases == [f"{PREFIX}malloc_free_long_63"]


@needs_semgrep
def test_dead_bad_helper_in_good_file_is_neutral():
    report = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files())

    assert [(Path(m.path).name, m.function) for m in report.neutral] == [
        (f"{PREFIX}return_freed_ptr_01_good.c", "helperBad"),
    ]


@needs_semgrep
def test_matches_line_finds_the_sink():
    bad = FIXTURES / "bad" / f"{PREFIX}malloc_free_char_01_bad.c"
    report = evaluate(KNOWN_GOOD_RULE, [bad])

    assert report.matches_line(bad, 17)  # printLine(data);
    assert not report.matches_line(bad, 15)  # free(data);


@needs_semgrep
def test_overbroad_rule_fails_with_false_positives(tmp_path):
    rule = write_rule(tmp_path, """
rules:
  - id: any-free
    languages: [c]
    severity: ERROR
    message: free
    pattern: free($P)
""")
    report = evaluate(rule, bad_files(), good_files())

    assert report.valid
    assert report.false_positives
    assert not report.passed()
    assert "must NOT match" in report.feedback()


@needs_semgrep
@pytest.mark.parametrize("body, expected", [
    ("rules:\n  - id: x\n    languages: [c]\n    severity: ERROR\n    message: m\n    pattern: free($P\n", "Invalid pattern"),
    ("rules:\n  - id: x\n    languages: [c]\n    message: m\n    pattern: free($P)\n", "severity"),
    ("rules:\n  - id: x\n   languages: [c\n", "YAML"),
])
def test_invalid_rule_is_rejected(tmp_path, body, expected):
    report = evaluate(write_rule(tmp_path, body), bad_files(), good_files())

    assert not report.valid
    assert not report.passed()
    assert any(expected in e for e in report.errors)
    assert report.feedback().startswith("The rule is INVALID")


def test_feedback_groups_repeated_false_positives():
    from src.pipeline.gate import GateReport, Match
    report = GateReport(
        rule_path="r.yaml",
        false_positives=[Match(f"f{i}.c", i, "r", "good", "free(data);") for i in range(10)]
        + [Match("g.c", 1, "r", "goodB2G", "free(x);")],
    )
    text = report.feedback(max_items=5)
    assert "(and 9 more like it)" in text
    assert text.count("free(data);") == 1 and "free(x);" in text
