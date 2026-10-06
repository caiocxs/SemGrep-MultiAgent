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


CLEAN_REAL_CODE = """#include <stdlib.h>
struct s { int x; };

int release_and_read(struct s *p)
{
	free(p);
	return p->x;
}
"""


def real_world_dir(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    (root / "clean.c").write_text(CLEAN_REAL_CODE, encoding="utf-8")
    return root


@needs_semgrep
def test_alerts_on_real_code_are_kept_apart_and_limit_acceptance(tmp_path):
    negatives = collect_files([real_world_dir(tmp_path)])

    unlimited = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files(), negative_files=negatives)
    strict = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files(), negative_files=negatives, max_negative_rate=0.0)
    lenient = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files(), negative_files=negatives, max_negative_rate=1000.0)

    # the function rule is skipped on real code (it is ten times slower), so there is no function name
    assert [(Path(m.path).name, m.line, m.function, m.code) for m in unlimited.negative_matches] == [
        ("clean.c", 7, None, "return p->x;")]
    assert unlimited.false_positives == []  # they do not mix with the Juliet false positives
    assert unlimited.negative_lines == len(CLEAN_REAL_CODE.splitlines())
    assert unlimited.negative_rate == pytest.approx(1000 / unlimited.negative_lines)
    assert unlimited.passed() and lenient.passed()
    assert not strict.passed()
    assert unlimited.precision == 1.0  # precision stays comparable with the baseline: Juliet only


@needs_semgrep
def test_feedback_shows_the_code_around_alerts_on_real_code(tmp_path):
    negatives = collect_files([real_world_dir(tmp_path)])
    report = evaluate(KNOWN_GOOD_RULE, bad_files(), good_files(), negative_files=negatives, max_negative_rate=0.5)

    text = report.feedback()
    assert "1 alert in" in text and "per KLOC, at most 0.5 allowed" in text
    assert "clean.c:7: `return p->x;`" in text
    assert "> 7|     return p->x;" in text  # the alert line is marked
    assert "  6|     free(p);" in text  # tabs expanded, context before the alert


@needs_semgrep
def test_feedback_shows_the_code_around_juliet_false_positives(tmp_path):
    rule = write_rule(tmp_path, """
rules:
  - id: any-free
    languages: [c]
    severity: ERROR
    message: free
    pattern: free($P)
""")
    text = evaluate(rule, bad_files(), good_files()).feedback()

    assert "```c" in text and "> " in text


def test_snippet_is_clipped_to_the_file_and_tolerates_missing_files(tmp_path):
    from src.pipeline.gate import _snippet
    source = tmp_path / "a.c"
    source.write_text("one\ntwo\nthree\n", encoding="utf-8")

    assert _snippet(source, 1) == "```c\n> 1| one\n  2| two\n  3| three\n```"
    assert _snippet(source, 4) == ""
    assert _snippet(tmp_path / "missing.c", 1) == ""


def test_report_log_keeps_the_exact_count_but_few_real_code_alerts():
    from src.pipeline.gate import GateReport, Match, MAX_LOGGED_NEGATIVES
    report = GateReport(
        rule_path="r.yaml",
        negative_matches=[Match(f"f{i}.c", i, "r") for i in range(MAX_LOGGED_NEGATIVES + 70)],
        negative_lines=2000,
    )
    data = report.to_dict()

    assert data["negative_alerts"] == MAX_LOGGED_NEGATIVES + 70
    assert len(data["negative_matches"]) == MAX_LOGGED_NEGATIVES
    assert data["negative_rate"] == round((MAX_LOGGED_NEGATIVES + 70) / 2, 4)


def test_feedback_lists_files_with_most_real_code_alerts_first_and_counts_the_rest():
    from src.pipeline.gate import GateReport, Match
    report = GateReport(
        rule_path="r.yaml",
        negative_lines=1000,
        negative_matches=[Match("a.c", 1, "r", "f", "x")] + [Match("b.c", i, "r", "g", "y") for i in range(1, 4)]
        + [Match("c.c", 1, "r", "h", "z"), Match("d.c", 1, "r", "i", "w")],
    )
    text = report.feedback(max_snippets=2)

    assert text.index("b.c:1") < text.index("a.c:1")  # b.c has 3 alerts
    assert "(and 2 more in this file)" in text
    assert "c.c" not in text and "d.c" not in text
    assert "... and 2 more alerts in 2 other files" in text


MARK_RULE = """
rules:
  - id: mark-then-use
    languages: [c]
    severity: ERROR
    message: m
    mode: taint
    pattern-sources:
      - by-side-effect: true
        patterns:
          - pattern: mark($X)
          - focus-metavariable: $X
    pattern-sinks:
      - patterns:
          - pattern: $F($X, ...)
          - focus-metavariable: $X
"""


@needs_semgrep
def test_alerts_on_the_statement_that_marks_the_variable_are_reported(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    (root / "code.c").write_text("void f(int *p)\n{\n\tmark(p);\n\tuse(p);\n\tmark(p);\n}\n", encoding="utf-8")

    report = evaluate(write_rule(tmp_path, MARK_RULE), [], [], negative_files=collect_files([root]))

    # the sink `$F($X, ...)` also matches the two mark(p) calls that mark the variable
    assert [m.line for m in report.negative_matches] == [3, 4, 5]
    assert report.negative_on_source == 2
    assert "2 of these 3 alerts (67%) are on a line that one of the rule's own source patterns also matches" in report.feedback()
    assert report.to_dict()["negative_on_source"] == 2


@needs_semgrep
def test_no_source_warning_for_search_rules_or_when_no_alert_is_on_a_source(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    (root / "code.c").write_text("void f(int *p)\n{\n\tmark(p);\n\tuse(p);\n}\n", encoding="utf-8")
    negatives = collect_files([root])

    specific_sink = MARK_RULE.replace("$F($X, ...)", "use($X)")
    taint = evaluate(write_rule(tmp_path, specific_sink), [], [], negative_files=negatives)
    search = evaluate(write_rule(tmp_path, "rules:\n  - id: s\n    languages: [c]\n    severity: ERROR\n"
                                           "    message: m\n    pattern: use($X)\n"), [], [], negative_files=negatives)

    assert [m.line for m in taint.negative_matches] == [4] and taint.negative_on_source == 0
    assert len(search.negative_matches) == 1 and search.negative_on_source == 0
    assert "own source patterns" not in taint.feedback() and "own source patterns" not in search.feedback()


def test_source_patterns_are_read_from_the_sources_only(tmp_path):
    from src.pipeline.gate import _source_patterns
    rule = write_rule(tmp_path, """
rules:
  - id: r
    languages: [c]
    severity: ERROR
    message: m
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: a($X)
          - pattern-not: b($X)
          - focus-metavariable: $X
      - pattern-either:
          - pattern: c($Y)
          - patterns:
              - pattern: d($Y)
              - metavariable-pattern:
                  metavariable: $Y
                  pattern: e
    pattern-sinks:
      - pattern: sink($Z)
""")

    assert _source_patterns(rule) == ["a($X)", "c($Y)", "d($Y)"]
    assert _source_patterns(tmp_path / "missing.yaml") == []


NOT_RULE = """
rules:
  - id: mark-then-use-field
    languages: [c]
    severity: ERROR
    message: m
    mode: taint
    pattern-sources:
      - by-side-effect: true
        patterns:
          - pattern: mark($X)
          - focus-metavariable: $X
    pattern-sinks:
      - patterns:
          - pattern: $Y->...
          - EXCLUSION
          - focus-metavariable: $Y
"""


def exclusion_rule(tmp_path, exclusion):
    return write_rule(tmp_path, NOT_RULE.replace("- EXCLUSION", exclusion))


@needs_semgrep
def test_a_not_equal_to_the_source_pattern_is_flagged_as_ineffective(tmp_path):
    root = tmp_path / "real"
    root.mkdir()
    (root / "code.c").write_text("void f(struct s *p)\n{\n\tmark(p);\n\tmark(p->a);\n\tuse(p->b);\n}\n", encoding="utf-8")
    negatives = collect_files([root])

    with_not = evaluate(exclusion_rule(tmp_path, "- pattern-not: mark($X)"), [], [], negative_files=negatives)
    with_not_inside = evaluate(exclusion_rule(tmp_path, "- pattern-not-inside: mark(...)"), [], [], negative_files=negatives)

    # `p->a` is the argument of the marking call: the match is not equal to `mark($X)`, so the `not` does nothing
    assert [m.line for m in with_not.negative_matches] == [4, 5] and with_not.negative_on_source == 1
    assert with_not.ineffective_nots == ["mark($X)"]
    text = with_not.feedback()
    assert "Your `not` of `mark($X)` on the uses does not remove them" in text and "`not_inside`" in text
    assert with_not.to_dict()["ineffective_nots"] == ["mark($X)"]

    assert [m.line for m in with_not_inside.negative_matches] == [5] and with_not_inside.negative_on_source == 0
    assert with_not_inside.ineffective_nots == [] and "does not remove them" not in with_not_inside.feedback()


def test_only_sink_nots_that_equal_a_source_pattern_count(tmp_path):
    from src.pipeline.gate import _sink_nots_equal_to_sources
    rule = write_rule(tmp_path, """
rules:
  - id: r
    languages: [c]
    severity: ERROR
    message: m
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: a($X)
          - pattern-not: b($X)
          - focus-metavariable: $X
    pattern-sinks:
      - patterns:
          - pattern: c($X)
          - pattern-not: a($X)
          - pattern-not: b($X)
          - pattern-not: other($X)
    pattern-sanitizers:
      - patterns:
          - pattern: d($X)
          - pattern-not: a($X)
""")

    # `a($X)` is a source and a sink `not`; `b($X)` is a `not` inside the *source* only; sanitizers are ignored
    assert _sink_nots_equal_to_sources(rule) == ["a($X)"]
    assert _sink_nots_equal_to_sources(tmp_path / "missing.yaml") == []
