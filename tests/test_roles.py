import itertools
from pathlib import Path

import pytest

from src.pipeline import roles
from src.pipeline.gate import collect_files
from src.pipeline.synthesize import _score, render, synthesize
from tests.test_synthesize import FIXTURES, ROOT, graded, write_logs


_runs = itertools.count()  # every run gets its own detector-log directory


def attempt(n, report=None, problems=(), source=""):
    return {"n": n, "report": report, "problems": list(problems), "rule_source": source, "passed": False}


# ----------------------------------------------------------------------------- history
def test_history_is_empty_without_earlier_attempts_and_lists_them_oldest_first():
    assert roles.history_block([]) == ""

    block = roles.history_block([
        attempt(0, graded(true_positives=2, detected=2, false_positives=5)),
        attempt(1, problems=["No JSON spec found in the answer."]),
        attempt(2, problems=["This is exactly the same rule as attempt 0, which already failed."]),
    ])
    assert block.startswith("### Earlier attempts (oldest first)")
    lines = [l for l in block.splitlines() if l.startswith("- attempt")]
    assert lines[0].startswith("- attempt 0: recall 50%, 5 false positives on the Juliet files")
    assert lines[1] == "- attempt 1: rejected before testing: No JSON spec found in the answer."
    assert lines[2] == "- attempt 2: the same rule as an earlier attempt"
    assert "Do not go back to a rule that already failed." in block and block.endswith("\n")


def test_history_keeps_only_the_latest_attempts():
    block = roles.history_block([attempt(i, problems=[f"p{i}"]) for i in range(10)], limit=3)
    assert [l.split(":")[0] for l in block.splitlines() if l.startswith("- attempt")] == \
        ["- attempt 7", "- attempt 8", "- attempt 9"]


def test_summary_of_an_invalid_rule_names_semgreps_error():
    from src.pipeline.gate import GateReport
    invalid = GateReport(rule_path="r.yaml", errors=["Invalid pattern for C: free($P"])
    assert roles.attempt_summary(attempt(0, invalid)) == "Semgrep rejected the rule: Invalid pattern for C: free($P"


def test_render_drops_an_empty_marker_line_and_fills_a_filled_one():
    common = dict(CWE_ID="CWE-416", CWE_NAME="n", CWE_DESCRIPTION="d", PATTERN_DOCS="docs", RULE="{}",
                  FEEDBACK="the result", MISSED_CODE="(none)", PROJECT_APIS="")
    plain = render("template_corrector", **common, HISTORY="")
    assert "{{" not in plain and "### Test result\n\nthe result\n\n### Vulnerable code" in plain

    block = roles.history_block([attempt(0, problems=["p"])])
    filled = render("template_corrector", **common, HISTORY=block)
    assert "the result\n\n### Earlier attempts" in filled and "failed.\n\n### Vulnerable code" in filled


# ----------------------------------------------------------------------------- critic
def test_review_is_added_as_a_fallible_opinion():
    assert roles.with_review("result", "") == "result"
    text = roles.with_review("result", "  - the sink matches the free call  ")
    assert text.startswith("result\n\nReview of the rule by another agent (it can be wrong")
    assert text.endswith("\n- the sink matches the free call")


# ----------------------------------------------------------------------------- merger
def test_merge_pair_takes_the_quietest_rule_when_the_best_one_is_noisy():
    noisy_best = attempt(0, graded(true_positives=4, detected=4, false_positives=2))      # F1 high, 2 alerts
    quiet = attempt(1, graded(true_positives=2, detected=2))                              # no alerts, lower recall
    quieter_still_but_empty = attempt(2, graded())                                        # detects nothing: not usable
    pair = roles.select_merge_pair([noisy_best, quiet, quieter_still_but_empty], _score)

    assert pair is not None and pair[0] is noisy_best and pair[1] is quiet


def test_merge_pair_takes_the_stronger_rule_when_the_best_one_is_already_the_quietest():
    quiet_best = attempt(0, graded(true_positives=1, detected=1))                         # F1 0.4, no alerts
    noisy_strong = attempt(1, graded(true_positives=4, detected=4, false_positives=20))   # recall 100%, 20 alerts
    pair = roles.select_merge_pair([quiet_best, noisy_strong], _score)

    assert pair is not None and pair[0] is quiet_best and pair[1] is noisy_strong


def test_no_merge_without_two_usable_rules_with_different_behaviour():
    one = attempt(0, graded(true_positives=2, detected=2, false_positives=1))
    twin = attempt(1, graded(true_positives=2, detected=2, false_positives=1))            # same numbers
    broken = attempt(2, problems=["rejected"])
    assert roles.select_merge_pair([one], _score) is None
    assert roles.select_merge_pair([one, twin, broken], _score) is None
    worse_in_everything = attempt(3, graded(true_positives=1, detected=1, false_positives=9))
    assert roles.select_merge_pair([one, worse_in_everything], _score) is None


def test_merge_task_names_both_rules_and_shows_the_second_one():
    a = attempt(0, graded(true_positives=1, detected=1), source="rule A text")
    b = attempt(1, graded(true_positives=4, detected=4, false_positives=20), source="rule B text")
    text = roles.merge_feedback(a, b)

    assert text.startswith("MERGE TASK.")
    assert "- rule A: recall 25%" in text and "- rule B: recall 100%, 20 false positives" in text
    assert "Rule B:\n```\nrule B text\n```" in text


# ----------------------------------------------------------------------------- examples
def test_pairs_come_from_different_variants_and_match_by_name():
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    pairs = roles.select_pairs(bad, good, n=2, seed=0)

    assert len(pairs) == 2
    for b, g in pairs:
        assert b.endswith("_bad.c") and g.endswith("_good.c")
        assert Path(b).name.replace("_bad.c", "") == Path(g).name.replace("_good.c", "")
    from src.pipeline.split import flow_variant
    assert len({flow_variant(b) for b, _ in pairs}) == 2
    assert roles.select_pairs(bad, good, n=2, seed=0) == pairs                            # deterministic
    assert roles.select_pairs(bad, [], n=2) == []                                         # no safe counterpart, no pair


def test_a_pair_is_shown_as_vulnerable_and_safe_version():
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    b, g = roles.select_pairs(bad, good, n=1)[0]
    text = roles.render_pair(b, g, 3)

    assert text.startswith("#### Example 3") and "Vulnerable version (`" in text and "Safe version (`" in text
    assert text.count("```c") == 2 and "L1|" in text


def prompts_of(tmp_path, monkeypatch, **options):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    logs = tmp_path / f"logs_{next(_runs)}"
    write_logs(logs, bad)
    seen = []

    def complete(role, prompt):
        seen.append((role, prompt))
        return "no rule", 0.0  # rejected before the gate: no Semgrep run

    run = synthesize("CWE-416", "A", bad, good, [logs], complete=complete, rules_dir=tmp_path / "rules",
                     logs_dir=tmp_path / "synthesis", **options)
    return seen, run


def test_the_generator_is_shown_findings_pairs_or_nothing(tmp_path, monkeypatch):
    findings, run_f = prompts_of(tmp_path, monkeypatch, max_fix_attempts=0, output_format="template")
    pairs, run_p = prompts_of(tmp_path, monkeypatch, max_fix_attempts=0, output_format="template", example_mode="pairs")
    nothing, run_n = prompts_of(tmp_path, monkeypatch, max_fix_attempts=0, output_format="template", example_mode="none")

    assert "Analyzer report:" in findings[0][1] and roles.PAIRS_INTRO not in findings[0][1]
    assert roles.PAIRS_INTRO in pairs[0][1] and "Vulnerable version (`" in pairs[0][1] and "Analyzer report:" not in pairs[0][1]
    assert roles.NO_EXAMPLES_NOTE in nothing[0][1] and "Example 1" not in nothing[0][1]
    assert run_f["roles"]["example_mode"] == "findings" and run_f["examples"] and all(e.endswith(".c") for e in run_f["examples"])
    assert len(run_p["examples"]) == 2 and all(e.endswith("_bad.c") for e in run_p["examples"])
    assert run_n["examples"] == []


def test_unknown_example_mode_is_an_error(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="Unknown example mode"):
        prompts_of(tmp_path, monkeypatch, max_fix_attempts=0, example_mode="vibes")


# ----------------------------------------------------------------------------- the roles inside the loop
RULES = {name: f"```yaml\nrules:\n  - id: x\n    pattern: free({name})\n```" for name in "abcd"}


def run_loop(tmp_path, monkeypatch, reports, answers, **options):
    """The loop with a fake model and a fake gate: `answers` maps a role to the rules it returns in turn."""
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    logs = tmp_path / f"logs_{next(_runs)}"
    write_logs(logs, bad)
    calls, diagnose_flags, given = [], [], {role: iter(texts) for role, texts in answers.items()}

    def fake_evaluate(rule_path, bad_files, good_files=(), timeout=600, negative_files=(), max_negative_rate=None, diagnose=True):
        diagnose_flags.append(diagnose)
        return reports[min(len(diagnose_flags) - 1, len(reports) - 1)]

    def complete(role, prompt):
        calls.append((role, prompt))
        return next(given[role]), 0.0

    monkeypatch.setattr("src.pipeline.synthesize.evaluate", fake_evaluate)
    monkeypatch.setattr("src.pipeline.synthesize.missed_code", lambda report, **kwargs: "(missed code)")  # the fake cases have no files
    run = synthesize("CWE-416", "A", bad, good, [logs], complete=complete, rules_dir=tmp_path / "rules",
                     logs_dir=tmp_path / "synthesis", **options)
    return run, calls, diagnose_flags


def test_the_critic_reviews_a_tested_rule_and_the_corrector_sees_the_review(tmp_path, monkeypatch):
    reports = [graded(true_positives=2, detected=2, false_positives=5), graded(true_positives=3, detected=3)]
    run, calls, _ = run_loop(tmp_path, monkeypatch, reports,
                             {"generator": [RULES["a"]], "critic": ["- the pattern matches every free"], "corrector": [RULES["b"]]},
                             critic=True, min_recall=0.0, max_fix_attempts=3)

    assert [role for role, _ in calls] == ["generator", "critic", "corrector"]
    critic_prompt, corrector_prompt = calls[1][1], calls[2][1]
    assert "free(a)" in critic_prompt and "### Test result" in critic_prompt and "{{" not in critic_prompt
    assert "Review of the rule by another agent (it can be wrong" in corrector_prompt
    assert "- the pattern matches every free" in corrector_prompt
    assert run["attempts"][0]["review"] == "- the pattern matches every free" and "review" not in run["attempts"][1]
    assert run["roles"]["critic"] is True and "critic" in run["models"] and run["accepted"]


def test_without_the_critic_flag_no_critic_is_called(tmp_path, monkeypatch):
    reports = [graded(true_positives=2, detected=2, false_positives=5), graded(true_positives=3, detected=3)]
    run, calls, _ = run_loop(tmp_path, monkeypatch, reports, {"generator": [RULES["a"]], "corrector": [RULES["b"]]},
                             min_recall=0.0, max_fix_attempts=3)

    assert [role for role, _ in calls] == ["generator", "corrector"]
    assert "Review of the rule" not in calls[1][1] and "critic" not in run["models"]


def test_the_critic_is_not_asked_about_a_rule_that_never_reached_the_gate(tmp_path, monkeypatch):
    reports = [graded(true_positives=3, detected=3)]
    run, calls, _ = run_loop(tmp_path, monkeypatch, reports, {"generator": ["no rule"], "corrector": [RULES["a"]], "critic": []},
                             critic=True, min_recall=0.0, max_fix_attempts=3)

    assert [role for role, _ in calls] == ["generator", "corrector"]


def test_history_reaches_the_corrector_and_the_critic_only_when_asked(tmp_path, monkeypatch):
    reports = [graded(true_positives=2, detected=2, false_positives=5), graded(true_positives=1, detected=1, false_positives=3),
               graded(true_positives=3, detected=3)]
    answers = {"generator": [RULES["a"]], "corrector": [RULES["b"], RULES["c"]]}
    _, with_history, _ = run_loop(tmp_path, monkeypatch, reports, answers, history=True, min_recall=0.0, max_fix_attempts=3)
    _, without, _ = run_loop(tmp_path, monkeypatch, reports,
                             {"generator": [RULES["a"]], "corrector": [RULES["b"], RULES["c"]]}, min_recall=0.0, max_fix_attempts=3)

    first_fix, second_fix = with_history[1][1], with_history[2][1]
    assert "Earlier attempts" not in first_fix                      # nothing happened before the first rule
    assert "### Earlier attempts (oldest first)\n\n- attempt 0: recall 50%, 5 false positives" in second_fix
    assert all("Earlier attempts" not in prompt for _, prompt in without)


def test_the_diagnose_option_reaches_every_gate_run(tmp_path, monkeypatch):
    reports = [graded(true_positives=3, detected=3)]
    _, _, flags_on = run_loop(tmp_path, monkeypatch, reports, {"generator": [RULES["a"]]}, min_recall=0.0)
    _, _, flags_off = run_loop(tmp_path, monkeypatch, reports, {"generator": [RULES["a"]]}, min_recall=0.0, diagnose=False)

    assert flags_on and set(flags_on) == {True}
    assert flags_off and set(flags_off) == {False}                  # the attempts and the held-out test run


def test_the_merger_combines_the_best_and_the_strongest_rule_and_the_gate_judges_the_result(tmp_path, monkeypatch):
    reports = [graded(true_positives=1, detected=1),                                  # attempt 0: quiet, recall 25%
               graded(true_positives=4, detected=4, false_positives=20),              # attempt 1: recall 100%, 20 alerts
               graded(true_positives=3, detected=3)]                                  # the merged rule: passes
    run, calls, _ = run_loop(tmp_path, monkeypatch, reports,
                             {"generator": [RULES["a"]], "corrector": [RULES["b"]], "merger": [RULES["c"]]},
                             merge=True, min_recall=0.5, max_fix_attempts=1)

    assert [role for role, _ in calls] == ["generator", "corrector", "merger"]
    merger_prompt = calls[2][1]
    assert "MERGE TASK." in merger_prompt and "- rule A: recall 25%" in merger_prompt and "- rule B: recall 100%" in merger_prompt
    assert "free(b)" in merger_prompt and "free(a)" in merger_prompt          # B is quoted, A is the current rule
    last = run["attempts"][-1]
    assert [a["role"] for a in run["attempts"]] == ["generator", "corrector", "merger"]
    assert last["merged"] == [0, 1] and last["rule_path"].endswith("_merge.yaml")
    assert run["accepted"] and run["best_attempt"] == 2 and "merger" in run["models"]


def test_no_merge_call_when_there_is_nothing_to_combine(tmp_path, monkeypatch):
    twin = graded(true_positives=2, detected=2, false_positives=1)
    run, calls, _ = run_loop(tmp_path, monkeypatch, [twin], {"generator": [RULES["a"]], "corrector": [RULES["b"]], "merger": []},
                             merge=True, min_recall=0.5, max_fix_attempts=1)

    assert [role for role, _ in calls] == ["generator", "corrector"] and not run["accepted"]


def test_no_merge_call_when_the_loop_already_passed(tmp_path, monkeypatch):
    run, calls, _ = run_loop(tmp_path, monkeypatch, [graded(true_positives=3, detected=3)],
                             {"generator": [RULES["a"]], "merger": []}, merge=True, min_recall=0.5, max_fix_attempts=2)

    assert [role for role, _ in calls] == ["generator"] and run["accepted"]
