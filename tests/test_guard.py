from src.pipeline import roles
from tests.test_roles import RULES, attempt, run_loop
from tests.test_synthesize import graded

# attempt 0 is the best rule so far (recall 50%, 5 false positives); attempt 1 loses recall and adds alerts
BASE = graded(true_positives=2, detected=2, false_positives=5)
WORSE = graded(true_positives=1, detected=1, false_positives=8)
PASSING = graded(true_positives=3, detected=3)


def test_a_correction_that_scores_worse_is_discarded_and_the_corrector_gets_the_best_rule_back(tmp_path, monkeypatch):
    run, calls, _ = run_loop(tmp_path, monkeypatch, [BASE, WORSE, PASSING],
                             {"generator": [RULES["a"]], "corrector": [RULES["b"], RULES["c"]]},
                             guard=True, min_recall=0.5, max_fix_attempts=3)

    second_fix = calls[2][1]
    assert "Your last change (attempt 1) made the rule worse and was discarded" in second_fix
    assert "The rule below is attempt 0" in second_fix and "free(a)" in second_fix and "free(b)" not in second_fix
    assert [a.get("discarded") for a in run["attempts"]] == [None, True, None]   # all of them stay in the log
    assert run["roles"]["guard"] is True and run["accepted"]


def test_without_the_guard_the_corrector_keeps_editing_its_last_rule(tmp_path, monkeypatch):
    run, calls, _ = run_loop(tmp_path, monkeypatch, [BASE, WORSE, PASSING],
                             {"generator": [RULES["a"]], "corrector": [RULES["b"], RULES["c"]]},
                             min_recall=0.5, max_fix_attempts=3)

    second_fix = calls[2][1]
    assert "free(b)" in second_fix and "discarded" not in second_fix
    assert all("discarded" not in a for a in run["attempts"]) and run["roles"]["guard"] is False


def test_a_correction_that_improves_becomes_the_new_base(tmp_path, monkeypatch):
    better = graded(true_positives=3, detected=3, false_positives=2)
    run, calls, _ = run_loop(tmp_path, monkeypatch, [BASE, better, WORSE, PASSING],
                             {"generator": [RULES["a"]], "corrector": [RULES["b"], RULES["c"], RULES["d"]]},
                             guard=True, min_recall=0.5, max_fix_attempts=4)

    first_fix, second_fix, third_fix = calls[1][1], calls[2][1], calls[3][1]
    assert "discarded" not in first_fix and "discarded" not in second_fix and "free(b)" in second_fix   # better: kept
    assert "attempt 1 (" in third_fix and "free(b)" in third_fix and "free(c)" not in third_fix         # worse: back to 1
    assert [a.get("discarded") for a in run["attempts"]] == [None, None, True, None]


def test_a_rule_that_never_reached_the_gate_is_corrected_as_before(tmp_path, monkeypatch):
    run, calls, _ = run_loop(tmp_path, monkeypatch, [BASE, PASSING],
                             {"generator": [RULES["a"]], "corrector": ["no rule", RULES["c"]]},
                             guard=True, min_recall=0.5, max_fix_attempts=3)

    assert "No YAML rule found" in calls[2][1] and "discarded" not in calls[2][1]
    assert not any(a.get("discarded") for a in run["attempts"])


def test_the_critic_reviews_the_rule_the_corrector_is_given(tmp_path, monkeypatch):
    run, calls, _ = run_loop(tmp_path, monkeypatch, [BASE, WORSE, PASSING],
                             {"generator": [RULES["a"]], "critic": ["review 0", "review 1"],
                              "corrector": [RULES["b"], RULES["c"]]},
                             guard=True, critic=True, min_recall=0.5, max_fix_attempts=3)

    critic_prompts = [prompt for role, prompt in calls if role == "critic"]
    assert len(critic_prompts) == 2 and "free(a)" in critic_prompts[1] and "free(b)" not in critic_prompts[1]


def test_the_note_names_both_attempts():
    base = attempt(0, graded(true_positives=2, detected=2, false_positives=5))
    worse = attempt(3, graded(true_positives=1, detected=1, false_positives=8))
    note = roles.regression_note(worse, base)
    assert "attempt 3" in note and "attempt 0" in note and "8 false positives" in note and "5 false positives" in note
