import json
import shutil
from pathlib import Path

import pytest

from src.pipeline.gate import collect_files
from src.pipeline.synthesize import synthesize

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "juliet" / "cwe416"
KNOWN_GOOD_RULE = ROOT / "tests" / "fixtures" / "rules" / "cwe416_uaf.yaml"


def write_logs(log_dir, files):
    log_dir.mkdir(parents=True)
    for f in files:
        log = {"vulnerable": True, "findings": [
            {"cwe": "CWE-416", "pointer": "data", "source_line": 1, "violation_line": 2, "description": "use after free"},
        ]}
        (log_dir / f"log_{f.stem}.json").write_text(json.dumps(log), encoding="utf-8")


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_loop_corrects_until_the_rule_passes(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)

    responses = iter([
        "I am not sure how to write this.",
        "Strategy: match the example.\n```yaml\nrules:\n  - id: x\n    pattern: free(data)\n```",
        f"Strategy: taint mode.\n```yaml\n{KNOWN_GOOD_RULE.read_text()}```",
    ])
    prompts = []

    def fake_complete(role, prompt):
        prompts.append((role, prompt))
        return next(responses), 0.0

    run = synthesize(
        "CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete,
        min_recall=0.0, rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=3,
    )

    assert [role for role, _ in prompts] == ["generator", "corrector", "corrector"]
    assert "Semgrep documentation" in prompts[0][1] and "Example 1" in prompts[0][1]
    assert "No YAML rule found" in prompts[1][1]
    assert "`data`, a name taken from the example code" in prompts[2][1]

    attempts = run["attempts"]
    assert attempts[0]["problems"] and attempts[1]["problems"]
    assert attempts[2]["report"]["passed"]
    assert run["accepted"] and Path(run["accepted_path"]).exists()
    assert run["test_report"] is not None
    assert len(list((tmp_path / "synthesis").rglob("*.json"))) == 1


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_repeated_rule_is_not_retested(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)

    overbroad = "```yaml\nrules:\n  - id: x\n    pattern: free($P)\n```"
    responses = iter([overbroad, "Changed it.\n" + overbroad])
    prompts = []

    def fake_complete(role, prompt):
        prompts.append(prompt)
        return next(responses), 0.0

    run = synthesize(
        "CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete,
        min_recall=0.0, rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=1,
    )

    first, second = run["attempts"]
    assert first["report"]["false_positives"]
    assert second["report"] is None
    assert "exactly the same rule as attempt 0" in second["problems"][0]
    assert not run["accepted"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
@pytest.mark.parametrize("stop_on_pass, expected_samples", [(False, 3), (True, 2)])
def test_best_of_n_samples_are_independent_and_gate_picks_the_best(tmp_path, monkeypatch, stop_on_pass, expected_samples):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)

    broad = "```yaml\nrules:\n  - id: x\n    pattern: free(data)\n```"      # false positives
    working = f"```yaml\n{KNOWN_GOOD_RULE.read_text()}```"
    # sample 0: one broken answer, sample 1: passes at once, sample 2: broad rule
    responses = iter(["no rule", working, broad, broad, broad])
    calls = []

    def fake_complete(role, prompt, temperature=None):
        calls.append((role, temperature))
        return next(responses), 0.0

    run = synthesize(
        "CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
        rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=0,
        samples=3, stop_on_pass=stop_on_pass,
    )

    assert all(t == 0.7 for _, t in calls)  # sampling default
    assert len(run["sample_summary"]) == expected_samples
    assert [s["passed"] for s in run["sample_summary"]][:2] == [False, True]
    assert run["samples"] == 3 and run["samples_passed"] == 1
    assert run["best_sample"] == 1 and run["accepted"]
    assert {a["sample"] for a in run["attempts"]} == set(range(expected_samples))
    assert (tmp_path / "rules" / "candidates" / "A" / "CWE-416" / run["run_id"] / "sample1_attempt_0.yaml").exists()


def attempt(report, passed=False):
    return {"report": report, "passed": passed}


def graded(true_positives=0, false_positives=0, negatives=0, cases=4, detected=0):
    """A GateReport with the given numbers of graded matches and detected cases."""
    from src.pipeline.gate import GateReport, Match
    names = [f"case{i}" for i in range(cases)]
    return GateReport(
        rule_path="r.yaml",
        cases={c: [f"{c}_bad.c"] for c in names},
        true_positives=[Match(f"{names[i]}_bad.c", 1, "r") for i in range(detected)]
        + [Match("extra_bad.c", i, "r") for i in range(true_positives - detected)],
        false_positives=[Match("x_good.c", i, "r") for i in range(false_positives)],
        negative_matches=[Match("real.c", i, "r") for i in range(negatives)],
        negative_lines=1000,
    )


def test_a_rule_that_matches_nothing_does_not_beat_one_that_detects_something():
    from src.pipeline.synthesize import _score
    empty = graded()                                                  # valid, 0 FP, 0 recall
    noisy = graded(true_positives=2, detected=2, false_positives=5)   # the old ranking preferred `empty`

    assert _score(attempt(noisy)) > _score(attempt(empty))


def test_score_order_invalid_empty_detecting_passed():
    from src.pipeline.gate import GateReport
    from src.pipeline.synthesize import _score
    invalid = GateReport(rule_path="r.yaml", errors=["bad rule"])

    ranked = [
        attempt(None),
        attempt(invalid),
        attempt(graded()),
        attempt(graded(true_positives=1, detected=1, false_positives=9)),
        attempt(graded(true_positives=3, detected=3, false_positives=1)),
        attempt(graded(true_positives=2, detected=2), passed=True),
    ]
    assert [_score(a) for a in ranked] == sorted(_score(a) for a in ranked)
    assert _score(ranked[0]) == _score(ranked[1])  # both rejected before reaching any matching


def test_score_counts_alerts_on_real_code_as_false_positives():
    from src.pipeline.synthesize import _score
    clean = graded(true_positives=2, detected=2)
    noisy = graded(true_positives=2, detected=2, negatives=50)

    assert _score(attempt(clean)) > _score(attempt(noisy))


WORKING_RULE_RESPONSE = f"```yaml\n{KNOWN_GOOD_RULE.read_text()}```"


def real_world_repo(tmp_path, files=12):
    repo = tmp_path / "real"
    repo.mkdir()
    for i in range(files):
        (repo / f"module{i}.c").write_text(
            "#include <stdlib.h>\nstruct s { int x; };\n\nint read_after_free(struct s *p)\n{\n"
            "\tfree(p);\n\treturn p->x;\n}\n", encoding="utf-8")
    return repo


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
@pytest.mark.parametrize("max_rate, accepted", [(0.0, False), (1000.0, True)])
def test_alerts_on_real_code_decide_acceptance_and_reach_the_corrector(tmp_path, monkeypatch, max_rate, accepted):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)
    repo = real_world_repo(tmp_path)
    prompts = []

    def fake_complete(role, prompt):
        prompts.append((role, prompt))
        return WORKING_RULE_RESPONSE, 0.0

    run = synthesize(
        "CWE-416", "A", bad, good, [tmp_path / "logs"], complete=fake_complete, min_recall=0.0,
        rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=1,
        negatives=repo, max_negative_rate=max_rate,
    )

    info = run["negatives"]
    assert info["train_files"] + info["test_files"] == 12 and info["train_files"] > 0
    assert info["max_rate"] == max_rate
    first = run["attempts"][0]["report"]
    assert first["negative_alerts"] == info["train_files"]  # one alert per train file
    assert run["accepted"] is accepted
    assert run["test_report"]["negative_alerts"] == info["test_files"]
    if accepted:
        assert [role for role, _ in prompts] == ["generator"]
    else:
        # the corrector is told what the rule raised on real code, with the code around it
        assert "Alerts on real-world C code" in prompts[1][1]
        assert "int read_after_free(struct s *p)" in prompts[1][1] and "> 7|" in prompts[1][1]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_without_negatives_nothing_changes_in_the_log(tmp_path, monkeypatch):
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    write_logs(tmp_path / "logs", bad)

    run = synthesize(
        "CWE-416", "A", bad, good, [tmp_path / "logs"], complete=lambda role, prompt: (WORKING_RULE_RESPONSE, 0.0),
        min_recall=0.0, rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", max_fix_attempts=0,
    )

    assert run["negatives"] is None
    assert run["accepted"]
    assert run["attempts"][0]["report"]["negative_alerts"] == 0
