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
