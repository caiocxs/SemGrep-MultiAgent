import shutil
from pathlib import Path

import pytest
import yaml

from src.pipeline.ensemble import build, find_candidates, greedy_cover, merge_rules, train_split, union_summary
from src.pipeline.gate import GateReport, Match, collect_files

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "juliet" / "cwe416"
KNOWN_GOOD_RULE = ROOT / "tests" / "fixtures" / "rules" / "cwe416_uaf.yaml"
PREFIX = "CWE416_Use_After_Free__"

needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


def report(cases, detected, fp=(), errors=()):
    """A GateReport that detects `detected` (case ids) and has false positives at the given lines."""
    r = GateReport(rule_path="r.yaml", errors=list(errors), cases={c: [f"{c}_bad.c"] for c in cases})
    r.true_positives = [Match(f"{c}_bad.c", 1, "r") for c in detected]
    r.false_positives = [Match("x_good.c", line, "r") for line in fp]
    return r


CASES = ["a", "b", "c", "d"]


def test_greedy_cover_picks_complementary_rules():
    reports = {
        "wide": report(CASES, ["a", "b"]),
        "other": report(CASES, ["c"]),
        "subset": report(CASES, ["a"]),
    }
    assert greedy_cover(reports) == ["wide", "other"]


def test_greedy_cover_drops_false_positives_and_invalid_rules():
    reports = {
        "noisy": report(CASES, ["a", "b", "c"], fp=[3]),
        "broken": report(CASES, [], errors=["boom"]),
        "silent": report(CASES, []),
        "safe": report(CASES, ["d"]),
    }
    assert greedy_cover(reports) == ["safe"]


def test_greedy_cover_max_fp_bounds_the_union():
    reports = {
        "one": report(CASES, ["a", "b"], fp=[1]),
        "two": report(CASES, ["c"], fp=[2]),
    }
    assert greedy_cover(reports, max_fp=1) == ["one"]
    assert greedy_cover(reports, max_fp=2) == ["one", "two"]


def test_greedy_cover_empty():
    assert greedy_cover({}) == []


def test_union_summary_counts_shared_matches_once():
    r1, r2 = report(CASES, ["a", "b"], fp=[1]), report(CASES, ["b", "c"], fp=[1, 2])
    s = union_summary([r1, r2])
    assert (s["detected"], s["cases"], s["tp"], s["fp"]) == (3, 4, 3, 2)
    assert s["recall"] == 0.75


def test_find_candidates_dedups_identical_content(tmp_path):
    for run, body in [("r1", "rules: []\n"), ("r2", "rules: []\n"), ("r3", "rules: [x]\n")]:
        d = tmp_path / "C" / "CWE-416" / run
        d.mkdir(parents=True)
        (d / "attempt_0.yaml").write_text(body, encoding="utf-8")
    (tmp_path / "C" / "CWE-415").mkdir(parents=True)
    (tmp_path / "C" / "CWE-415" / "other.yaml").write_text("rules: [y]\n", encoding="utf-8")
    assert len(find_candidates("CWE-416", tmp_path)) == 2


def test_merge_rules_gives_unique_ids(tmp_path):
    a, b = tmp_path / "a.yaml", tmp_path / "b.yaml"
    for p in (a, b):
        p.write_text(yaml.safe_dump({"rules": [{"id": "gen-cwe-416", "message": "m"}]}), encoding="utf-8")
    out = merge_rules([a, b], tmp_path / "out" / "m.yaml")
    ids = [r["id"] for r in yaml.safe_load(out.read_text(encoding="utf-8"))["rules"]]
    assert ids == ["gen-cwe-416-ens1", "gen-cwe-416-ens2"]


def test_train_split_is_the_complement_of_test():
    bad, good = collect_files([FIXTURES / "bad"]), collect_files([FIXTURES / "good"])
    from src.pipeline.baseline import test_split
    tb, tg, _ = test_split("CWE-416", bad, good, seed=0)
    rb, rg = train_split("CWE-416", bad, good, seed=0)
    assert set(rb).isdisjoint(tb) and set(rg).isdisjoint(tg)
    assert len(rb) + len(tb) == len(bad)


@needs_semgrep
def test_build_end_to_end_on_fixtures(tmp_path):
    cand = tmp_path / "C" / "CWE-416" / "run"
    cand.mkdir(parents=True)
    shutil.copy(KNOWN_GOOD_RULE, cand / "attempt_0.yaml")
    (cand / "attempt_1.yaml").write_text("rules:\n- id: x\n  pattern: 'foo(\n", encoding="utf-8")  # invalid
    bad, good = collect_files([FIXTURES / "bad"]), collect_files([FIXTURES / "good"])
    result = build("CWE-416", bad, good, find_candidates("CWE-416", tmp_path),
                   out_path=tmp_path / "out" / "ens.yaml")
    assert result["invalid"] == 1
    assert len(result["picked"]) == 1
    assert result["train"]["fp"] == 0
    assert result["merged"]["valid"] and result["merged"]["fp"] == 0
    assert result["merged"]["recall"] == result["test"]["recall"]
