import json
import shutil
from pathlib import Path

import pytest

from src.pipeline.crossval import format_table, run_folds, summarize
from src.pipeline.gate import collect_files
from src.pipeline.split import fold_split

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "juliet" / "cwe416"
KNOWN_GOOD_RULE = ROOT / "tests" / "fixtures" / "rules" / "cwe416_uaf.yaml"


def fake_files(variants=20):
    return [f"CWE416_Use_After_Free__malloc_free_int_{v:02d}_bad.c" for v in range(1, variants + 1)] + \
           [f"CWE416_Use_After_Free__malloc_free_char_{v:02d}_bad.c" for v in range(1, variants + 1)]


def test_every_variant_is_tested_exactly_once_over_the_folds():
    files = fake_files()
    tested = []
    for fold in range(5):
        train, test, variants = fold_split(files, 5, fold)
        assert len(variants) == 4  # 20 variants / 5 folds
        assert set(train) | set(test) == set(files) and not set(train) & set(test)
        tested += variants

    assert sorted(tested) == sorted({f"{v:02d}" for v in range(1, 21)})


def test_files_of_one_variant_stay_together_and_the_split_is_deterministic():
    files = fake_files()
    _, test, variants = fold_split(files, 4, 1, seed=3)

    assert len(test) == 2 * len(variants)  # int and char file of each variant
    assert fold_split(files, 4, 1, seed=3) == fold_split(files, 4, 1, seed=3)
    assert fold_split(files, 4, 1, seed=3)[2] != fold_split(files, 4, 1, seed=4)[2]


@pytest.mark.parametrize("folds, fold, message", [
    (1, 0, "at least 2"), (3, 3, "between 0 and 2"), (3, -1, "between 0 and 2"), (30, 0, "cannot make 30 folds"),
])
def test_invalid_folds_are_rejected(folds, fold, message):
    with pytest.raises(ValueError, match=message):
        fold_split(fake_files(), folds, fold)


def run_log(fold, recall, precision, tp, fp, accepted=False, has_rule=True, rate=0.5):
    test = {"recall": recall, "precision": precision, "negative_rate": rate,
            "true_positives": [{}] * tp, "false_positives": [{}] * fp} if has_rule else None
    return {"fold": fold, "run_id": f"r{fold}", "accepted": accepted, "best_attempt": 1,
            "split": {"test_variants": [f"{fold:02d}"]}, "test_report": test}


def test_summarize_averages_over_folds_and_counts_a_missing_rule_as_zero_recall():
    runs = [
        run_log(0, 1.0, 0.5, tp=10, fp=10, accepted=True),
        run_log(1, 0.5, 1.0, tp=5, fp=0),
        run_log(2, 0.0, 0.0, tp=0, fp=0),                   # valid rule that matched nothing
        run_log(3, 0.0, 0.0, tp=0, fp=0, has_rule=False),   # never got a valid rule
    ]
    summary = summarize(runs[::-1])  # order of arrival does not matter

    assert [f["fold"] for f in summary["folds"]] == [0, 1, 2, 3]
    assert summary["accepted_folds"] == 1 and summary["folds_with_rule"] == 3
    assert summary["recall_mean"] == 0.375  # (1 + .5 + 0 + 0) / 4
    # precision only over the two folds that graded something: a rule that matches nothing has none
    assert summary["precision_mean"] == 0.75
    assert summary["false_positives_total"] == 10
    assert summary["folds"][2]["precision"] is None and summary["folds"][3]["false_positives"] is None
    assert summary["real_world_rate_mean"] == 0.5


def test_summarize_single_fold_has_zero_deviation_and_table_lists_every_fold():
    summary = summarize([run_log(0, 0.5, 0.8, tp=4, fp=1)])
    assert summary["recall_sd"] == 0.0

    runs = [run_log(i, 0.5, 0.8, tp=4, fp=1) for i in range(3)]
    table = format_table(summarize(runs))
    assert table.count("\n") >= 4 and "accepted 0/3 folds" in table and "recall 50.0% +- 0.0%" in table


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")
def test_run_folds_covers_every_variant_and_never_touches_accepted_rules(tmp_path, monkeypatch):
    import json
    monkeypatch.chdir(ROOT)
    bad = collect_files([FIXTURES / "bad"])
    good = collect_files([FIXTURES / "good"])
    logs = tmp_path / "detector"
    logs.mkdir()
    for f in bad:
        (logs / f"log_{f.stem}.json").write_text(json.dumps({"vulnerable": True, "findings": [
            {"cwe": "CWE-416", "pointer": "data", "source_line": 1, "violation_line": 2, "description": "uaf"}]}),
            encoding="utf-8")
    response = f"```yaml\n{KNOWN_GOOD_RULE.read_text()}```"

    summary = run_folds(
        "CWE-416", "A", 3, complete=lambda role, prompt: (response, 0.0),
        rules_dir=tmp_path / "rules", logs_dir=tmp_path / "synthesis", crossval_dir=tmp_path / "crossval",
        bad_files=bad, good_files=good, log_dirs=[logs], min_recall=0.0, max_fix_attempts=0,
    )

    variants = [v for f in summary["folds"] for v in f["test_variants"]]
    assert sorted(variants) == ["01", "07", "63"]  # the three variants of the fixtures, one per fold
    assert len(list((tmp_path / "synthesis").rglob("*.json"))) == 3
    assert len(list((tmp_path / "crossval").rglob("*.json"))) == 1
    assert not (tmp_path / "rules" / "accepted").exists()  # accepted rules sit under rules/<run>/fold<i>/
    assert len(list((tmp_path / "rules").rglob("accepted/A/cwe-416.yaml"))) >= 1


def test_folds_without_a_fold_number_is_an_error(monkeypatch):
    from src.pipeline.synthesize import synthesize
    monkeypatch.chdir(ROOT)

    with pytest.raises(ValueError, match="fold is required"):
        synthesize("CWE-416", "A", collect_files([FIXTURES / "bad"]), [], [], complete=lambda r, p: ("", 0.0), folds=3)


# ----------------------------------------------------------------------------- resuming an interrupted cross-validation
from src.pipeline import crossval as crossval_module

OPTIONS = dict(output_format="template", seed=1, negatives="../git")


def finished_fold(run_id, fold, **override):
    """The run log `synthesize` writes when a fold ends, with the fields that decide whether it can be reused."""
    run = run_log(fold, 0.5, 0.9, tp=3, fp=1)
    run.update(run_id=run_id, cwe="CWE-416", combo="D", seed=1, folds=5, format="template", docs=True,
               roles={"history": False, "critic": False, "merge": False, "example_mode": "findings", "diagnose": True},
               negatives={"root": "../git", "train_files": 446, "test_files": 198, "max_rate": 0.1})
    run.update(override)
    return run


def write_runs(tmp_path, runs):
    folder = tmp_path / "synthesis" / "D" / "CWE-416"
    folder.mkdir(parents=True)
    for run in runs:
        (folder / f"{run['run_id']}.json").write_text(json.dumps(run), encoding="utf-8")
    (folder / "broken.json").write_text("{", encoding="utf-8")
    (folder / "list.json").write_text("[1]", encoding="utf-8")
    return tmp_path / "synthesis"


def test_only_runs_with_the_same_configuration_that_are_new_enough_are_reused(tmp_path):
    logs = write_runs(tmp_path, [
        finished_fold("20261007-100000", 0),
        finished_fold("20261007-100100", 1),
        finished_fold("20261007-080000", 2),                                    # older than the interrupted run
        finished_fold("20261007-100200", 3, seed=2),                            # another seed
        finished_fold("20261007-100300", 4, docs=False),                        # another option
        finished_fold("20261007-100400", 0, roles={"history": True, "critic": False, "merge": False,
                                                    "example_mode": "findings", "diagnose": True}),
        finished_fold("20261007-100500", 1, negatives={"root": "../other"}),    # other real-world code
        finished_fold("20261007-100600", 2, folds=4),                           # another number of folds
        finished_fold("20261007-100700", 3, format="yaml"),
    ])
    found = crossval_module.find_finished_folds(logs, "D", "CWE-416", 5, "20261007-090000", OPTIONS)

    assert sorted(found) == [0, 1] and found[0]["run_id"] == "20261007-100000" and found[1]["run_id"] == "20261007-100100"


def test_the_latest_run_of_a_fold_wins(tmp_path):
    logs = write_runs(tmp_path, [finished_fold("20261007-100000", 2), finished_fold("20261007-110000", 2)])
    found = crossval_module.find_finished_folds(logs, "D", "CWE-416", 5, "20261007-000000", OPTIONS)

    assert found[2]["run_id"] == "20261007-110000"


def test_a_log_from_before_the_options_were_recorded_counts_as_the_defaults(tmp_path):
    legacy = finished_fold("20261007-100000", 0)
    del legacy["roles"], legacy["docs"]
    logs = write_runs(tmp_path, [legacy])

    assert sorted(crossval_module.find_finished_folds(logs, "D", "CWE-416", 5, "20261007-000000", OPTIONS)) == [0]
    assert crossval_module.find_finished_folds(logs, "D", "CWE-416", 5, "20261007-000000", dict(OPTIONS, docs=False)) == {}


def fake_synthesize(calls):
    def synthesize(cwe, combo, complete=None, fold=None, folds=None, **kwargs):
        calls.append(fold)
        return finished_fold(f"2026100{8}-0000{fold}", fold)
    return synthesize


def test_a_resumed_run_only_runs_the_folds_that_are_missing(tmp_path, monkeypatch):
    logs = write_runs(tmp_path, [finished_fold("20261007-100000", 0), finished_fold("20261007-100100", 1),
                                 finished_fold("20261007-100300", 3)])
    calls = []
    monkeypatch.setattr(crossval_module, "synthesize", fake_synthesize(calls))

    summary = run_folds("CWE-416", "D", 5, complete=lambda role, prompt: ("", 0.0), logs_dir=logs, rules_dir=tmp_path / "rules",
                        crossval_dir=tmp_path / "crossval", resume_since="20261007-000000", **OPTIONS)

    assert calls == [2, 4]
    assert [f["fold"] for f in summary["folds"]] == [0, 1, 2, 3, 4] and summary["reused_folds"] == [0, 1, 3]
    assert len(list((tmp_path / "crossval").rglob("*.json"))) == 1


def test_nothing_is_reused_without_resume_since(tmp_path, monkeypatch):
    logs = write_runs(tmp_path, [finished_fold("20261007-100000", 0)])
    calls = []
    monkeypatch.setattr(crossval_module, "synthesize", fake_synthesize(calls))

    summary = run_folds("CWE-416", "D", 5, complete=lambda role, prompt: ("", 0.0), logs_dir=logs, rules_dir=tmp_path / "rules",
                        crossval_dir=tmp_path / "crossval", **OPTIONS)

    assert calls == [0, 1, 2, 3, 4] and summary["reused_folds"] == []


def test_the_model_is_not_loaded_when_every_fold_is_already_finished(tmp_path, monkeypatch):
    logs = write_runs(tmp_path, [finished_fold(f"20261007-10000{i}", i) for i in range(5)])

    def forbidden(*args, **kwargs):
        raise AssertionError("the model must not be loaded")

    monkeypatch.setattr(crossval_module, "synthesize", forbidden)
    monkeypatch.setattr("src.pipeline.llm.LocalLLM", forbidden)

    summary = run_folds("CWE-416", "D", 5, logs_dir=logs, rules_dir=tmp_path / "rules", crossval_dir=tmp_path / "crossval",
                        resume_since="20261007-000000", **OPTIONS)

    assert summary["reused_folds"] == [0, 1, 2, 3, 4]
