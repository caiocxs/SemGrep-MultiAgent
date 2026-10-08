import json

import pytest

from src.pipeline.compare import (bootstrap_interval, compare, compare_metric, format_report, load_folds, paired_values)


def fold(i, recall, precision=None, fp=0, rate=1.0, accepted=False):
    return {"fold": i, "recall": recall, "precision": precision, "false_positives": fp, "real_world_rate": rate,
            "accepted": accepted}


def write_summary(tmp_path, name, seed, folds):
    path = tmp_path / name
    path.write_text(json.dumps({"seed": seed, "folds": folds}), encoding="utf-8")
    return path


def test_folds_are_keyed_by_seed_and_fold_across_files(tmp_path):
    one = write_summary(tmp_path, "s1.json", 1, [fold(0, 0.5), fold(1, 0.6)])
    two = write_summary(tmp_path, "s2.json", 2, [fold(0, 0.7)])

    assert sorted(load_folds([one, two])) == [(1, 0), (1, 1), (2, 0)]


def test_the_same_seed_twice_on_one_side_is_an_error(tmp_path):
    first = write_summary(tmp_path, "a.json", 1, [fold(0, 0.5)])
    again = write_summary(tmp_path, "b.json", 1, [fold(0, 0.9)])

    with pytest.raises(ValueError, match="seed 1 fold 0 appears twice"):
        load_folds([first, again])


def test_only_folds_on_both_sides_with_the_metric_are_paired():
    a = {(1, 0): fold(0, 0.5, precision=1.0), (1, 1): fold(1, 0.6, precision=None), (1, 2): fold(2, 0.7, precision=0.5)}
    b = {(1, 0): fold(0, 0.6, precision=0.9), (1, 1): fold(1, 0.7, precision=0.8), (2, 0): fold(0, 0.1, precision=0.1)}

    assert paired_values(a, b, "recall") == [((1, 0), 0.5, 0.6), ((1, 1), 0.6, 0.7)]      # fold (1,2) and (2,0) are unpaired
    assert paired_values(a, b, "precision") == [((1, 0), 1.0, 0.9)]                       # a fold without precision is skipped


def test_the_difference_is_b_minus_a_and_wins_follow_the_direction_of_the_metric():
    a = {(1, i): fold(i, r, rate=x) for i, (r, x) in enumerate([(0.5, 2.0), (0.6, 3.0), (0.7, 1.0)])}
    b = {(1, i): fold(i, r, rate=x) for i, (r, x) in enumerate([(0.6, 1.0), (0.6, 3.5), (0.9, 1.0)])}

    recall = compare_metric(a, b, "recall", True)
    assert recall["pairs"] == 3 and recall["mean_difference"] == pytest.approx((0.1 + 0 + 0.2) / 3)
    assert (recall["b_better"], recall["a_better"], recall["ties"]) == (2, 0, 1)

    rate = compare_metric(a, b, "real_world_rate", False)                                  # lower is better
    assert rate["mean_difference"] == pytest.approx((-1.0 + 0.5 + 0) / 3)
    assert (rate["b_better"], rate["a_better"], rate["ties"]) == (1, 1, 1)


def test_no_pairs_gives_no_result():
    assert compare_metric({(1, 0): fold(0, 0.5)}, {(2, 0): fold(0, 0.5)}, "recall", True) is None


def test_the_bootstrap_interval_is_deterministic_and_contains_the_mean():
    differences = [0.1, 0.2, -0.05, 0.15, 0.0, 0.3, 0.1, 0.05, 0.2, 0.1]
    low, high = bootstrap_interval(differences)

    assert (low, high) == bootstrap_interval(differences)
    assert low < sum(differences) / len(differences) < high
    assert bootstrap_interval([0.3]) is None                                               # one pair has no spread


def test_an_interval_around_zero_for_identical_configurations():
    same = {(1, i): fold(i, 0.5 + 0.1 * i) for i in range(5)}
    result = compare(same, dict(same))

    assert result["recall"]["mean_difference"] == 0 and result["recall"]["ties"] == 5
    assert result["recall"]["interval"] == (0.0, 0.0)


def test_the_report_names_the_sides_and_handles_a_metric_without_pairs():
    a = {(1, 0): fold(0, 0.5, precision=None), (1, 1): fold(1, 0.6, precision=None)}
    b = {(1, 0): fold(0, 0.6, precision=None), (1, 1): fold(1, 0.7, precision=None)}
    text = format_report(compare(a, b), "with-docs", "no-docs", a, b)

    assert "with-docs: 2 folds | no-docs: 2 folds | shared (same seed and fold): 2" in text
    assert "recall" in text and "+0.100" in text
    assert "precision" in text and "no fold has the metric on both sides" in text
