"""
Paired comparison of two cross-validation configurations.

`crossval` writes one summary per seed with the held-out numbers of every fold. Two configurations run on the
same seeds share their folds and their real-world files, so the folds can be compared pair by pair: the same
variants are tested, only the configuration differs. The comparison reports, per metric, the mean of the paired
differences, a bootstrap interval over the folds and how often each side was better.

    python -m src.pipeline.compare --a logs/crossval/D/CWE-416/<seed1>.json ... --label-a with-docs \\
        --b logs/crossval/D/CWE-416/<seed1-nodocs>.json ... --label-b no-docs

With 10 folds (two seeds) an interval is wide: it tells how large a difference would have to be before it could be
told apart from the spread over folds, not that a small difference is real. A pair is used only when both sides
have the metric (a fold without a valid rule has no precision, for example).
"""

import argparse
import json
import random
import statistics
from pathlib import Path

# metric -> (summary field, True when a larger value is better)
METRICS = {
    "recall": ("recall", True),
    "precision": ("precision", True),
    "false positives (Juliet)": ("false_positives", False),
    "real-world alerts/KLOC": ("real_world_rate", False),
    "accepted": ("accepted", True),
}


def load_folds(paths):
    """{(seed, fold): per-fold numbers} from `crossval` summaries; a seed must not appear twice on one side."""
    folds = {}
    for path in paths:
        summary = json.loads(Path(path).read_text(encoding="utf-8"))
        seed = summary["seed"]
        for fold in summary["folds"]:
            key = (seed, fold["fold"])
            if key in folds:
                raise ValueError(f"seed {seed} fold {fold['fold']} appears twice on the same side ({path})")
            folds[key] = fold
    return folds


def _value(fold, field):
    value = fold.get(field)
    return None if value is None else float(value)


def paired_values(a, b, field):
    """[(key, value in a, value in b)] for the folds present on both sides with the metric defined on both."""
    pairs = []
    for key in sorted(set(a) & set(b)):
        va, vb = _value(a[key], field), _value(b[key], field)
        if va is not None and vb is not None:
            pairs.append((key, va, vb))
    return pairs


def bootstrap_interval(differences, resamples=10000, seed=0, level=0.95):
    """Percentile interval of the mean of the paired differences, resampling the folds."""
    if len(differences) < 2:
        return None
    rng = random.Random(seed)
    n = len(differences)
    means = sorted(statistics.fmean(rng.choices(differences, k=n)) for _ in range(resamples))
    low = means[int((1 - level) / 2 * resamples)]
    high = means[min(resamples - 1, int((1 + level) / 2 * resamples))]
    return low, high


def compare_metric(a, b, field, higher_is_better):
    pairs = paired_values(a, b, field)
    if not pairs:
        return None
    differences = [vb - va for _, va, vb in pairs]  # b minus a
    better = (lambda d: d > 0) if higher_is_better else (lambda d: d < 0)
    worse = (lambda d: d < 0) if higher_is_better else (lambda d: d > 0)
    return {
        "pairs": len(pairs),
        "mean_a": statistics.fmean(va for _, va, _ in pairs),
        "mean_b": statistics.fmean(vb for _, _, vb in pairs),
        "mean_difference": statistics.fmean(differences),
        "interval": bootstrap_interval(differences),
        "b_better": sum(better(d) for d in differences),
        "a_better": sum(worse(d) for d in differences),
        "ties": sum(d == 0 for d in differences),
    }


def compare(a, b):
    return {name: compare_metric(a, b, field, higher) for name, (field, higher) in METRICS.items()}


def format_report(result, label_a, label_b, folds_a, folds_b):
    shared = len(set(folds_a) & set(folds_b))
    lines = [f"{label_a}: {len(folds_a)} folds | {label_b}: {len(folds_b)} folds | shared (same seed and fold): {shared}",
             "",
             f"{'metric':<26}{'pairs':>6}{label_a[:12]:>14}{label_b[:12]:>14}{'b - a':>10}   {'95% interval':<22}{'b better':>10}{'a better':>10}"]
    for name, row in result.items():
        if row is None:
            lines.append(f"{name:<26}{0:>6}  no fold has the metric on both sides")
            continue
        low, high = row["interval"] or (float("nan"), float("nan"))
        interval = "-" if row["interval"] is None else f"[{low:+.3f}, {high:+.3f}]"
        lines.append(f"{name:<26}{row['pairs']:>6}{row['mean_a']:>14.3f}{row['mean_b']:>14.3f}{row['mean_difference']:>+10.3f}   "
                     f"{interval:<22}{row['b_better']:>10}{row['a_better']:>10}")
    lines.append(f"\na = {label_a}, b = {label_b}. Recall and precision are fractions (0-1); the interval is a bootstrap over the paired folds.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Paired comparison of two cross-validation configurations.")
    parser.add_argument("--a", nargs="+", required=True, help="crossval summaries of configuration A (one per seed)")
    parser.add_argument("--b", nargs="+", required=True, help="crossval summaries of configuration B, on the same seeds")
    parser.add_argument("--label-a", default="A")
    parser.add_argument("--label-b", default="B")
    parser.add_argument("--json", default=None, help="Also write the result here")
    args = parser.parse_args()

    folds_a, folds_b = load_folds(args.a), load_folds(args.b)
    result = compare(folds_a, folds_b)
    print(format_report(result, args.label_a, args.label_b, folds_a, folds_b))
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=4), encoding="utf-8")


if __name__ == "__main__":
    main()
