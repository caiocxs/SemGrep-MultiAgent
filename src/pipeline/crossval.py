"""
k-fold cross-validation of the rule synthesis, by flow variant.

A single train/test split of CWE-416 tests 6 variants; the number moves a lot with which
6 are drawn. Here the variants are dealt into k folds (`split.fold_split`), the whole
generator -> gate -> corrector loop runs once per fold with that fold as the held-out
test, and the test numbers are averaged: every variant is tested exactly once.

The model is loaded once and shared by all folds. Rules go to `rules/crossval/<run>/fold<i>/`,
never to the versioned `rules/accepted/`. Each fold also writes its usual run log to
`logs/synthesis/<combo>/<cwe>/`; the summary goes to `logs/crossval/<combo>/<cwe>/<run>.json`.

    python -m src.pipeline.crossval --combo C --cwe CWE-416 --format template --folds 5 \\
        --negatives ../git
"""

import argparse
import json
import statistics
import time
from pathlib import Path

from src.config import load_combo
from src.pipeline.gate import collect_files
from src.pipeline.synthesize import CWES, synthesize


def _mean_sd(values):
    values = list(values)
    if not values:
        return None, None
    return round(statistics.mean(values), 4), round(statistics.stdev(values), 4) if len(values) > 1 else 0.0


def summarize(runs):
    """
    Per-fold held-out numbers and their mean and standard deviation over folds. Recall counts a
    fold without any valid rule as 0; precision is averaged only over folds whose rule matched
    something (a rule that matches nothing has no precision, not a precision of 0).
    """
    folds = []
    for run in sorted(runs, key=lambda r: r["fold"]):
        test = run["test_report"]
        graded = (len(test["true_positives"]) + len(test["false_positives"])) if test else 0
        folds.append({
            "fold": run["fold"],
            "test_variants": run["split"]["test_variants"],
            "accepted": run["accepted"],
            "best_attempt": run["best_attempt"],
            "has_rule": test is not None,
            "recall": test["recall"] if test else 0.0,
            "precision": test["precision"] if graded else None,
            "false_positives": len(test["false_positives"]) if test else None,
            "real_world_rate": test.get("negative_rate") if test else None,
            "run_id": run["run_id"],
        })
    recall = _mean_sd(f["recall"] for f in folds)
    precision = _mean_sd(f["precision"] for f in folds if f["precision"] is not None)
    rate = _mean_sd(f["real_world_rate"] for f in folds if f["real_world_rate"] is not None)
    return {
        "folds": folds,
        "accepted_folds": sum(f["accepted"] for f in folds),
        "folds_with_rule": sum(f["has_rule"] for f in folds),
        "recall_mean": recall[0], "recall_sd": recall[1],
        "precision_mean": precision[0], "precision_sd": precision[1],
        "real_world_rate_mean": rate[0], "real_world_rate_sd": rate[1],
        "false_positives_total": sum(f["false_positives"] or 0 for f in folds),
    }


def format_table(summary):
    def pct(x):
        return "-" if x is None else f"{x:.1%}"
    lines = ["fold  test variants          accepted  recall  precision  FP     real-world/KLOC"]
    for f in summary["folds"]:
        rate = "-" if f["real_world_rate"] is None else f"{f['real_world_rate']:.2f}"
        fp = "-" if f["false_positives"] is None else str(f["false_positives"])
        lines.append(f"{f['fold']:<5} {', '.join(f['test_variants']):<22} {str(f['accepted']):<9} "
                     f"{pct(f['recall']):<7} {pct(f['precision']):<10} {fp:<6} {rate}")
    lines.append(
        f"\naccepted {summary['accepted_folds']}/{len(summary['folds'])} folds, "
        f"{summary['folds_with_rule']} with a valid rule | "
        f"recall {pct(summary['recall_mean'])} +- {pct(summary['recall_sd'])} | "
        f"precision {pct(summary['precision_mean'])} +- {pct(summary['precision_sd'])}"
    )
    return "\n".join(lines)


def run_folds(cwe, combo_name, folds, complete=None, rules_dir=Path("rules/crossval"),
              logs_dir=Path("logs/synthesis"), crossval_dir=Path("logs/crossval"), **kwargs):
    """Runs `synthesize` once per fold (kwargs go to it) and returns the summary; also written to disk."""
    if complete is None:
        from src.pipeline.llm import LocalLLM
        complete = LocalLLM(load_combo(combo_name)).complete  # one model load for all folds
    stamp = time.strftime("%Y%m%d-%H%M%S")
    runs = []
    for fold in range(folds):
        print(f"\n=== fold {fold + 1}/{folds} ===")
        runs.append(synthesize(cwe, combo_name, complete=complete, fold=fold, folds=folds,
                               rules_dir=Path(rules_dir) / stamp / f"fold{fold}", logs_dir=logs_dir, **kwargs))
    summary = summarize(runs)
    summary.update(cwe=cwe, combo=combo_name, run=stamp, seed=kwargs.get("seed", 0),
                   format=kwargs.get("output_format", "yaml"), negatives=kwargs.get("negatives"),
                   docs=kwargs.get("docs", True),
                   roles={k: kwargs.get(k, default) for k, default in (
                       ("history", False), ("critic", False), ("merge", False),
                       ("example_mode", "findings"), ("diagnose", True))})
    out = Path(crossval_dir) / combo_name / cwe / f"{stamp}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=4, ensure_ascii=False), encoding="utf-8")
    print("\n" + format_table(summary) + f"\nSummary: {out}")
    return summary


def main():
    parser = argparse.ArgumentParser(description="k-fold cross-validation (by flow variant) of the rule synthesis.")
    parser.add_argument("--combo", required=True)
    parser.add_argument("--cwe", required=True, choices=sorted(CWES))
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--bad", nargs="+", default=["datasets/cwes_mixed/bad"])
    parser.add_argument("--good", nargs="+", default=["datasets/cwes_mixed/good"])
    parser.add_argument("--logs", nargs="+",
                        default=["logs/dataset/QWEN_CODE/CWES_BAD", "logs/dataset/QWEN_CODE/CWES_GOOD"])
    parser.add_argument("--examples", type=int, default=3)
    parser.add_argument("--min-recall", type=float, default=0.5)
    parser.add_argument("--max-fix-attempts", type=int, default=None)
    parser.add_argument("--seed", type=int, default=0, help="Seed of the fold assignment and the example choice")
    parser.add_argument("--format", choices=("yaml", "spec", "template"), default="yaml")
    parser.add_argument("--negatives", default=None)
    parser.add_argument("--max-negative-rate", type=float, default=0.1)
    parser.add_argument("--negatives-max-files", type=int, default=None)
    parser.add_argument("--no-docs", action="store_true", help="Leave the Semgrep documentation out of the prompts")
    parser.add_argument("--history", action="store_true")
    parser.add_argument("--critic", action="store_true")
    parser.add_argument("--merge", action="store_true")
    parser.add_argument("--example-mode", choices=("findings", "pairs", "none"), default="findings")
    parser.add_argument("--no-diagnosis", action="store_true")
    args = parser.parse_args()

    run_folds(
        args.cwe, args.combo, args.folds,
        bad_files=collect_files(args.bad), good_files=collect_files(args.good), log_dirs=args.logs,
        n_examples=args.examples, min_recall=args.min_recall, seed=args.seed,
        max_fix_attempts=args.max_fix_attempts, output_format=args.format,
        negatives=args.negatives, max_negative_rate=args.max_negative_rate,
        max_negative_files=args.negatives_max_files, docs=not args.no_docs, history=args.history,
        critic=args.critic, merge=args.merge, example_mode=args.example_mode, diagnose=not args.no_diagnosis,
    )


if __name__ == "__main__":
    main()
