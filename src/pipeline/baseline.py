"""
Grades existing rule files (e.g. the official Semgrep packs) with the same gate
and the same held-out test split that `synthesize` uses, so their numbers are
directly comparable with the generated rules.

    python -m src.pipeline.baseline --cwe CWE-416 --rules rules/baseline/semgrep_p_c.yaml
"""

import argparse
import json
from pathlib import Path

from src.pipeline.gate import collect_files, evaluate
from src.pipeline.split import flow_variant, split_files


def test_split(cwe, bad_files, good_files, test_ratio=0.3, seed=0):
    prefix = cwe.replace("-", "")
    bad = [str(f) for f in bad_files if Path(f).name.startswith(prefix)]
    good = [str(f) for f in good_files if Path(f).name.startswith(prefix)]
    _, test_bad, variants = split_files(bad, test_ratio, seed)
    return test_bad, [f for f in good if flow_variant(f) in variants], variants


def main():
    parser = argparse.ArgumentParser(description="Grade existing rule files on the held-out test split.")
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--rules", nargs="+", required=True, help="Rule YAML files")
    parser.add_argument("--bad", nargs="+", default=["datasets/cwes_mixed/bad"])
    parser.add_argument("--good", nargs="+", default=["datasets/cwes_mixed/good"])
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--json", default=None, help="Write the summary of all rule files here")
    args = parser.parse_args()

    test_bad, test_good, variants = test_split(
        args.cwe, collect_files(args.bad), collect_files(args.good), seed=args.seed)
    print(f"{args.cwe} | test {len(test_bad)} BAD / {len(test_good)} GOOD (variants {', '.join(variants)})\n")

    summary = {}
    for rule in args.rules:
        report = evaluate(rule, test_bad, test_good)
        if not report.valid:
            print(f"{rule}: INVALID - {report.errors[:2]}")
            continue
        summary[rule] = dict(
            recall=round(report.recall, 4), precision=round(report.precision, 4),
            tp=len(report.true_positives), fp=len(report.false_positives), neutral=len(report.neutral),
        )
        print(f"{rule}: recall={report.recall:.1%} precision={report.precision:.1%} "
              f"tp={len(report.true_positives)} fp={len(report.false_positives)} neutral={len(report.neutral)}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(summary, indent=4), encoding="utf-8")


if __name__ == "__main__":
    main()
