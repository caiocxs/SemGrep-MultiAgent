"""
Secondary metrics of docs/ablation_plan.md for two configurations run on the same seeds, from the cross-validation summaries and
the run logs they point to: attempts that repeat an earlier rule, attempts that reach the gate, attempts with a not_inside, the
position of the best attempt, and the median time and prompt size of a model call. Descriptive only: the plan claims effects
for the primary metrics (python -m src.pipeline.compare).

    python scripts/secondary_metrics.py 20261006-001149,20261006-005913 20261008-204035,20261008-212828 [--combo D] [--cwe CWE-416]

Each argument is a comma-separated list of summary names (the file names under logs/crossval/<combo>/<cwe>/ without .json).
"""

import argparse
import json
import re
import statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_runs(names, combo, cwe):
    runs, flags = [], None
    for name in names:
        summary = json.loads((ROOT / "logs/crossval" / combo / cwe / f"{name}.json").read_text(encoding="utf-8"))
        flags = (summary.get("docs"), summary.get("roles"))
        for fold in summary["folds"]:
            path = ROOT / "logs/synthesis" / combo / cwe / f"{fold['run_id']}.json"
            runs.append(json.loads(path.read_text(encoding="utf-8")))
    return runs, flags


def uses_not_inside(response):
    match = re.search(r"```json\s*(.*?)```", response, re.S)
    if not match:
        return False
    try:
        spec = json.loads(match.group(1))
    except ValueError:
        return False
    return any(isinstance(u, dict) and u.get("not_inside") for u in spec.get("uses", []))


def metrics(runs):
    attempts = [a for r in runs for a in r["attempts"]]
    n = len(attempts)
    repeated = sum(1 for a in attempts if a["problems"] and a["problems"][0].startswith("This is exactly the same rule"))
    valid = sum(1 for a in attempts if a["report"] and a["report"]["valid"])
    not_inside = sum(uses_not_inside(a["response"]) for a in attempts)
    best = [r["best_attempt"] for r in runs if r["test_report"]]
    return {
        "folds": len(runs),
        "attempts": n,
        "repeat an earlier rule": f"{repeated} ({repeated / n:.1%})",
        "reach the gate (valid)": f"{valid} ({valid / n:.1%})",
        "with a not_inside": f"{not_inside} ({not_inside / n:.1%})",
        "best attempt, mean position": round(st.mean(best), 2) if best else "-",
        "best attempt after the 3rd try": f"{sum(1 for b in best if b >= 3)}/{len(best)}",
        "seconds per call, median": round(st.median(a["seconds"] for a in attempts)),
        "prompt characters, median": round(st.median(a["prompt_chars"] for a in attempts)),
    }


def main():
    parser = argparse.ArgumentParser(description="Secondary metrics of two cross-validated configurations.")
    parser.add_argument("baseline", help="comma-separated summary names of the baseline")
    parser.add_argument("other", help="comma-separated summary names of the other configuration")
    parser.add_argument("--combo", default="D")
    parser.add_argument("--cwe", default="CWE-416")
    args = parser.parse_args()

    base, base_flags = load_runs(args.baseline.split(","), args.combo, args.cwe)
    other, other_flags = load_runs(args.other.split(","), args.combo, args.cwe)
    print("options recorded: baseline", base_flags, "| other", other_flags)
    a, b = metrics(base), metrics(other)
    print(f"\n{'':34}{'baseline':>16}{'other':>16}")
    for key in a:
        print(f"{key:34}{str(a[key]):>16}{str(b[key]):>16}")


if __name__ == "__main__":
    main()
