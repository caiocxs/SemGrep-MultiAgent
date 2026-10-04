"""
Builds an ensemble from the candidate rules that earlier synthesis runs already
produced: many narrow rules with no false positives can cover different flow
variants, so their union has more recall than any single one.

Selection uses only the train split: every candidate is graded there, the ones
with too many false positives are dropped, and a greedy set cover picks the rules
that add the most not-yet-detected cases. The held-out test split is evaluated
once, for the chosen rules only, so selection never sees it. No rule is written
or edited by this module: the rules are the models' own, and the merged file only
gets a unique `id` suffix per rule.

    python -m src.pipeline.ensemble --cwe CWE-416 --out rules/ensemble/cwe-416.yaml
"""

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from src.pipeline.baseline import test_split
from src.pipeline.gate import collect_files, evaluate
from src.pipeline.split import flow_variant


def find_candidates(cwe, candidates_dir="rules/candidates"):
    """Distinct candidate rule files for a CWE across all combos and runs (identical content counted once)."""
    seen, found = set(), []
    for path in sorted(Path(candidates_dir).glob(f"*/{cwe}/**/*.yaml")):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest not in seen:
            seen.add(digest)
            found.append(path)
    return found


def train_split(cwe, bad_files, good_files, test_ratio=0.3, seed=0):
    """The complement of `baseline.test_split`: BAD/GOOD files of the variants the test split does not use."""
    prefix = cwe.replace("-", "")
    _, _, test_variants = test_split(cwe, bad_files, good_files, test_ratio, seed)
    def keep(files):
        return [str(f) for f in files
                if Path(f).name.startswith(prefix) and flow_variant(f) not in test_variants]
    return keep(bad_files), keep(good_files)


def _fp_keys(report):
    return {(m.path, m.line) for m in report.false_positives}


def greedy_cover(reports, max_fp=0):
    """
    reports: {name: GateReport} graded on the train split. Returns the names picked, in order.
    Only valid rules with at most `max_fp` false positives take part; each step adds the rule
    that detects the most cases not detected yet (ties: fewer false positives, then name), and
    the union of false positives of the picked rules stays within `max_fp`.
    """
    eligible = {n: r for n, r in reports.items()
                if r.valid and len(r.false_positives) <= max_fp and r.detected_cases}
    picked, covered, fps = [], set(), set()
    while eligible:
        def gain(name):
            return len(set(eligible[name].detected_cases) - covered)
        best = max(eligible, key=lambda n: (gain(n), -len(eligible[n].false_positives), n))
        if gain(best) == 0:
            break
        if len(fps | _fp_keys(eligible[best])) > max_fp:
            del eligible[best]
            continue
        picked.append(best)
        covered |= set(eligible[best].detected_cases)
        fps |= _fp_keys(eligible[best])
        del eligible[best]
    return picked


def union_summary(reports):
    """Recall/precision of several rules run together: union of detected cases and of graded matches."""
    reports = list(reports)
    cases = {c for r in reports for c in r.cases}
    detected = {c for r in reports for c in r.detected_cases}
    tp = {(m.path, m.line) for r in reports for m in r.true_positives}
    fp = {(m.path, m.line) for r in reports for m in r.false_positives}
    graded = len(tp) + len(fp)
    return dict(
        recall=round(len(detected) / len(cases), 4) if cases else 0.0,
        precision=round(len(tp) / graded, 4) if graded else 0.0,
        detected=len(detected), cases=len(cases), tp=len(tp), fp=len(fp),
    )


def merge_rules(paths, out_path):
    """Writes one YAML with every rule of `paths`; ids get `-ens<k>` so they stay unique."""
    merged, k = [], 0
    for path in paths:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        for rule in doc.get("rules", []):
            k += 1
            rule = dict(rule)
            rule["id"] = f"{rule.get('id', 'rule')}-ens{k}"
            merged.append(rule)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(yaml.safe_dump({"rules": merged}, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return out_path


def build(cwe, bad_files, good_files, candidates, max_fp=0, seed=0, out_path=None):
    """Grades candidates on train, picks the cover, grades the union on test. Returns a summary dict."""
    train_bad, train_good = train_split(cwe, bad_files, good_files, seed=seed)
    test_bad, test_good, _ = test_split(cwe, bad_files, good_files, seed=seed)

    train = {str(c): evaluate(c, train_bad, train_good) for c in candidates}
    invalid = sorted(n for n, r in train.items() if not r.valid)
    picked = greedy_cover(train, max_fp=max_fp)

    result = dict(
        cwe=cwe, candidates=len(candidates), invalid=len(invalid), picked=picked,
        train=union_summary(train[n] for n in picked) if picked else None,
        singles={n: union_summary([r]) for n, r in train.items() if r.valid},
        test=None, merged=None,
    )
    if picked:
        test = {n: evaluate(n, test_bad, test_good) for n in picked}
        result["test"] = union_summary(test.values())
        result["test_by_rule"] = {n: union_summary([r]) for n, r in test.items()}
        if out_path:
            merged = merge_rules(picked, out_path)
            report = evaluate(merged, test_bad, test_good)
            result["merged"] = dict(path=str(merged), valid=report.valid, **union_summary([report]))
    return result


def main():
    parser = argparse.ArgumentParser(description="Greedy set-cover ensemble of candidate rules.")
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--candidates", default="rules/candidates")
    parser.add_argument("--bad", nargs="+", default=["datasets/cwes_mixed/bad"])
    parser.add_argument("--good", nargs="+", default=["datasets/cwes_mixed/good"])
    parser.add_argument("--max-fp", type=int, default=0, help="False positives allowed on train (default 0)")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", default=None, help="Write the merged rule file here")
    parser.add_argument("--json", default=None, help="Write the summary here")
    args = parser.parse_args()

    candidates = find_candidates(args.cwe, args.candidates)
    print(f"{args.cwe}: {len(candidates)} distinct candidates")
    result = build(args.cwe, collect_files(args.bad), collect_files(args.good), candidates,
                   max_fp=args.max_fp, seed=args.seed, out_path=args.out)

    print(f"invalid: {result['invalid']} | picked: {len(result['picked'])}")
    for name in result["picked"]:
        single = result["singles"][name]
        print(f"  {name}: train recall={single['recall']:.1%} fp={single['fp']}")
    print(f"train union: {result['train']}")
    print(f"test  union: {result['test']}")
    if result["merged"]:
        print(f"merged file: {result['merged']}")
    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(result, indent=4), encoding="utf-8")


if __name__ == "__main__":
    main()
