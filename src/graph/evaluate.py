"""
Scores the event-graph query like the Semgrep gate scores a rule: per Juliet case (a match in a `*bad*` function of a BAD file is
a hit, in a `*good*` function a false positive; a case split across files is found if any of its files is) and alerts per KLOC
on real-world code assumed correct.

    python -m src.graph.evaluate --bad datasets/cwes_mixed/bad --good datasets/cwes_mixed/good --filter "CWE416*" \
        [--query use_after_free|double_free] [--negatives ../git]
"""

import argparse
import time
from collections import defaultdict
from pathlib import Path

from src.graph import extract, paths
from src.pipeline.gate import case_id, collect_files, function_role
from src.pipeline.split import flow_variant, split_negatives


def _kloc(files):
    total = 0
    for f in files:
        with open(f, "rb") as handle:
            total += sum(1 for _ in handle)
    return total / 1000


def score_juliet(conn, bad_files, good_files, query):
    bad_set = {str(f) for f in bad_files}
    cases = defaultdict(list)
    for f in bad_files:
        cases[case_id(f)].append(str(f))
    hits, false_positives, neutral = set(), [], 0
    for c in getattr(paths, query)(conn):
        role = function_role(c["function"])
        if role == "good":
            false_positives.append(c)
        elif c["path"] in bad_set:
            hits.add(case_id(c["path"]))
        elif role == "bad":
            neutral += 1
        else:
            false_positives.append(c)
    by_variant = defaultdict(lambda: [0, 0])
    for case, files in cases.items():
        by_variant[flow_variant(files[0])][1] += 1
        by_variant[flow_variant(files[0])][0] += case in hits
    return {"cases": len(cases), "detected": len(hits), "false_positives": false_positives, "neutral": neutral,
            "by_variant": dict(sorted(by_variant.items())), "missed": sorted(set(cases) - hits)}


def main():
    parser = argparse.ArgumentParser(description="Event-graph query on Juliet and on real-world code.")
    parser.add_argument("--bad", nargs="+", required=True)
    parser.add_argument("--good", nargs="*", default=[])
    parser.add_argument("--filter", default="*")
    parser.add_argument("--query", choices=("use_after_free", "double_free"), default="use_after_free")
    parser.add_argument("--negatives", default=None, help="Real-world code assumed correct (e.g. ../git)")
    parser.add_argument("--show-missed", action="store_true")
    parser.add_argument("--seed", type=int, default=0, help="Seed of the train/test split of the real-world files")
    parser.add_argument("--show", type=int, default=10, help="Alerts to print")
    parser.add_argument("--show-test-alerts", action="store_true", help="Also print alerts of the test files (final reading only)")
    args = parser.parse_args()

    bad, good = collect_files(args.bad, args.filter), collect_files(args.good, args.filter)
    start = time.time()
    conn, failed = extract.build(bad + good)
    events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"Juliet: {len(bad)} BAD / {len(good)} GOOD files, {events} events, extracted in {time.time() - start:.1f}s"
          + (f", {len(failed)} failed" if failed else ""))
    start = time.time()
    result = score_juliet(conn, bad, good, args.query)
    print(f"query {args.query} in {time.time() - start:.1f}s: detected {result['detected']}/{result['cases']} cases "
          f"({result['detected'] / max(result['cases'], 1):.1%}), {len(result['false_positives'])} false positives, "
          f"{result['neutral']} neutral")
    print("recall by variant: " + "  ".join(f"{v}:{d}/{n}" for v, (d, n) in result["by_variant"].items()))
    for fp in result["false_positives"][:10]:
        print(f"  FP {Path(fp['path']).name}:{fp['line']} {fp['function']} free@{fp['free_line']} {fp['detail']}")
    if args.show_missed:
        print("missed: " + ", ".join(result["missed"]))

    if args.negatives:
        files = collect_files([args.negatives])
        start = time.time()
        real, failed = extract.build(files, headers=sorted(Path(args.negatives).rglob("*.h")))
        print(f"\nReal-world: {len(files)} files, {_kloc(files):.0f} KLOC, "
              f"{real.execute('SELECT COUNT(*) FROM events').fetchone()[0]} events, extracted in {time.time() - start:.1f}s")
        start = time.time()
        alerts = getattr(paths, args.query)(real)
        train, test = split_negatives(files, args.negatives, 0.3, args.seed)
        print(f"query in {time.time() - start:.1f}s (split by file hash, seed {args.seed}: {len(train)} train / {len(test)} test files)")
        for name, side in (("train", train), ("test", test)):
            keys = set(side)
            mine = [a for a in alerts if a["path"] in keys]
            print(f"  {name}: {len(mine)} alerts = {len(mine) / _kloc(side):.3f} per KLOC")
        if not args.show_test_alerts:  # the test side stays unread while the extractor is being tuned
            alerts = [a for a in alerts if a["path"] in set(train)]
        for a in alerts[:args.show]:
            print(f"  {Path(a['path']).name}:{a['line']} {a['function']} free@{a['free_line']} [{a['kind']}] {a['detail']}")

if __name__ == "__main__":
    main()
