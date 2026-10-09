"""
Does the event-graph query point at real fixes? Takes the commits of a repository since a date whose subject names a use after
free, a double free or a freed pointer (the filter of docs/experiments.md, fixed before this script was written), runs the
query on each changed .c file before and after the fix, and counts an alert as "near the fix" when it lies within WINDOW lines of
a line the fix changed (old line numbers for the file before, new ones for the file after).

    python -m src.graph.fixcommits ../git [--window 10] [--since 2018-01-01]

Reported per commit: alerts near the fix before / after, and the alerts of the file in total (noise). Chance level: the share of
the `free()` lines of the same files that lie within the window, which is what a predictor that flags every `free()` would hit.
"""

import argparse
import re
import subprocess
import tempfile
from pathlib import Path

from src.graph import extract, paths

SUBJECT_FILTER = re.compile(r"use[- ]after[- ]free|double[- ]free|\bfreed\b|memory after", re.IGNORECASE)
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)


def git(repo, *args, binary=False):
    out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout
    return out if binary else out.decode("utf-8", errors="replace")


def fix_commits(repo, since):
    lines = git(repo, "log", "--no-merges", f"--since={since}", "--format=%H\t%s").splitlines()
    return [(h, s) for h, s in (line.split("\t", 1) for line in lines) if SUBJECT_FILTER.search(s)]


def changed_c_files(repo, commit):
    return [f for f in git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines() if f.endswith(".c")]


def changed_lines(repo, commit, path):
    """(old ranges, new ranges) of the lines the commit touched in `path`, as (first, last)."""
    diff = git(repo, "diff", "-U0", f"{commit}^", commit, "--", path)
    old, new = [], []
    for a, b, c, d in HUNK.findall(diff):
        count_old, count_new = int(b) if b != "" else 1, int(d) if d != "" else 1
        old.append((int(a), int(a) + max(count_old, 1) - 1))
        new.append((int(c), int(c) + max(count_new, 1) - 1))
    return old, new


def near(line, ranges, window):
    return any(first - window <= line <= last + window for first, last in ranges)


def alerts_of(repo, rev, path, workdir):
    try:
        source = git(repo, "show", f"{rev}:{path}", binary=True)
    except subprocess.CalledProcessError:
        return None, []
    target = Path(workdir) / "file.c"
    target.write_bytes(source)
    conn, _ = extract.build([target])
    alerts = paths.use_after_free(conn) + paths.double_free(conn)
    free_lines = [r[0] for r in conn.execute("SELECT line FROM events WHERE kind = 'free'")]
    return alerts, free_lines


def main():
    parser = argparse.ArgumentParser(description="Event-graph query against the fix commits of a repository.")
    parser.add_argument("repo")
    parser.add_argument("--since", default="2018-01-01")
    parser.add_argument("--window", type=int, default=10)
    args = parser.parse_args()

    commits = fix_commits(args.repo, args.since)
    print(f"{len(commits)} commits since {args.since} whose subject matches the filter\n")
    totals = {"files": 0, "before": 0, "gone": 0, "alerts_before": 0, "alerts_after": 0, "free_total": 0, "free_near": 0}
    with tempfile.TemporaryDirectory() as workdir:
        for commit, subject in commits:
            for path in changed_c_files(args.repo, commit):
                old, new = changed_lines(args.repo, commit, path)
                before, free_before = alerts_of(args.repo, f"{commit}^", path, workdir)
                after, _ = alerts_of(args.repo, commit, path, workdir)
                if before is None or after is None:  # the file is new or removed by the commit
                    continue
                near_before = [a for a in before if near(a["line"], old, args.window) or near(a["free_line"], old, args.window)]
                near_after = [a for a in after if near(a["line"], new, args.window) or near(a["free_line"], new, args.window)]
                totals["files"] += 1
                totals["before"] += bool(near_before)
                totals["gone"] += bool(near_before) and not near_after
                totals["alerts_before"] += len(before)
                totals["alerts_after"] += len(after)
                totals["free_total"] += len(free_before)
                totals["free_near"] += sum(near(line, old, args.window) for line in free_before)
                print(f"{commit[:9]} {path}: alerts in file before/after {len(before)}/{len(after)}, near the fix before/after "
                      f"{len(near_before)}/{len(near_after)}  | {subject[:70]}")
                for a in near_before[:3]:
                    print(f"      before: line {a['line']} (free at {a['free_line']}) [{a['kind']}] {a['detail'][:80]}")
    n = totals["files"]
    print(f"\nfiles compared: {n}")
    print(f"alert near the fix before the fix: {totals['before']}/{n}; and none near it after the fix: {totals['gone']}/{n}")
    print(f"alerts in those files: {totals['alerts_before']} before, {totals['alerts_after']} after")
    print(f"chance: {totals['free_near']}/{totals['free_total']} of the free() lines are within {args.window} lines of the fix "
          f"({totals['free_near'] / max(totals['free_total'], 1):.0%})")


if __name__ == "__main__":
    main()
