"""
The graph arm on the benchmarks of Li et al. (arXiv 2601.19239), so that the comparison with RepoAudit, KNighter, CodeQL and Semgrep is on
one benchmark. The protocol is in docs/graph_progress.md ("Protocol: direct comparison ...", written before the first measurement).

    # A. known vulnerabilities of the Linux kernel (recall): one line per case, "<CWE> <fix commit>"
    python -m src.graph.paper_benchmark cases --cases cases.txt --repo ../linux-cases --out results.json [--window 10]

    # B. a project (reports and a sample to read): every k-th alert in path and line order
    python -m src.graph.paper_benchmark project --root ../linux-6093/sound --query memory_leak [--sample 10] [--out alerts.json]

The queries are not changed here: this file only calls them.
"""

import argparse
import concurrent.futures
import json
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

from src.graph import extract, paths
from src.graph.fixcommits import HUNK, near

QUERIES = {"CWE-401": ("memory_leak", paths.memory_leak), "CWE-416": ("use_after_free", paths.use_after_free),
           "CWE-476": ("null_dereference", paths.null_dereference), "CWE-476-check": ("check_after_deref", paths.check_after_deref)}
MAX_SIBLINGS = 400  # .c files of a directory kept as context for the names the code teaches the extractor


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout.decode("utf-8", errors="replace")


def run_query(cwe, files, headers):
    name, query = QUERIES[cwe]
    conn, failed = extract.build(files, headers=headers)
    if name == "memory_leak":
        extract.prepare_leaks(conn)
        sites = conn.execute(paths.ALLOC_SITES_SQL.replace("SELECT a.event_id, a.callee", "SELECT count(*)")).fetchone()[0]
    else:
        sites = None
    frees = conn.execute("SELECT count(*) FROM events WHERE kind = 'free'").fetchone()[0]
    run_query.coverage = {"free_events": frees, "allocation_sites": sites}  # the coverage diagnostic of the arm: 0 means blind, not clean
    return query(conn), failed


RAW = "https://raw.githubusercontent.com/torvalds/linux/{sha}/{path}"


def fetch_file(sha, path, dest):
    """One file of the kernel at a commit, from the raw-content server (a sparse checkout of the whole tree is slow on this machine)."""
    target = dest / path
    if target.exists():
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(RAW.format(sha=sha, path=path), timeout=60) as response:
                target.write_bytes(response.read())
            return target
        except (urllib.error.URLError, TimeoutError):
            time.sleep(2 * (attempt + 1))
    raise OSError(f"could not fetch {path} at {sha}")


def changed_ranges(old_file, new_file):
    """(old ranges, new ranges) of the hunks between two local copies, as (first, last); `git diff --no-index` needs no objects of the repository."""
    diff = subprocess.run(["git", "diff", "--no-index", "-U0", "--no-color", str(old_file), str(new_file)], capture_output=True).stdout
    old, new = [], []
    for a, b, c, d in HUNK.findall(diff.decode("utf-8", errors="replace")):
        count_old, count_new = int(b) if b != "" else 1, int(d) if d != "" else 1
        old.append((int(a), int(a) + max(count_old, 1) - 1))
        new.append((int(c), int(c) + max(count_new, 1) - 1))
    return old, new


def materialize(repo, rev, directories, changed, cache):
    """Directory with the .c and .h files of `directories` (not recursive) and the changed files, at `rev`."""
    sha = git(repo, "rev-parse", rev).strip()
    dest = Path(cache) / sha
    wanted = set(changed)
    for d in sorted(directories):
        names = git(repo, "ls-tree", "--name-only", f"{sha}:{d}").splitlines()
        wanted |= {f"{d}/{n}" for n in names if n.endswith(".h")}
        wanted |= {f"{d}/{n}" for n in [n for n in names if n.endswith(".c")][:MAX_SIBLINGS]}
    with concurrent.futures.ThreadPoolExecutor(16) as pool:
        list(pool.map(lambda f: fetch_file(sha, f, dest), sorted(wanted)))
    return dest, wanted


def case_alerts(repo, cwe, rev, changed, directories, cache):
    root, wanted = materialize(repo, rev, directories, changed, cache)
    files = sorted(root / f for f in wanted if f.endswith(".c"))
    headers = sorted(root / f for f in wanted if f.endswith(".h"))
    alerts, failed = run_query(cwe, files, headers)
    for a in alerts:
        a["path"] = Path(a["path"]).relative_to(root).as_posix()
    return alerts, len(files)


def evaluate_case(repo, cwe, commit, window, cache):
    changed = [f for f in git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit).splitlines() if f.endswith(".c")]
    result = {"cwe": cwe, "commit": commit, "c_files": changed}
    if not changed:
        result["status"] = "no C file changed"
        return result
    directories = {str(Path(f).parent).replace("\\", "/") for f in changed}
    parent, fixed = git(repo, "rev-parse", f"{commit}^").strip(), commit
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        before = list(pool.map(lambda f: fetch_file(parent, f, Path(cache) / parent), changed))
        after = list(pool.map(lambda f: fetch_file(fixed, f, Path(cache) / fixed), changed))
    ranges = {f: changed_ranges(b, a) for f, b, a in zip(changed, before, after)}
    old = {f: r[0] for f, r in ranges.items()}
    new = {f: r[1] for f, r in ranges.items()}
    alerts, n_files = case_alerts(repo, cwe, f"{commit}^", changed, directories, cache)
    in_changed = [a for a in alerts if a["path"] in old]
    near_hunk, exact = [], []
    for a in in_changed:
        ranges = old[a["path"]]
        if near(a["line"], ranges, window) or near(a["free_line"], ranges, window):
            near_hunk.append(a)
        if near(a["line"], ranges, 0) or near(a["free_line"], ranges, 0):
            exact.append(a)
    result.update(status="ok", coverage=dict(run_query.coverage), files_built=n_files, alerts_total=len(alerts), alerts_in_changed_files=len(in_changed),
                  near=len(near_hunk), exact=len(exact), noise=len(in_changed) - len(near_hunk),
                  examples=[{"file": a["path"], "line": a["line"], "origin": a["free_line"], "var": a["var"]} for a in near_hunk[:3]])
    if near_hunk:  # fix-sensitive: the alerts near the hunk are gone in the fixed version
        after, _ = case_alerts(repo, cwe, commit, changed, directories, cache)
        result["gone_after_fix"] = not any(
            b["path"] == a["path"] and (near(b["line"], new[a["path"]], window) or near(b["free_line"], new[a["path"]], window))
            for a in near_hunk for b in after)
    return result


def cmd_cases(args):
    cases = [line.split() for line in Path(args.cases).read_text().splitlines() if line.strip()]
    if args.only:
        cases = [c for c in cases if c[0] == args.only]
    results = []
    for cwe, commit in cases:
        started = time.time()
        if cwe not in QUERIES:
            results.append({"cwe": cwe, "commit": commit, "status": "no query for this CWE"})
            continue
        try:
            result = evaluate_case(args.repo, cwe, commit, args.window, args.cache)
        except Exception as error:  # a case that cannot be read is reported, not dropped
            result = {"cwe": cwe, "commit": commit, "status": f"error: {type(error).__name__}: {error}"}
        result["seconds"] = round(time.time() - started, 1)
        results.append(result)
        print(cwe, commit[:10], result.get("status"), "near", result.get("near"), "exact", result.get("exact"),
              "noise", result.get("noise"), f"{result['seconds']}s", flush=True)
        Path(args.out).write_text(json.dumps(results, indent=1), encoding="utf-8")
    for cwe in sorted({r["cwe"] for r in results}):
        rs = [r for r in results if r["cwe"] == cwe]
        ok = [r for r in rs if r.get("status") == "ok"]
        print(f"{cwe}: {len(rs)} cases, {len(ok)} analysed, near {sum(bool(r['near']) for r in ok)}, exact {sum(bool(r['exact']) for r in ok)}, "
              f"file-level {sum(bool(r['alerts_in_changed_files']) for r in ok)}, fix-sensitive {sum(bool(r.get('gone_after_fix')) for r in ok)}")


def cmd_project(args):
    from src.pipeline.gate import collect_files
    root = Path(args.root)
    cwe = {"memory_leak": "CWE-401", "use_after_free": "CWE-416", "null_dereference": "CWE-476", "check_after_deref": "CWE-476-check"}[args.query]
    files = collect_files([str(root)])
    headers = sorted(root.rglob("*.h"))
    started = time.time()
    alerts, failed = run_query(cwe, files, headers)
    alerts.sort(key=lambda a: (a["path"], a["line"]))
    step = max(len(alerts) // args.sample, 1) if alerts else 1
    sample = alerts[::step][:args.sample]
    print(f"{root}: {len(files)} files, {len(alerts)} alerts ({args.query}), {len(failed)} files failed, {time.time() - started:.0f}s")
    print("coverage:", run_query.coverage)
    if args.out:
        Path(args.out).write_text(json.dumps({"alerts": len(alerts), "files": len(files), "sample": sample}, indent=1, default=str), encoding="utf-8")
    for a in sample:
        print(a["path"], a["free_line"], a["line"], a["function"], a["var"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    cases = sub.add_parser("cases")
    cases.add_argument("--cases", required=True)
    cases.add_argument("--repo", required=True)
    cases.add_argument("--out", required=True)
    cases.add_argument("--window", type=int, default=10)
    cases.add_argument("--cache", default="../linux-cases-files")
    cases.add_argument("--only")
    project = sub.add_parser("project")
    project.add_argument("--root", required=True)
    project.add_argument("--query", choices=("memory_leak", "use_after_free", "null_dereference", "check_after_deref"), required=True)
    project.add_argument("--sample", type=int, default=10)
    project.add_argument("--out")
    args = parser.parse_args()
    {"cases": cmd_cases, "project": cmd_project}[args.cmd](args)


if __name__ == "__main__":
    main()
