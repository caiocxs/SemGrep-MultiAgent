"""
The graph analyzer as the detector of the rule synthesis: writes its alerts in the layout the generator already reads (`log_<file stem>.json`, one per
Juliet file, with a `findings` list), so that `synthesize --example-mode graph` can show the model real alerts of a deterministic analysis and ask for a
Semgrep rule that catches situations like them. The graph arm itself writes no rule; the model does, and the gate decides.

    python -m src.graph.export_findings --cwe CWE-416 [--out logs/graph/cwe_416]
"""

import argparse
import json
from pathlib import Path

from src.graph import extract, paths
from src.pipeline.gate import collect_files

QUERIES = {"CWE-416": "use_after_free", "CWE-415": "double_free", "CWE-401": "memory_leak", "CWE-476": "null_dereference"}

DESCRIPTIONS = {
    "use_after_free": "The pointer '{var}' is released at line {a} and used at line {b}, on a path along which it is not given a new value.",
    "double_free": "The pointer '{var}' is released at line {a} and released again at line {b}, on a path along which it is not given a new value.",
    "memory_leak": "The memory allocated at line {a} and held by '{var}' is neither released, nor handed on, nor returned before the function ends at line {b}.",
    "null_dereference": "The pointer '{var}' is NULL at line {a} (assigned NULL or known NULL on that branch) and is dereferenced at line {b} with no new value and no non-NULL test in between.",
}


def default_out(cwe):
    return Path("logs/graph") / cwe.lower().replace("-", "_")


def write_logs(alerts, query, files, out):
    """One log per file in `files` (an empty `findings` list when the analysis found nothing there). Returns the number of findings written."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    by_file = {}
    for a in alerts:
        by_file.setdefault(str(a["path"]), []).append(a)
    total = 0
    for f in files:
        lines = Path(f).read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")
        findings = []
        for a in by_file.get(str(f), []):
            origin, hit = a["free_line"], a["line"]
            code = lambda n: lines[n - 1].strip() if 0 < n <= len(lines) else ""
            findings.append({
                "cwe": next(c for c, q in QUERIES.items() if q == query),
                "pointer": a["var"],
                "source_line": origin, "source_code": code(origin),
                "violation_line": hit, "violation_code": code(hit),
                "path": [f"L{origin}: {code(origin)}", f"L{hit}: {code(hit)}"],
                "description": DESCRIPTIONS[query].format(var=a["var"], a=origin, b=hit),
            })
        total += len(findings)
        (out / f"log_{Path(f).stem}.json").write_text(
            json.dumps({"analysis": "event-graph analysis (deterministic, no language model)", "findings": findings,
                        "vulnerable": bool(findings)}, indent=1), encoding="utf-8")
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cwe", required=True, choices=sorted(QUERIES))
    parser.add_argument("--bad", nargs="+", default=["datasets/cwes_mixed/bad"])
    parser.add_argument("--good", nargs="+", default=["datasets/cwes_mixed/good"])
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    query = QUERIES[args.cwe]
    prefix = args.cwe.replace("-", "")
    files = [f for f in collect_files(args.bad + args.good) if f.name.startswith(prefix)]
    conn, failed = extract.build(files)
    if query == "memory_leak":
        extract.prepare_leaks(conn)
    alerts = getattr(paths, query)(conn)
    out = args.out or default_out(args.cwe)
    total = write_logs(alerts, query, files, out)
    print(f"{args.cwe}: {len(files)} files, {total} findings of {query} written to {out}" + (f", {len(failed)} files failed" if failed else ""))


if __name__ == "__main__":
    main()
