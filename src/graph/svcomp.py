"""
The graph arm on SV-COMP memory-safety tasks (sv-benchmarks): programs with an expected verdict decided by verifiers. A `true` program has no memory
violation on any execution, so every alert on it is a false alert. The protocol is in docs/graph_progress.md ("Protocol: false positives on SV-COMP ...").

    python -m src.graph.svcomp --root ../sv-benchmarks/c --out results.json [--limit N]

One row per task (a .yml), the five queries run on the graph of its input files. The queries are not changed here.
"""

import argparse
import json
import time
from pathlib import Path

import yaml

from src.graph import extract, paths

DIRECTORIES = ("memsafety memsafety-ext memsafety-ext2 memsafety-ext3 memsafety-cve memsafety-bftpd memsafety-broom ldv-memsafety "
               "list-ext-properties list-ext2-properties list-ext3-properties list-properties heap-manipulation forester-heap ddv-machzwd "
               "list-simple ldv-regression ldv-sets heap-data memory-alloca").split()
QUERIES = {"null_dereference": paths.null_dereference, "use_after_free": paths.use_after_free, "double_free": paths.double_free,
           "memory_leak": paths.memory_leak, "check_after_deref": paths.check_after_deref}


def load_tasks(root):
    tasks = []
    for directory in DIRECTORIES:
        for yml in sorted((Path(root) / directory).glob("*.yml")):
            spec = yaml.safe_load(yml.read_text(encoding="utf-8"))
            files = spec["input_files"] if isinstance(spec["input_files"], list) else [spec["input_files"]]
            properties = {}
            for prop in spec.get("properties", []):
                name = Path(prop["property_file"]).name
                if name.startswith("valid-"):
                    properties[name] = {"verdict": prop.get("expected_verdict"), "subproperty": prop.get("subproperty")}
            if properties:
                tasks.append({"task": f"{directory}/{yml.name}", "files": [str(yml.parent / f) for f in files], "properties": properties})
    return tasks


def run_task(task):
    files = [Path(f) for f in task["files"]]
    conn, failed = extract.build(files)
    extract.prepare_leaks(conn)
    result = {"failed": [f for f, _ in failed]}
    for name, query in QUERIES.items():
        alerts = query(conn)
        result[name] = {"alerts": len(alerts), "examples": [{"line": a["line"], "origin": a["free_line"], "var": a["var"], "function": a["function"]}
                                                           for a in alerts[:3]]}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    tasks = load_tasks(args.root)
    if args.limit:
        tasks = tasks[:args.limit]
    rows = []
    for i, task in enumerate(tasks, 1):
        started = time.time()
        try:
            task["result"] = run_task(task)
        except Exception as error:  # a task that cannot be read is reported, not dropped
            task["result"] = {"error": f"{type(error).__name__}: {error}"}
        task["seconds"] = round(time.time() - started, 2)
        rows.append(task)
        if i % 25 == 0:
            print(i, "of", len(tasks), flush=True)
            Path(args.out).write_text(json.dumps(rows), encoding="utf-8")
    Path(args.out).write_text(json.dumps(rows), encoding="utf-8")
    print("done", len(rows), "tasks")


if __name__ == "__main__":
    main()
