"""
Analyzes logs under <root>/<MODEL>/<DATASET>/log_*.json and reports, per
model: average processing time, bad/good detection accuracy, how many
findings (problems) are reported on average, and whether the vulnerability
actually found matches the one the file is supposed to contain.

Ground truth for the vulnerable/safe verdict comes from the dataset
directory name: a name containing "BAD" expects vulnerable=true, a name
containing "GOOD" expects vulnerable=false. The specific CWE a "bad" file
is supposed to trigger is read from its own filename (Juliet-style, e.g.
"CWE401_Memory_Leak__..._bad.c" -> CWE-401) and compared against the
"cwe" field of each reported finding - so a model that says "vulnerable"
but names the wrong CWE is not counted as a true positive for that CWE.

Logs that never recovered valid JSON (still have an "error" key - see
reformat_logs.py) are counted in the timing average but excluded from
every other metric, since there's no verdict to grade.

Writes two reports (in addition to the console summary):
- summary.txt: the same per-model/dataset aggregate as printed to console.
- details.csv: one row per log file - expected/predicted verdict, whether
  it was correct, how many findings were reported, and whether the
  expected CWE was among them - so individual right/wrong files can be
  inspected or filtered.
"""

import argparse
import csv
import json
import os
import re
from collections import Counter
from pathlib import Path

CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def classify_dataset(dataset_name: str):
    name = dataset_name.upper()
    is_bad = "BAD" in name
    is_good = "GOOD" in name
    if is_bad and not is_good:
        return True
    if is_good and not is_bad:
        return False
    return None  # ambiguous or unrelated folder name, skip grading


def extract_cwe(text):
    if not isinstance(text, str):
        return None
    m = CWE_RE.search(text)
    return f"CWE-{m.group(1)}" if m else None


def new_bucket():
    return {
        "total": 0, "parse_failed": 0,
        "correct": 0, "incorrect": 0, "ungraded": 0,
        "total_time": 0.0, "timed_count": 0,
        "total_findings": 0, "findings_n": 0,
        "cwe_correct": 0, "cwe_eligible": 0,
    }


def analyze(root: Path):
    models = {}
    records = []
    # model -> dataset -> {"correct": Counter, "wrong": Counter} of found CWE occurrences.
    # "correct" = the found CWE matches the one this specific file is supposed to have
    # (only possible on BAD files); "wrong" = every other found CWE, including all
    # findings on GOOD files (which have no real vulnerability to match).
    cwe_counts = {}

    for log_path in sorted(root.rglob("log_*.json")):
        parts = log_path.relative_to(root).parts
        if len(parts) < 3:
            continue
        model, dataset = parts[0], parts[1]

        try:
            data = json.loads(log_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue

        d = models.setdefault(model, {}).setdefault(dataset, new_bucket())
        d["total"] += 1

        exec_time = data.get("execution_time_in_seconds")
        if isinstance(exec_time, (int, float)):
            d["total_time"] += exec_time
            d["timed_count"] += 1

        expected = classify_dataset(dataset)
        expected_cwe = extract_cwe(log_path.name)

        if "error" in data and "raw_response" in data:
            d["parse_failed"] += 1
            records.append({
                "model": model, "dataset": dataset, "file": log_path.name,
                "expected": expected, "predicted": None, "result": "parse_failed",
                "expected_cwe": expected_cwe, "found_cwes": "", "num_findings": "",
                "cwe_match": "", "execution_time_in_seconds": exec_time,
            })
            continue

        findings = data.get("findings")
        findings = findings if isinstance(findings, list) else []
        found_cwes = [extract_cwe(f.get("cwe")) for f in findings if isinstance(f, dict)]
        found_cwes = [c for c in found_cwes if c]
        num_findings = len(findings)
        d["total_findings"] += num_findings
        d["findings_n"] += 1

        buckets = cwe_counts.setdefault(model, {}).setdefault(
            dataset, {"correct": Counter(), "wrong": Counter()}
        )
        for cwe in found_cwes:
            bucket_name = "correct" if (expected is True and cwe == expected_cwe) else "wrong"
            buckets[bucket_name][cwe] += 1

        vulnerable = data.get("vulnerable")

        cwe_match = None
        if expected is True and expected_cwe is not None:
            cwe_match = expected_cwe in found_cwes
            d["cwe_eligible"] += 1
            if cwe_match:
                d["cwe_correct"] += 1

        if expected is None or not isinstance(vulnerable, bool):
            d["ungraded"] += 1
            result = "ungraded"
        elif vulnerable == expected:
            d["correct"] += 1
            result = "correct"
        else:
            d["incorrect"] += 1
            result = "incorrect"

        records.append({
            "model": model, "dataset": dataset, "file": log_path.name,
            "expected": expected, "predicted": vulnerable, "result": result,
            "expected_cwe": expected_cwe, "found_cwes": ";".join(found_cwes),
            "num_findings": num_findings, "cwe_match": cwe_match,
            "execution_time_in_seconds": exec_time,
        })

    return models, records, cwe_counts


def _pct(part, total):
    return f"{(100 * part / total):.1f}%" if total else "n/a"


def _dataset_line(dataset, d):
    avg_time = d["total_time"] / d["timed_count"] if d["timed_count"] else 0.0
    avg_findings = d["total_findings"] / d["findings_n"] if d["findings_n"] else 0.0
    graded = d["correct"] + d["incorrect"]

    line = (
        f"  {dataset}: total={d['total']} parse_failed={d['parse_failed']} "
        f"ungraded={d['ungraded']} accuracy={d['correct']}/{graded} "
        f"({_pct(d['correct'], graded)}) avg_time={avg_time:.2f}s "
        f"avg_findings={avg_findings:.2f}"
    )
    if d["cwe_eligible"]:
        line += (
            f" cwe_accuracy={d['cwe_correct']}/{d['cwe_eligible']} "
            f"({_pct(d['cwe_correct'], d['cwe_eligible'])})"
        )
    return line


def _cwe_breakdown_line(label, counter: Counter):
    if not counter:
        return f"    {label}: (none)"
    parts = ", ".join(f"{cwe}={n}" for cwe, n in counter.most_common())
    return f"    {label}: {parts}"


def build_summary_lines(models, cwe_counts):
    lines = []
    for model in sorted(models):
        lines.append(f"\n=== {model} ===")
        totals = new_bucket()
        model_correct_totals = Counter()
        model_wrong_totals = Counter()

        for dataset in sorted(models[model]):
            d = models[model][dataset]
            lines.append(_dataset_line(dataset, d))

            buckets = cwe_counts.get(model, {}).get(dataset, {"correct": Counter(), "wrong": Counter()})
            is_bad = classify_dataset(dataset) is True
            if is_bad:
                lines.append(_cwe_breakdown_line("CWEs correctly identified (right CWE for the file)", buckets["correct"]))
                lines.append(_cwe_breakdown_line("CWEs wrongly identified (right file, wrong CWE)", buckets["wrong"]))
            else:
                lines.append(_cwe_breakdown_line("CWEs wrongly identified (all false positives - file has no vulnerability)", buckets["wrong"]))

            for key in totals:
                totals[key] += d[key]
            model_correct_totals.update(buckets["correct"])
            model_wrong_totals.update(buckets["wrong"])

        lines.append(_dataset_line("TOTAL", totals))
        lines.append(_cwe_breakdown_line("CWEs correctly identified across all datasets", model_correct_totals))
        lines.append(_cwe_breakdown_line("CWEs wrongly identified across all datasets", model_wrong_totals))

    return lines


def write_summary_report(models, cwe_counts, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(build_summary_lines(models, cwe_counts)).lstrip("\n") + "\n", encoding="utf-8")


def write_details_report(records, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "model", "dataset", "file", "expected", "predicted", "result",
                "expected_cwe", "found_cwes", "num_findings", "cwe_match",
                "execution_time_in_seconds",
            ],
        )
        writer.writeheader()
        for r in records:
            writer.writerow(r)


def main():
    parser = argparse.ArgumentParser(
        description="Report average processing time, bad/good accuracy, findings-per-file, and CWE-match accuracy per model."
    )
    parser.add_argument(
        "--root",
        default=os.environ.get("LOGS_LOCATION", "logs/dataset/"),
        help="Root directory containing <MODEL>/<DATASET>/log_*.json (default: LOGS_LOCATION env or logs/dataset/)",
    )
    parser.add_argument(
        "--report-dir",
        default="logs/reports",
        help="Directory to write summary.txt and details.csv into (default: logs/reports)",
    )
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"[!] Root not found: {root}")
        return

    models, records, cwe_counts = analyze(root)
    print("\n".join(build_summary_lines(models, cwe_counts)))

    report_dir = Path(args.report_dir)
    summary_path = report_dir / "summary.txt"
    details_path = report_dir / "details.csv"
    write_summary_report(models, cwe_counts, summary_path)
    write_details_report(records, details_path)

    print(f"\nGeneral report written to {summary_path}")
    print(f"Per-file (correct/incorrect) report written to {details_path}")


if __name__ == "__main__":
    main()
