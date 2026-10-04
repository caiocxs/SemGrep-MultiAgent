"""
Deterministic Semgrep gate (no LLM): decides whether a candidate rule is
accepted, and produces the feedback text the corrector agent receives when
it is not.

A rule is run against vulnerable (BAD) and safe (GOOD) Juliet files, and each
match is graded by the name of the function that encloses it - the usual way
SAST tools are scored on Juliet, since files mix good and bad code (e.g. a
"good" file still contains the never-called `helperBad`):

- match in a function named *good*                -> false positive
- match in a function named *bad*                 -> true positive in a BAD file, neutral in a GOOD file
- match anywhere else (helpers, file scope)        -> true positive in a BAD file, false positive in a GOOD file

Recall is counted per Juliet test case, not per file: a case split across
files (e.g. `_63a_bad.c` + `_63b_bad.c`) is detected if any of its files is.

    python -m src.pipeline.gate --rule rules/accepted/<rule>.yaml \\
        --bad datasets/cwes_mixed/bad --good datasets/cwes_mixed/good --filter "CWE416*"
"""

import argparse
import json
import os
import re
import shutil
import subprocess
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

FUNCTION_RULE = Path(__file__).with_name("function_def.yaml")
FUNCTION_RULE_ID = "gate-internal-function-def"
SEMGREP_ARGS = ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet"]
# Windows caps a command line at 32767 chars; many target paths are split
# into several semgrep calls below that.
MAX_TARGET_CHARS = 24000

_VERDICT_SUFFIX_RE = re.compile(r"_(bad|good)$")
_SPLIT_VARIANT_RE = re.compile(r"_(\d+)[a-z]$")


def case_id(path) -> str:
    """`..._63a_bad.c` and `..._63b_bad.c` -> `..._63`: one Juliet test case split across files."""
    stem = _VERDICT_SUFFIX_RE.sub("", Path(path).stem)
    return _SPLIT_VARIANT_RE.sub(r"_\1", stem)


def function_role(name):
    if not name:
        return None
    lowered = name.lower()
    if "good" in lowered:
        return "good"
    if "bad" in lowered:
        return "bad"
    return None


@dataclass
class Match:
    path: str
    line: int
    rule_id: str
    function: str | None = None
    code: str = ""


@dataclass
class GateReport:
    rule_path: str
    errors: list[str] = field(default_factory=list)
    cases: dict[str, list[str]] = field(default_factory=dict)  # vulnerable case -> its BAD files
    true_positives: list[Match] = field(default_factory=list)
    false_positives: list[Match] = field(default_factory=list)
    neutral: list[Match] = field(default_factory=list)

    @property
    def valid(self):
        return not self.errors

    @property
    def detected_cases(self):
        return sorted({case_id(m.path) for m in self.true_positives} & self.cases.keys())

    @property
    def missed_cases(self):
        detected = set(self.detected_cases)
        return sorted(c for c in self.cases if c not in detected)

    @property
    def recall(self):
        return len(self.detected_cases) / len(self.cases) if self.cases else 0.0

    @property
    def precision(self):
        graded = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / graded if graded else 0.0

    def passed(self, min_recall=0.0):
        """Valid, no false positive, detects at least one case and reaches min_recall."""
        return (
            self.valid
            and not self.false_positives
            and bool(self.detected_cases)
            and self.recall >= min_recall
        )

    def matches_line(self, path, line):
        """Whether the rule fired on path:line - used to check a rule catches the finding it came from."""
        key = _key(path)
        return any(
            _key(m.path) == key and m.line == line
            for m in self.true_positives + self.false_positives + self.neutral
        )

    def feedback(self, max_items=5):
        """Plain-text summary for the corrector agent: what is broken and what to change."""
        if not self.valid:
            lines = ["The rule is INVALID. Semgrep rejected it with:"]
            lines += [f"- {e}" for e in self.errors[:max_items]]
            lines.append("Fix the rule so Semgrep accepts it.")
            return "\n".join(lines)

        lines = [f"Detected {len(self.detected_cases)}/{len(self.cases)} vulnerable test cases ({self.recall:.0%})."]
        if self.missed_cases:
            lines.append("Missed vulnerable cases (the rule should match these):")
            for case in self.missed_cases[:max_items]:
                files = ", ".join(Path(f).name for f in self.cases[case])
                lines.append(f"- {files}")
            _more(lines, self.missed_cases, max_items)
        if self.false_positives:
            lines.append("False positives on safe code (the rule must NOT match these):")
            # Group by matched code: 100 matches of the same statement are one lesson.
            groups = {}
            for m in self.false_positives:
                groups.setdefault(m.code, []).append(m)
            ranked = sorted(groups.items(), key=lambda kv: -len(kv[1]))
            for code, ms in ranked[:max_items]:
                m = ms[0]
                where = f" in {m.function}()" if m.function else ""
                times = f" (and {len(ms) - 1} more like it)" if len(ms) > 1 else ""
                lines.append(f"- {Path(m.path).name}:{m.line}{where}: `{code}`{times}")
            _more(lines, ranked, max_items)
        if self.passed():
            lines.append("No false positives.")
        return "\n".join(lines)

    def to_dict(self):
        data = asdict(self)
        data.update(
            valid=self.valid,
            passed=self.passed(),
            recall=round(self.recall, 4),
            precision=round(self.precision, 4),
            detected_cases=self.detected_cases,
            missed_cases=self.missed_cases,
        )
        return data


def _more(lines, items, max_items):
    if len(items) > max_items:
        lines.append(f"- ... and {len(items) - max_items} more")


def _key(path):
    return os.path.normcase(os.path.abspath(path))


def _chunks(targets):
    chunk, size = [], 0
    for t in targets:
        if chunk and size + len(t) + 1 > MAX_TARGET_CHARS:
            yield chunk
            chunk, size = [], 0
        chunk.append(t)
        size += len(t) + 1
    if chunk:
        yield chunk


def run_semgrep(rule_path, targets, timeout=600):
    """
    Runs the candidate rule plus the internal function-definition rule in a
    single scan per chunk of targets, and merges the JSON outputs.
    """
    exe = shutil.which("semgrep")
    if exe is None:
        raise RuntimeError("semgrep not found on PATH (install it with: pipx install semgrep)")

    merged = {"results": [], "errors": []}
    for chunk in _chunks([str(t) for t in targets]):
        cmd = [exe, *SEMGREP_ARGS, "--config", str(rule_path), "--config", str(FUNCTION_RULE), *chunk]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=timeout)
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            raise RuntimeError(f"semgrep failed (exit {proc.returncode}): {proc.stderr.strip()[-2000:]}")
        merged["results"] += data.get("results", [])
        merged["errors"] += data.get("errors", [])
        if _rule_errors(data["errors"] if "errors" in data else []):
            break  # an invalid rule fails the same way on every chunk
    return merged


def _rule_errors(errors):
    """Errors that make the rule itself invalid (parse/schema/YAML); target-file warnings are ignored."""
    messages = []
    for e in errors:
        if e.get("level") != "error":
            continue
        msg = " ".join((e.get("long_msg") or e.get("message") or "").split())
        if msg and msg not in messages and not msg.startswith("invalid configuration file found"):
            messages.append(msg)
    return messages


def _enclosing_function(spans, line):
    inside = [(end - start, name) for start, end, name in spans if start <= line <= end]
    return min(inside)[1] if inside else None


def _line_text(path, line, cache):
    if path not in cache:
        cache[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    lines = cache[path]
    return lines[line - 1].strip() if 1 <= line <= len(lines) else ""


def evaluate(rule_path, bad_files, good_files=(), timeout=600):
    """Runs rule_path over the BAD and GOOD files and grades every match."""
    bad_files = [str(p) for p in bad_files]
    good_files = [str(p) for p in good_files]

    cases = defaultdict(list)
    for f in bad_files:
        cases[case_id(f)].append(f)
    report = GateReport(rule_path=str(rule_path), cases=dict(cases))

    data = run_semgrep(rule_path, bad_files + good_files, timeout=timeout)
    report.errors = _rule_errors(data["errors"])
    if report.errors:
        return report

    functions = defaultdict(list)
    raw_matches = {}
    for r in data["results"]:
        path, start, end = r["path"], r["start"]["line"], r["end"]["line"]
        if r["check_id"].endswith(FUNCTION_RULE_ID):
            functions[_key(path)].append((start, end, r["extra"]["message"]))
        else:
            # Taint mode can report several sinks on one line; one match per line is enough.
            raw_matches.setdefault((_key(path), start, r["check_id"]), (path, start, r["check_id"]))

    bad_keys = {_key(f) for f in bad_files}
    line_cache = {}
    for key, (path, line, rule_id) in raw_matches.items():
        function = _enclosing_function(functions[key[0]], line)
        match = Match(path, line, rule_id.rsplit(".", 1)[-1], function, _line_text(path, line, line_cache))
        role = function_role(function)
        in_bad_file = key[0] in bad_keys
        if role == "good":
            report.false_positives.append(match)
        elif in_bad_file:
            report.true_positives.append(match)
        elif role == "bad":
            report.neutral.append(match)
        else:
            report.false_positives.append(match)

    for matches in (report.true_positives, report.false_positives, report.neutral):
        matches.sort(key=lambda m: (m.path, m.line))
    return report


def collect_files(paths, pattern="*"):
    """Expands files and directories (recursively) into .c files whose name matches pattern."""
    files = []
    for p in map(Path, paths):
        candidates = sorted(p.rglob("*.c")) if p.is_dir() else [p]
        files += [f for f in candidates if f.match(pattern)]
    return files


def main():
    parser = argparse.ArgumentParser(description="Run a Semgrep rule through the gate and grade it on BAD/GOOD files.")
    parser.add_argument("--rule", required=True, help="Rule YAML file")
    parser.add_argument("--bad", nargs="+", required=True, help="Vulnerable files or directories")
    parser.add_argument("--good", nargs="*", default=[], help="Safe files or directories")
    parser.add_argument("--filter", default="*", help='Filename glob applied to --bad/--good, e.g. "CWE416*"')
    parser.add_argument("--json", default=None, help="Also write the full report to this JSON file")
    parser.add_argument("--max-items", type=int, default=10, help="Items listed per section of the feedback")
    args = parser.parse_args()

    bad = collect_files(args.bad, args.filter)
    good = collect_files(args.good, args.filter)
    print(f"Evaluating {args.rule} on {len(bad)} BAD / {len(good)} GOOD files...\n")

    report = evaluate(args.rule, bad, good)
    print(report.feedback(max_items=args.max_items))
    if report.valid:
        print(
            f"\nrecall={report.recall:.1%} precision={report.precision:.1%} "
            f"tp={len(report.true_positives)} fp={len(report.false_positives)} "
            f"neutral={len(report.neutral)} passed={report.passed()}"
        )

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=4, ensure_ascii=False), encoding="utf-8")
        print(f"Report written to {args.json}")


if __name__ == "__main__":
    main()
