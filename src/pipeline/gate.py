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

Optionally the rule is also run over real-world C files (`negative_files`, e.g.
a mature open-source repository). That code is assumed correct, so every match
there is an alert the rule should not raise; the report keeps them apart from
the Juliet false positives and measures them as alerts per KLOC (1000 lines).
Juliet code is too uniform to show how a rule behaves on code with wrappers,
macros and cleanup functions.

    python -m src.pipeline.gate --rule rules/accepted/<rule>.yaml \\
        --bad datasets/cwes_mixed/bad --good datasets/cwes_mixed/good --filter "CWE416*" \\
        [--negatives ../git --max-negative-rate 0.1]
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

FUNCTION_RULE = Path(__file__).with_name("function_def.yaml")
FUNCTION_RULE_ID = "gate-internal-function-def"
# `--timeout 30`: with the default (5 s per rule and file) Semgrep silently skips the files that take longer,
# which on large real-world C files depends on the machine's load and made the alert count vary between runs.
SEMGREP_ARGS = ["scan", "--json", "--metrics=off", "--disable-version-check", "--quiet", "--timeout", "30"]
# Windows caps a command line at 32767 chars; many target paths are split
# into several semgrep calls below that.
MAX_TARGET_CHARS = 24000
MAX_LOGGED_NEGATIVES = 50  # alerts on real code kept in the JSON report (the count is always exact)
SNIPPET_BEFORE, SNIPPET_AFTER, SNIPPET_MAX_WIDTH = 8, 2, 160

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
    negative_matches: list[Match] = field(default_factory=list)  # alerts on real-world code, assumed correct
    negative_lines: int = 0  # lines of the real-world files that were scanned
    max_negative_rate: float | None = None  # alerts per KLOC a passing rule may raise; None = not enforced
    negative_on_source: int = 0  # of the real-world alerts, those on a line its own source patterns also match
    ineffective_nots: list[str] = field(default_factory=list)  # sink `pattern-not`s equal to a source pattern

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

    @property
    def negative_rate(self):
        """Alerts on real-world code per 1000 lines."""
        return len(self.negative_matches) / (self.negative_lines / 1000) if self.negative_lines else 0.0

    def passed(self, min_recall=0.0):
        """Valid, no false positive, detects a case, reaches min_recall and stays under the real-code alert limit."""
        return (
            self.valid
            and not self.false_positives
            and bool(self.detected_cases)
            and self.recall >= min_recall
            and (self.max_negative_rate is None or self.negative_rate <= self.max_negative_rate)
        )

    def matches_line(self, path, line):
        """Whether the rule fired on path:line - used to check a rule catches the finding it came from."""
        key = _key(path)
        return any(
            _key(m.path) == key and m.line == line
            for m in self.true_positives + self.false_positives + self.neutral
        )

    def feedback(self, max_items=5, max_snippets=3):
        """
        Plain-text summary for the corrector agent: what is broken and what to
        change. The first `max_snippets` false positives of each kind come with
        the code around them, since one line says little about why it is safe.
        """
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
            for i, (code, ms) in enumerate(ranked[:max_items]):
                m = ms[0]
                where = f" in {m.function}()" if m.function else ""
                times = f" (and {len(ms) - 1} more like it)" if len(ms) > 1 else ""
                lines.append(f"- {Path(m.path).name}:{m.line}{where}: `{code}`{times}")
                if i < max_snippets and (snippet := _snippet(m.path, m.line)):
                    lines.append(snippet)
            _more(lines, ranked, max_items)
        if self.negative_matches:
            lines += self._negative_feedback(max_snippets)
        if self.passed():
            lines.append("No false positives.")
        return "\n".join(lines)

    def _negative_feedback(self, max_files):
        """Alerts on real-world code: the rate, then one example per file, the files with most alerts first."""
        by_file = defaultdict(list)
        for m in self.negative_matches:
            by_file[m.path].append(m)
        ranked = sorted(by_file.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        limit = f", at most {self.max_negative_rate:g} allowed" if self.max_negative_rate is not None else ""
        count = len(self.negative_matches)
        lines = [f"Alerts on real-world C code, which is assumed correct: {count} alert{'s' if count != 1 else ''} in "
                 f"{self.negative_lines / 1000:.1f} KLOC ({self.negative_rate:.2f} per KLOC{limit}). "
                 "The rule must NOT match code like this:"]
        if self.negative_on_source:
            lines.insert(1, f"{self.negative_on_source} of these {count} alerts ({self.negative_on_source / count:.0%}) are "
                            "on a line that one of the rule's own source patterns also matches: the alert is raised on the "
                            "statement that marks the variable. A sink must not match the statement that marks the variable.")
            for pattern in self.ineffective_nots[:3]:
                lines.insert(2, f"Your `not` of `{pattern}` on the uses does not remove them: a `not` (Semgrep `pattern-not`) "
                                "only excludes a match that is exactly that pattern, and a use is usually just part of a "
                                "statement (for instance the argument of a call). `not_inside` (Semgrep `pattern-not-inside`) "
                                "excludes the uses that sit anywhere inside code matching it.")
        shown = 0
        for path, ms in ranked[:max_files]:
            m = ms[0]
            where = f" in {m.function}()" if m.function else ""
            more = f" (and {len(ms) - 1} more in this file)" if len(ms) > 1 else ""
            lines.append(f"- {Path(path).name}:{m.line}{where}: `{m.code}`{more}")
            if snippet := _snippet(path, m.line):
                lines.append(snippet)
            shown += len(ms)
        if len(ranked) > max_files:
            lines.append(f"- ... and {len(self.negative_matches) - shown} more alerts in {len(ranked) - max_files} other files")
        return lines

    def to_dict(self):
        data = asdict(self)
        data["negative_matches"] = data["negative_matches"][:MAX_LOGGED_NEGATIVES]
        data.update(
            negative_alerts=len(self.negative_matches),
            negative_rate=round(self.negative_rate, 4),
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


def _neutral_cwd():
    """
    A working directory for Semgrep that is not inside a git repository. The home
    directory, not the temp directory: on Windows an empty directory under
    AppData/Local/Temp made the same scan ten times slower (30 s against 3 s;
    the reason was not investigated).
    """
    home = Path.home()
    return str(home) if home.is_dir() else None


def _snippet(path, line, before=SNIPPET_BEFORE, after=SNIPPET_AFTER):
    """Fenced C code around `line` (marked with `>`), or "" if the file cannot be read."""
    try:
        source = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not 1 <= line <= len(source):
        return ""
    first, last = max(1, line - before), min(len(source), line + after)
    body = "\n".join(
        f"{'>' if n == line else ' '} {n}| {source[n - 1].expandtabs(4).rstrip()[:SNIPPET_MAX_WIDTH]}"
        for n in range(first, last + 1)
    )
    return f"```c\n{body}\n```"


def _source_patterns(rule_path):
    """The pattern strings under `pattern-sources` of the taint rules in a file (empty for other kinds of rule)."""
    try:
        doc = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pattern" and isinstance(value, str):
                    found.append(value)
                elif not key.startswith(("pattern-not", "metavariable", "focus")):
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for rule in doc.get("rules", []) if isinstance(doc, dict) else []:
        if isinstance(rule, dict):
            walk(rule.get("pattern-sources"))
    return list(dict.fromkeys(found))


def _sink_nots_equal_to_sources(rule_path):
    """Sink `pattern-not` strings that are also a source pattern: the usual attempt to keep a sink off the source statement."""
    try:
        doc = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    sources = set(_source_patterns(rule_path))
    found = []

    def walk(node):
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "pattern-not" and isinstance(value, str) and value in sources:
                    found.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for rule in doc.get("rules", []) if isinstance(doc, dict) else []:
        if isinstance(rule, dict):
            walk(rule.get("pattern-sinks"))
    return sorted(set(found))


def _alerts_on_source_lines(rule_path, matches, timeout=600):
    """
    How many of `matches` sit on a line that the rule's own source patterns also match. Such an
    alert is raised on the statement that marks the variable (e.g. a sink pattern generic enough
    to match the source call itself), a structural defect that one alert line does not reveal.
    """
    patterns = _source_patterns(rule_path)
    if not patterns or not matches:
        return 0
    probe = {"rules": [{"id": "gate-internal-source-probe", "languages": ["c"], "severity": "INFO",
                        "message": "source", "pattern-either": [{"pattern": p} for p in patterns]}]}
    with tempfile.TemporaryDirectory() as tmp:
        probe_path = Path(tmp) / "probe.yaml"
        probe_path.write_text(yaml.safe_dump(probe), encoding="utf-8")
        try:
            data = run_semgrep(probe_path, sorted({m.path for m in matches}), timeout=timeout, with_functions=False)
        except RuntimeError:
            return 0
    source_lines = {(_key(r["path"]), line)
                    for r in data["results"] for line in range(r["start"]["line"], r["end"]["line"] + 1)}
    return sum((_key(m.path), m.line) in source_lines for m in matches)


def _count_lines(files):
    total = 0
    for f in files:
        with open(f, "rb") as handle:
            total += sum(1 for _ in handle)
    return total


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


def run_semgrep(rule_path, targets, timeout=600, with_functions=True):
    """
    Runs the candidate rule plus the internal function-definition rule in a
    single scan per chunk of targets, and merges the JSON outputs. The function
    rule is what makes grading by function name possible, but it costs about ten
    times the candidate rule on large files, so real-world code skips it.

    Semgrep runs from the user's home directory with absolute paths: when the
    working directory is inside a git repository, Semgrep asks git about every
    target file (about 0.5 s each on Windows), which made 450 files take 250 s
    instead of 25 s. Results come back with the absolute paths.
    """
    exe = shutil.which("semgrep")
    if exe is None:
        raise RuntimeError("semgrep not found on PATH (install it with: pipx install semgrep)")

    merged = {"results": [], "errors": []}
    configs = ["--config", os.path.abspath(rule_path)]
    if with_functions:
        configs += ["--config", str(FUNCTION_RULE)]
    for chunk in _chunks([os.path.abspath(t) for t in targets]):
        cmd = [exe, *SEMGREP_ARGS, *configs, *chunk]
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", timeout=timeout,
                              cwd=_neutral_cwd())
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


def evaluate(rule_path, bad_files, good_files=(), timeout=600, negative_files=(), max_negative_rate=None):
    """
    Runs rule_path over the BAD and GOOD files and grades every match. Matches
    in `negative_files` (real-world code assumed correct) are collected apart;
    `max_negative_rate` is the number of such alerts per KLOC a passing rule may raise.
    """
    bad_files = [str(p) for p in bad_files]
    good_files = [str(p) for p in good_files]
    negative_files = [str(p) for p in negative_files]

    cases = defaultdict(list)
    for f in bad_files:
        cases[case_id(f)].append(f)
    report = GateReport(rule_path=str(rule_path), cases=dict(cases), max_negative_rate=max_negative_rate)

    data = run_semgrep(rule_path, bad_files + good_files, timeout=timeout) if bad_files + good_files \
        else {"results": [], "errors": []}
    if negative_files and not _rule_errors(data["errors"]):
        real = run_semgrep(rule_path, negative_files, timeout=timeout, with_functions=False)
        data = {"results": data["results"] + real["results"], "errors": data["errors"] + real["errors"]}
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
    negative_keys = {_key(f) for f in negative_files}
    report.negative_lines = _count_lines(negative_files)
    line_cache = {}
    for key, (path, line, rule_id) in raw_matches.items():
        function = _enclosing_function(functions[key[0]], line)
        match = Match(path, line, rule_id.rsplit(".", 1)[-1], function, _line_text(path, line, line_cache))
        if key[0] in negative_keys:
            report.negative_matches.append(match)
            continue
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

    for matches in (report.true_positives, report.false_positives, report.neutral, report.negative_matches):
        matches.sort(key=lambda m: (m.path, m.line))
    report.negative_on_source = _alerts_on_source_lines(rule_path, report.negative_matches, timeout=timeout)
    if report.negative_on_source:
        report.ineffective_nots = _sink_nots_equal_to_sources(rule_path)
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
    parser.add_argument("--negatives", default=None,
                        help="Directory of real-world C code assumed correct; every match is an alert")
    parser.add_argument("--max-negative-rate", type=float, default=None,
                        help="Alerts per KLOC on --negatives a passing rule may raise (default: not enforced)")
    parser.add_argument("--json", default=None, help="Also write the full report to this JSON file")
    parser.add_argument("--max-items", type=int, default=10, help="Items listed per section of the feedback")
    args = parser.parse_args()

    bad = collect_files(args.bad, args.filter)
    good = collect_files(args.good, args.filter)
    negatives = collect_files([args.negatives]) if args.negatives else []
    print(f"Evaluating {args.rule} on {len(bad)} BAD / {len(good)} GOOD / {len(negatives)} real-world files...\n")

    report = evaluate(args.rule, bad, good, negative_files=negatives, max_negative_rate=args.max_negative_rate)
    print(report.feedback(max_items=args.max_items))
    if report.valid:
        print(
            f"\nrecall={report.recall:.1%} precision={report.precision:.1%} "
            f"tp={len(report.true_positives)} fp={len(report.false_positives)} "
            f"neutral={len(report.neutral)} passed={report.passed()}"
            + (f" real-world alerts={len(report.negative_matches)} ({report.negative_rate:.2f}/KLOC)" if negatives else "")
        )

    if args.json:
        Path(args.json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=4, ensure_ascii=False), encoding="utf-8")
        print(f"Report written to {args.json}")


if __name__ == "__main__":
    main()
