"""
Loads the detector's findings (logs written by agents.code_agent, one
`log_<file stem>.json` per analyzed file) and picks the examples shown to the
rule generator.

Findings come from BAD and GOOD files alike: the detector doesn't know which
is which, so its false positives on safe code reach the generator too, as
they would on a real repository.
"""

import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from src.pipeline.split import flow_variant

CWE_RE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def normalize_cwe(text):
    m = CWE_RE.search(text) if isinstance(text, str) else None
    return f"CWE-{m.group(1)}" if m else None


@dataclass
class Finding:
    file: Path
    cwe: str
    pointer: str = ""
    description: str = ""
    source_line: int | None = None
    violation_line: int | None = None
    path: list = field(default_factory=list)


def load_findings(log_dirs, source_files, cwe):
    """Findings for `cwe` whose log matches one of source_files (by file stem)."""
    by_stem = {Path(f).stem: Path(f) for f in source_files}
    findings = []
    for log_dir in map(Path, log_dirs):
        for log in sorted(log_dir.glob("log_*.json")):
            source = by_stem.get(log.stem[len("log_"):])
            if source is None:
                continue
            try:
                data = json.loads(log.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict) or "error" in data:
                continue
            for f in data.get("findings") or []:
                if not isinstance(f, dict) or normalize_cwe(f.get("cwe")) != cwe:
                    continue
                findings.append(Finding(
                    file=source,
                    cwe=cwe,
                    pointer=str(f.get("pointer") or ""),
                    description=str(f.get("description") or ""),
                    source_line=f.get("source_line") if isinstance(f.get("source_line"), int) else None,
                    violation_line=f.get("violation_line") if isinstance(f.get("violation_line"), int) else None,
                    path=f.get("path") if isinstance(f.get("path"), list) else [],
                ))
    return findings


def select_examples(findings, n=3, seed=0):
    """
    Picks up to n findings from different files, each from a different flow
    variant (control-flow shape) and, while possible, a different test-case
    family (what is allocated/used), so the generator sees varied code instead
    of n copies of the same shape. Deterministic for a given seed.
    """
    rng = random.Random(seed)
    by_file = {}
    for f in findings:
        by_file.setdefault(f.file, f)  # first finding per file
    candidates = sorted(by_file.values(), key=lambda f: str(f.file))
    rng.shuffle(candidates)

    picked, variants, families = [], set(), set()
    for require_new_family in (True, False):
        for f in candidates:
            if len(picked) == n:
                return picked
            if f in picked or flow_variant(f.file) in variants:
                continue
            if require_new_family and family(f.file) in families:
                continue
            picked.append(f)
            variants.add(flow_variant(f.file))
            families.add(family(f.file))
    return picked


def family(path) -> str:
    """`CWE416_..._malloc_free_int_07_bad.c` -> `CWE416_..._malloc_free_int`."""
    return re.sub(r"_\d+[a-z]?_(?:bad|good)$", "", Path(path).stem)


def number_lines(code, max_lines=None):
    lines = code.splitlines()
    shown = lines[:max_lines] if max_lines else lines
    text = "\n".join(f"L{i}| {line}" for i, line in enumerate(shown, start=1))
    if max_lines and len(lines) > max_lines:
        text += f"\n... ({len(lines) - max_lines} more lines)"
    return text


def render_example(finding, index, max_lines=80):
    code = finding.file.read_text(encoding="utf-8", errors="replace")
    report = [f"- pointer: {finding.pointer}" if finding.pointer else None]
    if finding.source_line or finding.violation_line:
        report.append(f"- source line: {finding.source_line}, violation line: {finding.violation_line}")
    if finding.description:
        report.append(f"- description: {finding.description}")
    report = "\n".join(r for r in report if r)
    return (
        f"#### Example {index}\n\n"
        f"Analyzer report:\n{report}\n\n"
        f"```c\n{number_lines(code, max_lines)}\n```"
    )
