"""
Copies the cross-validation summaries from logs/crossval/ (not versioned) to results/crossval/ (versioned), so that the
numbers behind docs/findings.md survive a lost machine. A summary is small (about 3 KB): per-fold held-out recall,
precision, false positives and real-world alert rate, with the seed, the options and the model combo.

The per-fold run logs (logs/synthesis/, 0.3 to 5 MB each, with every raw model answer) are not copied.

    python scripts/export_results.py [--source logs/crossval] [--dest results/crossval]
"""

import argparse
import json
import shutil
from pathlib import Path


def export(source, dest):
    """Copies each summary to dest/<combo>/<cwe>/<name>.json when it is new or changed. Returns the files written."""
    source, dest = Path(source), Path(dest)
    written = []
    for path in sorted(source.rglob("*.json")):
        try:
            summary = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(summary, dict) or "folds" not in summary or "seed" not in summary:
            continue
        target = dest / path.relative_to(source)
        if target.exists() and target.read_bytes() == path.read_bytes():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        written.append(target)
    return written


def main():
    parser = argparse.ArgumentParser(description="Copy the cross-validation summaries to a versioned folder.")
    parser.add_argument("--source", default="logs/crossval")
    parser.add_argument("--dest", default="results/crossval")
    args = parser.parse_args()
    written = export(args.source, args.dest)
    for path in written:
        print("copied", path)
    print(f"{len(written)} summaries copied to {args.dest}")


if __name__ == "__main__":
    main()
