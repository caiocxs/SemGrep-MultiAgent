"""
Re-parses logs that failed JSON extraction on the first pass (the
{"error": "...", "raw_response": "..."} shape written by
agents.code_agent.start_code_analysis) and, when a valid JSON object can be
recovered from the raw response, overwrites the original log file with it.

The most common failure isn't a malformed model response: it's that the
original extractor sliced from the first '{' to the *last* '}' in the text,
which breaks as soon as the model rambles on after a perfectly valid JSON
object (e.g. "...}\nAssistant: {...}" repeated). This version scans forward
bracket-by-bracket (honoring string literals) to grab just the first
complete JSON value, and falls back to closing dangling brackets when the
response was cut off mid-generation by max_tokens.
"""

import argparse
import json
import os
import re
from pathlib import Path


def extract_first_json_value(text: str):
    """
    Finds the first '{' or '[' in text and returns the parsed JSON value
    ending at its matching closing bracket. Falls back to auto-closing
    unbalanced brackets (truncated output) before giving up.
    """
    if not text or not isinstance(text, str):
        return None

    start = None
    for i, ch in enumerate(text):
        if ch in "{[":
            start = i
            break
    if start is None:
        return None

    end = _find_matching_end(text, start)
    if end is not None:
        parsed = _try_parse(text[start:end + 1])
        if parsed is not None:
            return parsed

    # Either unbalanced (truncated by max_tokens) or the balanced slice
    # still didn't parse (e.g. trailing comma) - try closing it ourselves.
    return _try_parse(_close_truncated_json(text[start:]))


def _find_matching_end(text: str, start: int):
    stack = []
    in_string = False
    escape = False

    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
        elif ch in "}]":
            if not stack:
                return None
            stack.pop()
            if not stack:
                return i
    return None


def _close_truncated_json(text: str) -> str:
    """Drops a dangling partial token and appends the brackets needed to
    balance an otherwise well-formed JSON prefix."""
    stack = []
    in_string = False
    escape = False
    last_safe_index = 0

    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
                last_safe_index = i + 1
            continue

        if ch == '"':
            in_string = True
        elif ch in "{[":
            stack.append(ch)
            last_safe_index = i + 1
        elif ch in "}]":
            if stack:
                stack.pop()
            last_safe_index = i + 1
        elif ch == ",":
            last_safe_index = i
        elif not ch.isspace():
            last_safe_index = i + 1

    trimmed = text[:last_safe_index].rstrip().rstrip(",")
    closing = "".join("}" if c == "{" else "]" for c in reversed(stack))
    return trimmed + closing


def _try_parse(candidate: str):
    try:
        return json.loads(candidate, strict=False)
    except json.JSONDecodeError:
        pass
    repaired = re.sub(r",\s*([\]}])", r"\1", candidate)
    try:
        return json.loads(repaired, strict=False)
    except json.JSONDecodeError:
        return None


def reformat_log(log_path: Path, dry_run: bool = False):
    """Returns 'fixed', 'unrecoverable', or 'skipped' (not a failure record)."""
    try:
        data = json.loads(log_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return "skipped"

    if not isinstance(data, dict) or "raw_response" not in data or "error" not in data:
        return "skipped"

    recovered = extract_first_json_value(data["raw_response"])
    if not isinstance(recovered, dict):
        return "unrecoverable"

    recovered.setdefault("execution_time_in_seconds", data.get("execution_time_in_seconds"))

    if not dry_run:
        log_path.write_text(
            json.dumps(recovered, indent=4, ensure_ascii=False), encoding="utf-8"
        )
    return "fixed"


def main():
    parser = argparse.ArgumentParser(
        description="Recover JSON from failed model-response logs and rewrite them in place."
    )
    parser.add_argument(
        "--root",
        default=os.environ.get("LOGS_LOCATION", "logs/dataset/"),
        help="Root directory to scan recursively for log_*.json files (default: LOGS_LOCATION env or logs/dataset/)",
    )
    parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing files")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        print(f"[!] Root not found: {root}")
        return

    counts = {}
    totals = {"fixed": 0, "unrecoverable": 0, "skipped": 0}

    for log_path in sorted(root.rglob("log_*.json")):
        model_dataset = log_path.relative_to(root).parts[:2]
        key = "/".join(model_dataset) if len(model_dataset) == 2 else str(root)

        result = reformat_log(log_path, dry_run=args.dry_run)
        totals[result] += 1
        bucket = counts.setdefault(key, {"fixed": 0, "unrecoverable": 0, "skipped": 0})
        bucket[result] += 1

        if result == "fixed":
            print(f"[OK] Recovered JSON: {log_path}")

    print("\n=== Summary" + (" (dry-run, no files changed)" if args.dry_run else "") + " ===")
    for key in sorted(counts):
        c = counts[key]
        touched = c["fixed"] + c["unrecoverable"]
        if touched == 0:
            continue
        print(f"{key}: fixed={c['fixed']} unrecoverable={c['unrecoverable']} (of {touched} failed logs)")

    print(
        f"\nTotal: fixed={totals['fixed']} unrecoverable={totals['unrecoverable']} "
        f"skipped={totals['skipped']} (already-valid or non-log files)"
    )


if __name__ == "__main__":
    main()
