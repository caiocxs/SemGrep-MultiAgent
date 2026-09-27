"""
Rule synthesis for one CWE: generator -> gate -> corrector loop.

1. Split the CWE's Juliet files into train/test by flow variant (split.py).
2. Pick example findings from the detector's logs on the train files.
3. The generator model writes a rule; it is extracted, normalized and linted
   (rules.py), then graded by the gate on the train files (gate.py).
4. While it fails, the corrector model gets the rule plus the feedback and
   writes a new version, up to the combo's `max_fix_attempts`.
5. The best attempt is accepted if it passes, and is always evaluated once on
   the held-out test files - the number that goes into the results.

Every attempt (prompt size, raw response, rule, gate report, timing) is
logged to logs/synthesis/<combo>/<cwe>/<run>.json.

    python -m src.pipeline.synthesize --combo A --cwe CWE-416
"""

import argparse
import json
import re
import shutil
import time
from pathlib import Path

from src.config import load_combo
from src.pipeline.findings import load_findings, number_lines, render_example, select_examples
from src.pipeline.gate import collect_files, evaluate
from src.pipeline.rules import dump_rule, forbidden_identifiers, parse_response, write_rule
from src.pipeline.split import flow_variant, split_files

PROMPTS_DIR = Path("prompts")

# Short descriptions from MITRE CWE (https://cwe.mitre.org).
CWES = {
    "CWE-401": ("Missing Release of Memory after Effective Lifetime",
                "The product does not sufficiently track and release allocated memory after it has been used, "
                "which slowly consumes remaining memory."),
    "CWE-415": ("Double Free",
                "The product calls free() twice on the same memory address, potentially leading to "
                "modification of unexpected memory locations."),
    "CWE-416": ("Use After Free",
                "The product reuses or references memory after it has been freed. At some point afterward, "
                "the memory may be allocated again and saved in another pointer, while the original pointer "
                "references a location somewhere within the new allocation."),
    "CWE-457": ("Use of Uninitialized Variable",
                "The code uses a variable that has not been initialized, leading to unpredictable or "
                "unintended results."),
    "CWE-476": ("NULL Pointer Dereference",
                "The product dereferences a pointer that it expects to be valid but is NULL."),
}


def load_docs():
    text = (PROMPTS_DIR / "semgrep_docs.md").read_text(encoding="utf-8")
    return re.sub(r"<!--.*?-->\s*", "", text, flags=re.S).strip()  # drop the sources header


def render(template, **values):
    text = (PROMPTS_DIR / f"{template}.md").read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    return text


def missed_code(report, max_files=2, max_lines=80):
    """Numbered source of the first missed vulnerable files, for the corrector."""
    if report is None or not report.missed_cases:
        return "(none)"
    blocks = []
    for case in report.missed_cases[:max_files]:
        path = Path(report.cases[case][0])
        code = path.read_text(encoding="utf-8", errors="replace")
        blocks.append(f"{path.name}:\n```c\n{number_lines(code, max_lines)}\n```")
    return "\n\n".join(blocks)


def _score(attempt):
    """Ranks attempts: valid first, then fewest false positives, then highest recall."""
    report = attempt["report"]
    if report is None or not report.valid:
        return (0, 0, 0.0)
    return (1, -len(report.false_positives), report.recall)


def synthesize(cwe, combo_name, bad_files, good_files, log_dirs, complete=None, n_examples=3,
               min_recall=0.5, test_ratio=0.3, seed=0, rules_dir=Path("rules"),
               logs_dir=Path("logs/synthesis"), max_fix_attempts=None):
    """
    Runs the loop for one CWE and returns the run log (also written to disk).
    `complete(role, prompt) -> (text, seconds)` defaults to the combo's local
    models; tests pass a fake one.
    """
    combo = load_combo(combo_name)
    if max_fix_attempts is None:
        max_fix_attempts = combo["loop"].get("max_fix_attempts", 3)
    if complete is None:
        from src.pipeline.llm import LocalLLM
        complete = LocalLLM(combo).complete

    prefix = cwe.replace("-", "")  # Juliet files start with e.g. "CWE416"
    bad = [str(f) for f in bad_files if Path(f).name.startswith(prefix)]
    good = [str(f) for f in good_files if Path(f).name.startswith(prefix)]
    train_bad, test_bad, test_variants = split_files(bad, test_ratio, seed)
    # GOOD files follow the variants drawn for BAD, so both sides of a case land together.
    test_good = [f for f in good if flow_variant(f) in test_variants]
    train_good = [f for f in good if flow_variant(f) not in test_variants]

    findings = load_findings(log_dirs, train_bad + train_good, cwe)
    examples = select_examples(findings, n_examples, seed)
    if not examples:
        raise RuntimeError(f"No {cwe} findings in {', '.join(map(str, log_dirs))} for the train files.")

    cwe_name, cwe_description = CWES[cwe]
    common = dict(CWE_ID=cwe, CWE_NAME=cwe_name, CWE_DESCRIPTION=cwe_description, SEMGREP_DOCS=load_docs())
    forbidden = forbidden_identifiers(examples)
    rule_id = f"gen-{cwe.lower()}"

    run_id = time.strftime("%Y%m%d-%H%M%S")
    candidates_dir = Path(rules_dir) / "candidates" / combo["name"] / cwe / run_id
    print(
        f"{cwe} | combo {combo['name']} | train {len(train_bad)} BAD / {len(train_good)} GOOD | "
        f"test {len(test_bad)} BAD / {len(test_good)} GOOD (variants {', '.join(test_variants)}) | "
        f"{len(findings)} findings, {len(examples)} examples\n"
    )

    prompt = render("rule_generator", **common, EXAMPLES="\n\n".join(
        render_example(f, i) for i, f in enumerate(examples, start=1)))
    role = "generator"
    attempts = []
    seen = {}  # rule text -> (attempt number, its feedback)
    for n in range(max_fix_attempts + 1):
        print(f"[{n}] {role}: prompting ({len(prompt)} chars)...")
        text, seconds = complete(role, prompt)
        yaml_text, rule_doc, problems = parse_response(text, rule_id, cwe, forbidden)

        rule_path = write_rule(rule_doc, candidates_dir / f"attempt_{n}.yaml") if rule_doc else None
        rule_text = dump_rule(rule_doc) if rule_doc else None
        report = None
        if rule_text in seen:
            # Same rule as a failed attempt: re-testing it is pointless, and small
            # models otherwise keep resubmitting it with a new explanation.
            k, previous_feedback = seen[rule_text]
            problems = [f"This is exactly the same rule as attempt {k}, which already failed. "
                        "Change the rule itself to fix the problems below."]
            feedback = f"{problems[0]}\n\n{previous_feedback}"
        elif problems:
            feedback = "The rule was rejected before testing:\n" + "\n".join(f"- {p}" for p in problems)
        else:
            report = evaluate(rule_path, train_bad, train_good)
            feedback = report.feedback()
        if rule_text and rule_text not in seen:
            seen[rule_text] = (n, feedback)

        attempts.append({"n": n, "role": role, "seconds": round(seconds, 2), "prompt_chars": len(prompt),
                         "response": text, "rule_path": str(rule_path) if rule_path else None,
                         "problems": problems, "report": report})
        status = "PASSED" if report and report.passed(min_recall) else "failed"
        summary = f"recall={report.recall:.0%} fp={len(report.false_positives)}" if report and report.valid else \
            (report.errors[0][:120] if report else problems[0][:120])
        print(f"[{n}] {status} in {seconds:.0f}s: {summary}")
        if report and report.passed(min_recall):
            break

        prompt = render("rule_corrector", **common, FEEDBACK=feedback, MISSED_CODE=missed_code(report),
                        RULE=dump_rule(rule_doc).strip() if rule_doc else (yaml_text or text).strip())
        role = "corrector"

    best = max(attempts, key=_score)
    best_report = best["report"]
    accepted = bool(best_report and best_report.passed(min_recall))
    accepted_path = None
    test_report = None
    if best_report and best_report.valid:
        test_report = evaluate(best["rule_path"], test_bad, test_good)
        if accepted:
            accepted_path = Path(rules_dir) / "accepted" / combo["name"] / f"{cwe.lower()}.yaml"
            accepted_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(best["rule_path"], accepted_path)

    run = {
        "run_id": run_id, "cwe": cwe, "combo": combo["name"], "seed": seed, "min_recall": min_recall,
        "models": {r: combo["roles"][r]["model"]["name"] for r in ("generator", "corrector")},
        "split": {"test_variants": test_variants, "train_bad": len(train_bad), "train_good": len(train_good),
                  "test_bad": len(test_bad), "test_good": len(test_good)},
        "findings": len(findings), "examples": [str(f.file) for f in examples],
        "attempts": [{**a, "report": a["report"].to_dict() if a["report"] else None} for a in attempts],
        "best_attempt": best["n"], "accepted": accepted,
        "accepted_path": str(accepted_path) if accepted_path else None,
        "test_report": test_report.to_dict() if test_report else None,
    }
    log_path = Path(logs_dir) / combo["name"] / cwe / f"{run_id}.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(run, indent=4, ensure_ascii=False), encoding="utf-8")

    print(f"\nBest attempt: {best['n']} | accepted: {accepted}" + (f" -> {accepted_path}" if accepted_path else ""))
    if test_report:
        print(f"Held-out test: recall={test_report.recall:.1%} precision={test_report.precision:.1%} "
              f"fp={len(test_report.false_positives)}")
    print(f"Run log: {log_path}")
    return run


def main():
    parser = argparse.ArgumentParser(description="Generate a Semgrep rule for one CWE with the generator/corrector loop.")
    parser.add_argument("--combo", required=True, help="Model combo (A, B, C)")
    parser.add_argument("--cwe", required=True, choices=sorted(CWES), help="Target CWE")
    parser.add_argument("--bad", nargs="+", default=["datasets/cwes_mixed/bad"], help="Vulnerable files/directories")
    parser.add_argument("--good", nargs="+", default=["datasets/cwes_mixed/good"], help="Safe files/directories")
    parser.add_argument("--logs", nargs="+",
                        default=["logs/dataset/QWEN_CODE/CWES_BAD", "logs/dataset/QWEN_CODE/CWES_GOOD"],
                        help="Detector log directories (log_<file>.json)")
    parser.add_argument("--examples", type=int, default=3, help="Findings shown to the generator")
    parser.add_argument("--min-recall", type=float, default=0.5, help="Train recall a rule needs to be accepted")
    parser.add_argument("--max-fix-attempts", type=int, default=None, help="Override the combo's corrector limit")
    parser.add_argument("--seed", type=int, default=0, help="Seed for the train/test split and example choice")
    args = parser.parse_args()

    synthesize(
        cwe=args.cwe, combo_name=args.combo,
        bad_files=collect_files(args.bad), good_files=collect_files(args.good), log_dirs=args.logs,
        n_examples=args.examples, min_recall=args.min_recall, seed=args.seed,
        max_fix_attempts=args.max_fix_attempts,
    )


if __name__ == "__main__":
    main()
