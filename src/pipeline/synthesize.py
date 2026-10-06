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

With `negatives` (a directory of real-world C code, e.g. a mature open-source
repository) the gate also counts the alerts the rule raises on it, split into
train and test files like the Juliet ones, and a passing rule must stay under
`max_negative_rate` alerts per KLOC on the train side.

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
from src.pipeline.spec import parse_response as parse_spec_response
from src.pipeline.spec import parse_template_response
from src.pipeline.split import flow_variant, fold_split, split_files, split_negatives

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


def load_pattern_docs():
    """Only the pattern-syntax section of the docs: the spec format has no YAML for the model to write."""
    text = load_docs()
    start, end = text.index("## Pattern syntax"), text.index("## Taint mode")
    return text[start:end].strip()


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


def _f1(report):
    """F1 of case recall and precision, where alerts on real-world code count as false positives."""
    true_positives = len(report.true_positives)
    graded = true_positives + len(report.false_positives) + len(report.negative_matches)
    precision = true_positives / graded if graded else 0.0
    total = precision + report.recall
    return 2 * precision * report.recall / total if total else 0.0


def _score(attempt):
    """
    Ranks attempts: valid rules first; among them the ones that passed the gate, then
    the ones that detect at least one case, then the best F1 and the fewest alerts.
    A valid rule that matches nothing has no false positives either, so ranking by
    false positives first used to let it beat every rule that detected something.
    """
    report = attempt["report"]
    if report is None or not report.valid:
        return (0, 0, 0, 0.0, 0)
    alerts = len(report.false_positives) + len(report.negative_matches)
    return (1, int(attempt.get("passed", False)), int(bool(report.detected_cases)), _f1(report), -alerts)


def synthesize(cwe, combo_name, bad_files, good_files, log_dirs, complete=None, n_examples=3,
               min_recall=0.5, test_ratio=0.3, seed=0, rules_dir=Path("rules"),
               logs_dir=Path("logs/synthesis"), max_fix_attempts=None, output_format="yaml",
               samples=1, temperature=None, stop_on_pass=False,
               negatives=None, max_negative_rate=0.1, max_negative_files=None, fold=None, folds=None):
    """
    Runs the loop for one CWE and returns the run log (also written to disk).
    `complete(role, prompt) -> (text, seconds)` defaults to the combo's local
    models; tests pass a fake one. `output_format` is "yaml" (the model writes
    the rule), "spec" (the model writes a JSON of patterns) or "template" (the
    model fills in a predefined state-change strategy), see spec.py.

    `samples` > 1 runs that many independent generator -> corrector loops
    (best-of-N): the models sample with `temperature` (default 0.7 when
    sampling; `complete` is then called with a `temperature` keyword) and the
    gate, on the train files only, picks the best attempt among all of them.
    `stop_on_pass` ends the sampling at the first sample that passes.

    `negatives` is a directory of real-world C code assumed correct: its files
    are split like the Juliet ones (`split_negatives`), the gate counts the
    alerts on the train side (at most `max_negative_rate` per KLOC to pass,
    `max_negative_files` bounds how many files every gate run scans) and the
    test side is only scanned for the final report.

    `folds`/`fold` replace the random `test_ratio` split by one group of a k-fold split by
    flow variant (see `split.fold_split`), so that runs over all folds cover every variant.
    """
    if samples < 1:
        raise ValueError("samples must be at least 1")
    formats = {
        "yaml": ("rule_generator", "rule_corrector", parse_response),
        "spec": ("spec_generator", "spec_corrector", parse_spec_response),
        "template": ("template_generator", "template_corrector", parse_template_response),
    }
    if output_format not in formats:
        raise ValueError(f"Unknown output format: {output_format}")
    spec_mode = output_format != "yaml"  # the model answers in JSON, not YAML
    generator_template, corrector_template, parse = formats[output_format]
    combo = load_combo(combo_name)
    if max_fix_attempts is None:
        max_fix_attempts = combo["loop"].get("max_fix_attempts", 3)
    if complete is None:
        from src.pipeline.llm import LocalLLM
        complete = LocalLLM(combo).complete

    prefix = cwe.replace("-", "")  # Juliet files start with e.g. "CWE416"
    bad = [str(f) for f in bad_files if Path(f).name.startswith(prefix)]
    good = [str(f) for f in good_files if Path(f).name.startswith(prefix)]
    if folds:
        if fold is None:
            raise ValueError("fold is required when folds is given")
        train_bad, test_bad, test_variants = fold_split(bad, folds, fold, seed)
    else:
        train_bad, test_bad, test_variants = split_files(bad, test_ratio, seed)
    # GOOD files follow the variants drawn for BAD, so both sides of a case land together.
    test_good = [f for f in good if flow_variant(f) in test_variants]
    train_good = [f for f in good if flow_variant(f) not in test_variants]
    train_neg, test_neg = [], []
    if negatives:
        train_neg, test_neg = split_negatives(collect_files([negatives]), negatives, test_ratio, seed,
                                              max_train=max_negative_files)
        if not train_neg:
            raise RuntimeError(f"No C files for the train side in {negatives}.")
    rate_limit = max_negative_rate if negatives else None

    findings = load_findings(log_dirs, train_bad + train_good, cwe)
    examples = select_examples(findings, n_examples, seed)
    if not examples:
        raise RuntimeError(f"No {cwe} findings in {', '.join(map(str, log_dirs))} for the train files.")

    cwe_name, cwe_description = CWES[cwe]
    common = dict(CWE_ID=cwe, CWE_NAME=cwe_name, CWE_DESCRIPTION=cwe_description)
    common["PATTERN_DOCS" if spec_mode else "SEMGREP_DOCS"] = load_pattern_docs() if spec_mode else load_docs()
    forbidden = forbidden_identifiers(examples)
    rule_id = f"gen-{cwe.lower()}"

    run_id = time.strftime("%Y%m%d-%H%M%S")
    candidates_dir = Path(rules_dir) / "candidates" / combo["name"] / cwe / run_id
    print(
        f"{cwe} | combo {combo['name']}" + (f" | fold {fold + 1}/{folds}" if folds else "") + f" | train {len(train_bad)} BAD / {len(train_good)} GOOD | "
        f"test {len(test_bad)} BAD / {len(test_good)} GOOD (variants {', '.join(test_variants)}) | "
        f"{len(findings)} findings, {len(examples)} examples"
        + (f" | real-world code: train {len(train_neg)} / test {len(test_neg)} files" if negatives else "") + "\n"
    )

    first_prompt = render(generator_template, **common, EXAMPLES="\n\n".join(
        render_example(f, i) for i, f in enumerate(examples, start=1)))
    if samples > 1 and temperature is None:
        temperature = 0.7  # identical samples would be pointless
    call = complete if temperature is None else (lambda r, pr: complete(r, pr, temperature=temperature))

    def run_sample(k):
        """One independent generator -> gate -> corrector loop; returns its attempts."""
        prompt, role = first_prompt, "generator"
        attempts = []
        seen = {}  # rule text -> (attempt number, its feedback)
        for n in range(max_fix_attempts + 1):
            print(f"[{n}] {role}: prompting ({len(prompt)} chars)...")
            text, seconds = call(role, prompt)
            yaml_text, rule_doc, problems = parse(text, rule_id, cwe, forbidden)

            file_name = f"attempt_{n}.yaml" if samples == 1 else f"sample{k}_attempt_{n}.yaml"
            rule_path = write_rule(rule_doc, candidates_dir / file_name) if rule_doc else None
            rule_text = dump_rule(rule_doc) if rule_doc else None
            report = None
            if rule_text in seen:
                # Same rule as a failed attempt: re-testing it is pointless, and small
                # models otherwise keep resubmitting it with a new explanation.
                previous_n, previous_feedback = seen[rule_text]
                problems = [f"This is exactly the same rule as attempt {previous_n}, which already failed. "
                            "Change the rule itself to fix the problems below."]
                feedback = f"{problems[0]}\n\n{previous_feedback}"
            elif problems:
                feedback = "The rule was rejected before testing:\n" + "\n".join(f"- {p}" for p in problems)
            else:
                report = evaluate(rule_path, train_bad, train_good, negative_files=train_neg,
                                  max_negative_rate=rate_limit)
                feedback = report.feedback()
            if rule_text and rule_text not in seen:
                seen[rule_text] = (n, feedback)

            ok = bool(report and report.passed(min_recall))
            attempts.append({"sample": k, "n": n, "role": role, "seconds": round(seconds, 2), "prompt_chars": len(prompt),
                             "response": text, "rule_path": str(rule_path) if rule_path else None,
                             "problems": problems, "passed": ok, "report": report})
            status = "PASSED" if ok else "failed"
            summary = f"recall={report.recall:.0%} fp={len(report.false_positives)}" if report and report.valid else \
                (report.errors[0][:120] if report else problems[0][:120])
            if report and report.valid and negatives:
                summary += f" real-world={len(report.negative_matches)} ({report.negative_rate:.2f}/KLOC)"
            print(f"[{n}] {status} in {seconds:.0f}s: {summary}")
            if ok:
                break

            current = yaml_text if spec_mode else (dump_rule(rule_doc) if rule_doc else yaml_text)
            prompt = render(corrector_template, **common, FEEDBACK=feedback, MISSED_CODE=missed_code(report),
                            RULE=(current or text).strip())
            role = "corrector"

        return attempts

    attempts, sample_summary = [], []
    for k in range(samples):
        if samples > 1:
            print(f"--- sample {k + 1}/{samples} (temperature {temperature}) ---")
        sample_attempts = run_sample(k)
        attempts += sample_attempts
        best_of_sample = max(sample_attempts, key=_score)
        passed = best_of_sample["passed"]
        sample_summary.append({"sample": k, "attempts": len(sample_attempts), "passed": passed,
                               "best_attempt": best_of_sample["n"]})
        if passed and stop_on_pass:
            break

    best = max(attempts, key=_score)
    best_report = best["report"]
    accepted = best["passed"]
    accepted_path = None
    test_report = None
    if best_report and best_report.valid:
        test_report = evaluate(best["rule_path"], test_bad, test_good, negative_files=test_neg,
                               max_negative_rate=rate_limit)
        if accepted:
            accepted_path = Path(rules_dir) / "accepted" / combo["name"] / f"{cwe.lower()}.yaml"
            accepted_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(best["rule_path"], accepted_path)

    run = {
        "run_id": run_id, "cwe": cwe, "combo": combo["name"], "seed": seed, "format": output_format, "min_recall": min_recall,
        "fold": fold, "folds": folds,
        "models": {r: combo["roles"][r]["model"]["name"] for r in ("generator", "corrector")},
        "split": {"test_variants": test_variants, "train_bad": len(train_bad), "train_good": len(train_good),
                  "test_bad": len(test_bad), "test_good": len(test_good)},
        "negatives": {"root": str(negatives), "train_files": len(train_neg), "test_files": len(test_neg),
                      "max_rate": rate_limit} if negatives else None,
        "findings": len(findings), "examples": [str(f.file) for f in examples],
        "attempts": [{**a, "report": a["report"].to_dict() if a["report"] else None} for a in attempts],
        "samples": samples, "temperature": temperature, "sample_summary": sample_summary,
        "samples_passed": sum(s["passed"] for s in sample_summary),
        "best_sample": best["sample"], "best_attempt": best["n"], "accepted": accepted,
        "accepted_path": str(accepted_path) if accepted_path else None,
        "test_report": test_report.to_dict() if test_report else None,
    }
    log_path = Path(logs_dir) / combo["name"] / cwe / f"{run_id}.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(json.dumps(run, indent=4, ensure_ascii=False), encoding="utf-8")

    if samples > 1:
        print(f"\nSamples passing the gate: {run['samples_passed']}/{len(sample_summary)}")
    where = f"sample {best['sample']}, attempt {best['n']}" if samples > 1 else f"attempt {best['n']}"
    print(f"\nBest: {where} | accepted: {accepted}" + (f" -> {accepted_path}" if accepted_path else ""))
    if test_report:
        print(f"Held-out test: recall={test_report.recall:.1%} precision={test_report.precision:.1%} "
              f"fp={len(test_report.false_positives)}"
              + (f" real-world alerts={len(test_report.negative_matches)} ({test_report.negative_rate:.2f}/KLOC)"
                 if negatives else ""))
    print(f"Run log: {log_path}")
    return run


def main():
    parser = argparse.ArgumentParser(description="Generate a Semgrep rule for one CWE with the generator/corrector loop.")
    parser.add_argument("--combo", required=True, help="Model combo (A, B, C, D)")
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
    parser.add_argument("--folds", type=int, default=None,
                        help="Use a k-fold split by flow variant instead of a random test ratio (needs --fold)")
    parser.add_argument("--fold", type=int, default=None, help="Which fold is the test side (0-based)")
    parser.add_argument("--rules-dir", default="rules",
                        help="Where candidates/ and accepted/ are written (rules/accepted/ is versioned: "
                             "use another directory for experiments that must not overwrite it)")
    parser.add_argument("--format", choices=("yaml", "spec", "template"), default="yaml",
                        help="yaml: the model writes the rule; spec: the model writes a JSON of patterns; "
                             "template: the model fills in a predefined strategy (patterns only)")
    parser.add_argument("--samples", type=int, default=1,
                        help="Independent generator/corrector loops (best-of-N); the gate picks the best on train")
    parser.add_argument("--temperature", type=float, default=None,
                        help="Sampling temperature for generator and corrector (default: the combo's; 0.7 if --samples > 1)")
    parser.add_argument("--stop-on-pass", action="store_true", help="Stop sampling at the first sample that passes")
    parser.add_argument("--negatives", default=None,
                        help="Directory of real-world C code assumed correct (e.g. a clone of a mature project); "
                             "alerts on it count against the rule")
    parser.add_argument("--max-negative-rate", type=float, default=0.1,
                        help="Alerts per KLOC on the train side of --negatives a passing rule may raise")
    parser.add_argument("--negatives-max-files", type=int, default=None,
                        help="Scan at most this many train files of --negatives per gate run (bounds the time)")
    args = parser.parse_args()

    synthesize(
        cwe=args.cwe, combo_name=args.combo,
        bad_files=collect_files(args.bad), good_files=collect_files(args.good), log_dirs=args.logs,
        n_examples=args.examples, min_recall=args.min_recall, seed=args.seed,
        max_fix_attempts=args.max_fix_attempts, output_format=args.format,
        samples=args.samples, temperature=args.temperature, stop_on_pass=args.stop_on_pass,
        negatives=args.negatives, max_negative_rate=args.max_negative_rate,
        max_negative_files=args.negatives_max_files, fold=args.fold, folds=args.folds,
        rules_dir=Path(args.rules_dir),
    )


if __name__ == "__main__":
    main()
