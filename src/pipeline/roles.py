"""
The roles around the generator -> gate -> corrector loop, as small pure helpers so that
`synthesize` only orchestrates:

- history   what the corrector remembers of the earlier attempts (it kept returning the same rule);
- critic    prompt pieces for an agent that explains *why* a tested rule fails, for the corrector;
- merger    which two tested rules to combine (different strengths), and how the task is worded;
- examples  other ways to show the generator the weakness than the detector's findings:
            pairs of a vulnerable file and its safe counterpart, or nothing at all.

Nothing here decides whether a rule works: that stays with the gate (Semgrep and Python, no LLM).
Every rule a role produces goes through the gate like any other attempt.
"""

import random
from pathlib import Path

from src.pipeline.findings import number_lines
from src.pipeline.split import flow_variant

NO_EXAMPLES_NOTE = "(No examples are provided: write the rule from the description of the weakness alone.)"
PAIRS_INTRO = ("The examples below are pairs of the same test case: a vulnerable version and its safe version. "
               "What differs between the two is what the rule has to tell apart.")


# --------------------------------------------------------------------------- history
def attempt_summary(attempt):
    """One line on what an attempt was and how it fared, from the data the loop already keeps."""
    report, problems = attempt.get("report"), attempt.get("problems") or []
    if report is not None and report.valid:
        text = f"recall {report.recall:.0%}, {len(report.false_positives)} false positives on the Juliet files"
        if report.negative_lines:
            text += f", {len(report.negative_matches)} alerts on real code ({report.negative_rate:.2f} per KLOC)"
        return text
    if report is not None:
        return "Semgrep rejected the rule: " + (report.errors[0] if report.errors else "")[:110]
    if problems and problems[0].startswith("This is exactly the same rule"):
        return "the same rule as an earlier attempt"
    return "rejected before testing: " + (problems[0] if problems else "no rule")[:110]


def history_block(attempts, limit=6):
    """
    The earlier attempts, oldest first, for the corrector prompt ("" when there are none, so that the
    prompt stays as it was). `attempts` are the ones before the current rule, which the prompt shows anyway.
    """
    shown = attempts[-limit:]
    if not shown:
        return ""
    lines = [f"- attempt {a['n']}: {attempt_summary(a)}" for a in shown]
    return "### Earlier attempts (oldest first)\n\n" + "\n".join(lines) + "\n\nDo not go back to a rule that already failed.\n"


# --------------------------------------------------------------------------- guard
def regression_note(attempt, base):
    """
    Told to the corrector when its change scored worse than the rule it was editing. Like KNighter's refinement, which
    accepts a change only if the checker stays valid and loses its false positives, a correction that does not improve
    on the best rule so far is not built upon: the corrector goes back to that rule.
    """
    return (f"Your last change (attempt {attempt['n']}) made the rule worse and was discarded: "
            f"{attempt_summary(attempt)}. The rule below is attempt {base['n']} ({attempt_summary(base)}), "
            "which is the best one so far. Change a different part of it.")


# --------------------------------------------------------------------------- critic
def with_review(feedback, review):
    """The corrector's feedback plus the critic's review, which is presented as fallible."""
    review = (review or "").strip()
    if not review:
        return feedback
    return (f"{feedback}\n\nReview of the rule by another agent (it can be wrong; the test result above is what counts):\n"
            f"{review}")


# --------------------------------------------------------------------------- merger
def _alerts(attempt):
    report = attempt["report"]
    return len(report.false_positives) + len(report.negative_matches)


def _signature(attempt):
    report = attempt["report"]
    return (round(report.recall, 4), len(report.false_positives), len(report.negative_matches), tuple(report.detected_cases))


def select_merge_pair(attempts, score):
    """
    Two tested rules whose strengths differ: A is the best attempt by `score`; B is a rule with a different behaviour
    that does something better than A (it raises fewer alerts, else it detects more). Among the quieter ones B is the
    quietest; among the stronger ones it is the one that detects the most. None when no rule has anything A lacks.
    """
    usable = [a for a in attempts if a.get("report") is not None and a["report"].valid and a["report"].detected_cases]
    if len(usable) < 2:
        return None
    best = max(usable, key=score)
    others = [a for a in usable if _signature(a) != _signature(best)]  # same numbers mean the same behaviour
    quieter = [a for a in others if _alerts(a) < _alerts(best)]
    stronger = [a for a in others if a["report"].recall > best["report"].recall]
    if quieter:
        return best, min(quieter, key=lambda a: (_alerts(a), -a["report"].recall))
    if stronger:
        return best, max(stronger, key=lambda a: a["report"].recall)
    return None


def merge_feedback(a, b):
    """The merger's task, as the `feedback` of a corrector prompt whose current rule is A."""
    return (
        "MERGE TASK. Two candidate rules for this weakness were tested. The current rule below is rule A; rule B is shown here.\n"
        f"- rule A: {attempt_summary(a)}\n"
        f"- rule B: {attempt_summary(b)}\n"
        "Write ONE rule that keeps what each of them does well: it should detect as many cases as the better detector "
        "and raise as few false alerts as the quieter rule, on the Juliet files and on real code.\n\n"
        "Rule B:\n"
        f"```\n{b.get('rule_source', '').strip()}\n```"
    )


# --------------------------------------------------------------------------- examples
def _safe_counterpart(bad_path, good_files):
    """`..._07_bad.c` -> the `..._07_good.c` among the safe files, or None."""
    name = Path(bad_path).name
    if "_bad" not in name:
        return None
    head, tail = name.rsplit("_bad", 1)
    wanted = head + "_good" + tail
    return next((g for g in good_files if Path(g).name == wanted), None)


def select_pairs(bad_files, good_files, n=2, seed=0):
    """
    Up to n (vulnerable, safe) file pairs, each from a different flow variant, deterministic for a given seed.
    Unlike the detector's findings these come from the dataset's labels.
    """
    by_variant = {}
    for f in sorted(map(str, bad_files)):
        by_variant.setdefault(flow_variant(f), []).append(f)
    variants = sorted(by_variant)
    random.Random(seed).shuffle(variants)
    pairs = []
    for variant in variants:
        for bad in by_variant[variant]:
            good = _safe_counterpart(bad, good_files)
            if good:
                pairs.append((bad, str(good)))
                break
        if len(pairs) == n:
            break
    return pairs


def render_pair(bad, good, index, max_lines=60):
    def block(path):
        code = Path(path).read_text(encoding="utf-8", errors="replace")
        return f"```c\n{number_lines(code, max_lines)}\n```"
    return (f"#### Example {index}\n\nVulnerable version (`{Path(bad).name}`):\n{block(bad)}\n\n"
            f"Safe version (`{Path(good).name}`):\n{block(good)}")
