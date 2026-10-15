"""
Rule generators that are not a language model writing YAML, graded by the same gate on the same folds as `crossval`
(docs/graph_progress.md, "Protocol: alternative rule generators tried in order"). No model is called here.

    repair     start from the model's own best attempt of each fold (a finished cross-validation) and apply edit operators that the gate keeps or drops
    synthesis  abstract the source and use lines of the graph's train findings into patterns and pick the uses that cover the train cases
    fixed      one spec per CWE written from what the graph query does (an upper bound for the template language, not a result of a model)

    python -m src.pipeline.rulegen --method fixed --cwe CWE-416 --seeds 1 2 --negatives ../git
"""

import argparse
import copy
import json
import re
import time
from pathlib import Path

from src.pipeline.findings import load_findings
from src.pipeline.gate import collect_files, evaluate
from src.pipeline.rules import write_rule
from src.pipeline.spec import _load_json, parse_template_response
from src.pipeline.split import fold_split, flow_variant, split_negatives

GRAPH_LOGS = Path("logs/graph")
EVENT = {"pattern": "free($P)", "variable": "$P"}
RESETS = [{"pattern": "$P = ...", "variable": "$P"}]
NOT_INSIDE = ["free($X)"]
MESSAGE = "A pointer is used after the block it points to was released."

# One spec per CWE, written from what the graph query does. The uses are the places a pointer is dereferenced, indexed or handed on.
FIXED = {
    "CWE-416": {"message": MESSAGE, "event": EVENT, "resets": RESETS,
                "uses": [{"pattern": p, "focus": "$P", "not_inside": NOT_INSIDE}
                         for p in ("$P->$F", "$P[...]", "*$P", "$F($P, ...)", "$F(..., $P)")]},
    "CWE-415": {"message": "A block is released twice.", "event": EVENT, "resets": RESETS,
                "uses": [{"pattern": "free($P)", "focus": "$P"}]},
}


# ----------------------------------------------------------------------------- data of a fold, as `synthesize` builds it
def fold_data(cwe, folds, fold, seed, negatives, bad_dirs=("datasets/cwes_mixed/bad",), good_dirs=("datasets/cwes_mixed/good",)):
    prefix = cwe.replace("-", "")
    bad = [str(f) for f in collect_files(list(bad_dirs)) if Path(f).name.startswith(prefix)]
    good = [str(f) for f in collect_files(list(good_dirs)) if Path(f).name.startswith(prefix)]
    train_bad, test_bad, test_variants = fold_split(bad, folds, fold, seed)
    data = {"train_bad": train_bad, "test_bad": test_bad, "test_variants": test_variants,
            "test_good": [f for f in good if flow_variant(f) in test_variants],
            "train_good": [f for f in good if flow_variant(f) not in test_variants], "train_neg": [], "test_neg": []}
    if negatives:
        data["train_neg"], data["test_neg"] = split_negatives(collect_files([negatives]), negatives, 0.3, seed)
    return data


def build_rule(spec, cwe, path):
    """Writes the rule of a template spec; returns (path, problems)."""
    spec_text, rule_doc, problems = parse_template_response(json.dumps(spec), f"gen-{cwe.lower()}", cwe, set())
    if rule_doc is None or problems:
        return None, problems or ["no rule"]
    path.parent.mkdir(parents=True, exist_ok=True)
    return write_rule(rule_doc, path), []


def grade(spec, cwe, data, workdir, name, side="train", negatives=True, rate=0.1):
    """The gate on the train or the test side. Returns the report, or None when the spec does not build a rule."""
    path, problems = build_rule(spec, cwe, Path(workdir) / f"{name}.yaml")
    if path is None:
        return None
    bad, good = data[f"{side}_bad"], data[f"{side}_good"]
    neg = data[f"{side}_neg"] if negatives else []
    return evaluate(path, bad, good, negative_files=neg, max_negative_rate=rate if neg else None)


def alerts(report):
    return len(report.false_positives) + len(report.negative_matches)


def passed(report, min_recall=0.5):
    return bool(report is not None and report.valid and report.passed(min_recall))


# ----------------------------------------------------------------------------- 4: the fixed spec
def method_fixed(cwe, data, workdir, **_):
    return copy.deepcopy(FIXED[cwe])


# ----------------------------------------------------------------------------- 3: synthesis from the graph's findings
def abstract(code, pointer, keep=("free",)):
    """`printLine(data);` with the pointer `data` -> `$F($P)`: the pointer becomes `$P`, a callee that is not kept becomes `$F`, literals become `...`."""
    text = code.strip().rstrip(";").strip()
    text = re.sub(r"\b" + re.escape(pointer) + r"\b", "$P", text)
    text = re.sub(r"\b(?!\$)([A-Za-z_]\w*)\s*\(", lambda m: m.group(0) if m.group(1) in keep else "$F(", text)
    text = re.sub(r'"(?:[^"\\]|\\.)*"', "...", text)
    text = re.sub(r"\b\d+\b", "...", text)
    text = re.sub(r"\[[^\]]*\]", lambda m: m.group(0) if "$P" in m.group(0) else "[...]", text)
    return text


def method_synthesis(cwe, data, workdir, log=print, max_uses=6, **_):
    logs = GRAPH_LOGS / cwe.lower().replace("-", "_")
    findings = load_findings([logs], data["train_bad"] + data["train_good"], cwe)
    raw = {}
    for f in findings:
        path = Path(f.file)
        lines = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").split("\n")
        if not (f.violation_line and f.pointer and 0 < f.violation_line <= len(lines)):
            continue
        pattern = abstract(lines[f.violation_line - 1], f.pointer)
        if "$P" in pattern:
            raw[pattern] = raw.get(pattern, 0) + 1
    candidates = [p for p, _ in sorted(raw.items(), key=lambda kv: -kv[1])][:20]
    log(f"  {len(findings)} train findings, {len(candidates)} candidate uses")
    spec = {"message": MESSAGE, "event": EVENT, "resets": RESETS, "uses": []}
    best = None
    for step in range(max_uses):
        choice = None
        for pattern in candidates:
            if any(u["pattern"] == pattern for u in spec["uses"]):
                continue
            trial = copy.deepcopy(spec)
            trial["uses"].append({"pattern": pattern, "focus": "$P", "not_inside": NOT_INSIDE})
            report = grade(trial, cwe, data, workdir, f"s{step}", negatives=False)
            if report is None or not report.valid or report.false_positives:
                continue
            score = len(report.detected_cases)
            if choice is None or score > choice[0]:
                choice = (score, trial)
        if choice is None or (best is not None and choice[0] <= best):
            break
        best, spec = choice[0], choice[1]
        log(f"  uses={len(spec['uses'])}: {best} train cases covered")
    return spec if spec["uses"] else None


# ----------------------------------------------------------------------------- 2: repair operators on the model's own attempt
def model_spec(cwe, summary_path, fold):
    """The spec of the best attempt of `fold` in a finished cross-validation summary (None when it had no rule)."""
    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
    entry = summary["folds"][fold]
    if not entry.get("has_rule"):
        return None
    run = json.loads((Path("logs/synthesis") / summary["combo"] / cwe / f"{entry['run_id']}.json").read_text(encoding="utf-8"))
    attempt = next(a for a in run["attempts"] if a["n"] == entry["best_attempt"])
    spec, _, problems = _load_json(attempt["response"])
    return spec if spec and not problems else None


def operators(spec):
    """Candidate edits of a spec, each a (name, new spec)."""
    out = []
    uses = [{"pattern": u} if isinstance(u, str) else dict(u) for u in spec.get("uses", [])]
    if uses and any("free($X)" not in (u.get("not_inside") or []) for u in uses):
        new = copy.deepcopy(spec)
        new["uses"] = [dict(u, not_inside=sorted(set((u.get("not_inside") or []) + NOT_INSIDE))) for u in uses]
        out.append(("exclude the event statement", new))
    have = {r.get("pattern") for r in spec.get("resets", [])}
    for pattern in ("$P = ...", "$P = NULL"):
        if pattern not in have:
            new = copy.deepcopy(spec)
            new["resets"] = list(spec.get("resets", [])) + [{"pattern": pattern, "variable": "$P"}]
            out.append((f"reset {pattern}", new))
    if len(uses) > 1:
        for i in range(len(uses)):
            new = copy.deepcopy(spec)
            new["uses"] = uses[:i] + uses[i + 1:]
            out.append((f"drop use {i}", new))
    return out


def method_repair(cwe, data, workdir, start=None, log=print, **_):
    if start is None:
        return None
    spec = copy.deepcopy(start)
    report = grade(spec, cwe, data, workdir, "start")
    if report is None or not report.valid:
        return spec
    for rounds in range(6):
        improved = False
        for name, trial in operators(spec):
            trial_report = grade(trial, cwe, data, workdir, f"op{rounds}")
            if trial_report is None or not trial_report.valid:
                continue
            if len(trial_report.detected_cases) >= len(report.detected_cases) and alerts(trial_report) < alerts(report):
                log(f"  kept: {name} (alerts {alerts(report)} -> {alerts(trial_report)}, cases {len(report.detected_cases)} -> {len(trial_report.detected_cases)})")
                spec, report, improved = trial, trial_report, True
        if not improved:
            break
    return spec


def method_fixed_deref(cwe, data, workdir, **_):
    """The same spec without the calls that take the pointer: chosen after the first spec gave 12 Juliet false positives and 0.19 alerts per KLOC on the train files of fold 0."""
    spec = copy.deepcopy(FIXED[cwe])
    spec["uses"] = [u for u in spec["uses"] if u["pattern"] in ("$P->$F", "$P[...]", "*$P", "free($P)")]
    return spec


METHODS = {"fixed": method_fixed, "fixed_deref": method_fixed_deref, "synthesis": method_synthesis, "repair": method_repair}


# ----------------------------------------------------------------------------- the cross-validation
def run(method, cwe, seeds, folds, negatives, starts=None, out=Path("logs/crossval/NONE"), log=print):
    results = []
    for seed in seeds:
        rows = []
        for fold in range(folds):
            data = fold_data(cwe, folds, fold, seed, negatives)
            workdir = Path("rules/rulegen") / method / cwe / f"seed{seed}_fold{fold}"
            log(f"{method} {cwe} seed {seed} fold {fold + 1}/{folds} variants {', '.join(data['test_variants'])}")
            start = model_spec(cwe, starts[seed], fold) if starts else None
            spec = METHODS[method](cwe, data, workdir, start=start, log=log)
            row = {"fold": fold, "test_variants": data["test_variants"], "has_rule": spec is not None, "accepted": False, "best_attempt": 0}
            if spec is not None:
                train = grade(spec, cwe, data, workdir, "final_train")
                test = grade(spec, cwe, data, workdir, "final_test", side="test")
                row["accepted"] = passed(train)
                if test is not None and test.valid:
                    row.update(recall=test.recall, precision=test.precision if test.false_positives or test.detected_cases else None,
                               false_positives=len(test.false_positives), real_world_rate=test.negative_rate)
                log(f"  train: recall {train.recall:.0%} fp {len(train.false_positives)} real-world {train.negative_rate:.2f}/KLOC "
                    f"accepted={row['accepted']}" if train is not None and train.valid else "  no valid rule")
                if test is not None and test.valid:
                    log(f"  test: recall {test.recall:.0%} fp {len(test.false_positives)} real-world {test.negative_rate:.2f}/KLOC")
                (workdir / "spec.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")
            rows.append(row)
        summary = {"run_id": time.strftime("%Y%m%d-%H%M%S"), "cwe": cwe, "combo": "none", "seed": seed, "format": "template",
                   "generator": method, "folds": rows, "roles": {"generator": method}}
        out_path = Path(out) / cwe
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / f"{method}_{summary['run_id']}_seed{seed}.json").write_text(json.dumps(summary, indent=1), encoding="utf-8")
        accepted = sum(r["accepted"] for r in rows)
        rec = [r["recall"] for r in rows if r.get("recall") is not None]
        rw = [r["real_world_rate"] for r in rows if r.get("real_world_rate") is not None]
        log(f"seed {seed}: accepted {accepted}/{folds} | mean recall {sum(rec) / max(len(rec), 1):.1%} | mean real-world {sum(rw) / max(len(rw), 1):.2f}/KLOC")
        results.append(summary)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--method", choices=sorted(METHODS), required=True)
    parser.add_argument("--cwe", required=True)
    parser.add_argument("--seeds", nargs="+", type=int, default=[1, 2])
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--negatives", default="../git")
    parser.add_argument("--starts", nargs="*", help="repair: the finished cross-validation summaries to start from, one per seed, in the order of --seeds")
    args = parser.parse_args()
    starts = dict(zip(args.seeds, args.starts)) if args.starts else None
    run(args.method, args.cwe, args.seeds, args.folds, args.negatives, starts=starts)


if __name__ == "__main__":
    main()
