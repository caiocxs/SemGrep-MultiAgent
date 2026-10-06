# Findings so far (2026-10-05)

Status of the evidence after the runs described in [experiments.md](experiments.md) and the changes in
[changes.md](changes.md). Everything below is from one machine, local models, Semgrep OSS 1.178, Juliet CWE-416
(150 BAD / 150 GOOD files, 20 flow variants) and the source of Git (`8103b44651`, 644 `.c` files, 447 KLOC) as real-world
code assumed correct. Rules are always written by the local models; the gate is Semgrep and Python.

## What was measured

| Question | How |
|---|---|
| Does a rule work on unseen Juliet variants? | k-fold split by flow variant, held-out recall and precision per fold (mean +- sd) |
| Does a rule stay quiet on real code? | alerts per KLOC on Git files never used for the rule (train/test split by file hash), limit 0.1 |
| Does a rule find real bugs? | 16 Git commits whose subject names a use after free / double free, rule run before and after the fix |

## Cross-validation of CWE-416, template arm (5 folds, every variant tested once)

| Model | Configuration | Accepted | Test recall | Test precision | Real-world alerts/KLOC |
|---|---|---|---|---|---|
| Qwen3-4B (C) | template v1, seed 0 | 0/5 | 20.0% +- 44.7% | 23.9% (one fold) | 0.00 (rules empty or broad) |
| Qwen3-Coder-30B-A3B (D) | template v1, seed 0 | 0/5 | 89.2% +- 18.6% | 69.8% +- 19.9% | 5.11 +- 2.56 |
| D | template v1 + warning, seed 2 | 0/5 | 69.5% +- 23.7% | 87.4% +- 19.0% | 2.78 +- 2.02 |
| D | final (template v2 + warning + `not` feedback), seed 0 | 0/5 | 85.7% +- 17.5% | 81.2% +- 25.8% | 3.83 +- 2.50 |

Reference: the official Semgrep packs (`p/c`, `p/default`, `p/cwe-top-25`, `p/security-audit`) reach recall 0% on the seed-0
random 30% test split of CWE-416 (not measured fold by fold). Seed 1 of the final configuration has one finished fold (recall 85.7%, precision 100%, 1.86/KLOC);
seed 2 of it was never run. The numbers in different rows use different seeds and so different folds and real-world files:
they are not paired.

## Findings

1. **A 30B local model, given a strategy (state change of a variable), writes rules that generalize across Juliet flow
   variants** (mean recall 70-89% over folds), with mean precision 70-87%. The 4B model does not (mean recall 20%: one fold at
   100% with 204 false positives, four with rules that match nothing). The single "first accepted rule" of 2026-09-29 (recall
   48.8%, precision 100%) is at the low end of what the same model produces (per-fold recall 44-100%).
2. **No rule satisfies both gates.** The rules with 0-6 Juliet false positives raised 1.0 or more alerts per KLOC on Git (median
   about 2) against a limit of 0.1; the only rules under the limit (0.04 and 0.07 alerts/KLOC) had 266 and 354 Juliet false
   positives. The rule accepted on Juliet raises 2.1 and none of 40 sampled alerts was a real bug. Zero false positives on
   Juliet does not predict behaviour on real code.
3. **The dominant defect is structural and the models can say it but not write it.** About 80% of the alerts of the best rules
   are on the `free()` statement that marks the variable: the use patterns also match it. The corrector, told so, writes
   the right idea (`"not": ["free($P)"]`) in a form that cannot work in Semgrep (`pattern-not` only excludes a match equal to
   the pattern; the use is the argument inside the call). A hand-made probe with `pattern-not-inside: free(...)` cut the alerts
   from 2.21 to 0.40 per KLOC with the same recall and no new Juliet false positives.
4. **Feedback that names the mistake changes what the model writes, but not enough.** With `not_inside` available and a message
   saying that its `not` has no effect, the model wrote a `not_inside` in 21 of 42 attempts (0 of 7 in the run before that message), usually
   with `free($P)`, which repeats the metavariable and only excludes the same variable. The lowest real-world rate reached was
   1.04 alerts/KLOC. The next message would be the rule itself, so it was not added.
5. **The two kinds of false positive move independently.** Rules with recall 100% and hundreds of Juliet false positives raise
   0.0-0.1 alerts/KLOC on Git, and rules with 0 Juliet false positives raise 2 or more. A gate with only one of them accepts
   rules that the other rejects.
6. **The rules are not better than chance at real fixes.** On 16 Git fix commits (use after free, double free), 5 had an alert
   within 10 lines of the fixed lines before the fix (31%), against 36% for any line with `free()` in those files.
7. **Nothing was accepted by the gate that includes real-world code.** Every run with it used the template format, models C and
   D, CWE-416 (and CWE-415, recall 0% for both models). The earlier yaml and spec runs predate that gate and were not accepted
   either; the one rule accepted before it (template, D, 2026-09-29) fails it.

## Threats to validity and limits

- **One CWE with enough data (416), 20 variants, 4-6 per test group;** CWE-415 is a negative result with a template made for 416.
- **Seeds:** the seed-0 cross-validation exists for four configurations, other seeds for two (one complete). Spread over folds
  (+-18 to +-45 points of recall) is large; differences of a few points between configurations are not conclusions.
- **Template arm:** the strategy (event, uses, resets as taint by side effect) was written by us; it is the knowledge being
  tested and the results must be reported apart from the yaml/spec arms. Template v2, the source-line warning and the `not`
  message are generic feedback aids (changes.md phases 12-14); the last one is close to giving the rule.
- **Real-world code is assumed correct**; a real bug there counts as a false positive. The 40-alert triage was done by reading
  about 12 lines of context, not by running code. Alert counts of one rule vary 1-2% between runs.
- **Fix-commit check:** 16 commits, one file each, window of 10 lines, the same line numbers before and after the fix; the
  commit filter was adjusted after seeing the first output (changes.md and experiments.md say how).
- **Juliet recall** counts a match anywhere in a BAD file of a case as a detection, so it can overstate detection of cases split
  across files (variants 63/64).
- **Models and machine:** 4B and 30B (IQ4_XS, partial GPU offload) on a GTX 1060; the 30B runs depend on free RAM (runs were
  stopped by the system three times); no other model families were tried; one run of each model call is deterministic
  (temperature 0) except where `--samples` was used.

## Not done

Critic and merge agents; the other CWEs (401, 457, 476); a second model family; CVE-fix evaluation beyond the 16 Git commits;
interprocedural flows (Semgrep OSS); the final configuration for seeds 1 and 2 (it can be run with
`python -m src.pipeline.crossval --combo D --cwe CWE-416 --folds 5 --seed N --format template --max-fix-attempts 6 --negatives ../git`).
