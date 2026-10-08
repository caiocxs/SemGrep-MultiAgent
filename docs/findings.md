# Findings so far (2026-10-07)

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
| D | final, seed 1 | 0/5 | 71.4% +- 20.2% | 91.1% +- 20.0% | 2.40 +- 2.56 |
| D | final, seed 2 | 0/5 | 71.7% +- 26.3% | 87.8% +- 18.9% | 2.67 +- 2.53 |
| D | final, seed 3 | 0/5 | 94.9% +- 7.0% | 63.0% +- 28.4% | 3.56 +- 2.82 |
| D | final, seed 4 | 0/5 | 55.2% +- 36.2% (one fold without a valid rule) | 95.0% +- 10.0% (4 folds) | 1.93 +- 0.32 (4 folds) |

Pooled over the 25 folds of the final configuration (five seeds): recall 75.8% +- 25.6 (median 85.7%), precision 83.1% +- 23.1
over the 24 folds that have a rule (median 100%), 2.92 +- 2.29 real-world alerts/KLOC (median 2.14), 14 of those 24 folds with
0 Juliet false positives, 0 folds accepted. Only seed 2 is paired with another configuration (template v1 + warning, same folds and same real-world files):
recall 71.7% against 69.5%, precision 87.8% against 87.4%, 2.67 against 2.78 alerts/KLOC, all within the spread over folds.
Reference: the official Semgrep packs (`p/c`, `p/default`, `p/cwe-top-25`, `p/security-audit`) reach recall 0% on the seed-0
random 30% test split of CWE-416 (not measured fold by fold). The other rows use different seeds, so different folds and
real-world files: they are not paired.

## Findings

1. **A 30B local model, given a strategy (state change of a variable), writes rules that generalize across Juliet flow
   variants** (mean recall 76% over the 25 folds of the final configuration, between 55% and 95% by seed), with mean precision 83%. The 4B model does not (mean recall 20%: one fold at
   100% with 204 false positives, four with rules that match nothing). The single "first accepted rule" of 2026-09-29 (recall
   48.8%, precision 100%) is at the low end of what the same model produces (per-fold recall 44-100%).
2. **No rule satisfies both gates.** Most rules with 0-6 Juliet false positives raised 1.0 or more alerts per KLOC on Git (median
   about 2) against a limit of 0.1; two held-out folds were lower (0.37 and 0.105, both above the limit); the only rules under the limit (0.04, 0.07 and 0.009 alerts/KLOC) had 266, 354 and 156 Juliet false
   positives. One rule came close with no Juliet false positives (finding 8). The rule accepted on Juliet raises 2.1 and none of 40 sampled alerts was a real bug. Zero false positives on
   Juliet does not predict behaviour on real code.
3. **The dominant defect is structural and the models can say it but not write it.** About 80% of the alerts of the best rules
   are on the `free()` statement that marks the variable: the use patterns also match it. The corrector, told so, writes
   the right idea (`"not": ["free($P)"]`) in a form that cannot work in Semgrep (`pattern-not` only excludes a match equal to
   the pattern; the use is the argument inside the call). A hand-made probe with `pattern-not-inside: free(...)` cut the alerts
   from 2.21 to 0.40 per KLOC with the same recall and no new Juliet false positives.
4. **Feedback that names the mistake changes what the model writes, but rarely enough.** With `not_inside` available and a message
   saying that its `not` has no effect, 76 of 189 attempts of the final configuration (five seeds, counting the single complete run and one
   interrupted fold; 0 of 7 in the run before that message) reached the gate with a `not_inside`. Of the 56 of them that detected
   something, 55 used a pattern with the use's own metavariable (typically `free($P)`), which only excludes a use inside a `free` of the same variable
   (median 2.40 alerts/KLOC; the lowest, 0.05, is a rule with hundreds of Juliet false positives); one wrote `free($X)` with a new metavariable (finding 8). The message
   that would explain the metavariable was not added: it would be the rule itself.
5. **The two kinds of false positive move independently.** Rules with recall 100% and hundreds of Juliet false positives raise
   0.0-0.1 alerts/KLOC on Git, and rules with 0 Juliet false positives raise 2 or more. A gate with only one of them accepts
   rules that the other rejects.
6. **The rules are not better than chance at real fixes.** On 16 Git fix commits (use after free, double free), 5 had an alert
   within 10 lines of the fixed lines before the fix (31%), against 36% for any line with `free()` in those files.
7. **Nothing was accepted by the gate that includes real-world code**: 0 of 40 folds over the eight cross-validations of combos D
   and C with it, and the complete single runs. Every run with it used the template format, models C and D, CWE-416 (and
   CWE-415, recall 0% for both models). The earlier yaml and spec runs predate that gate and were not accepted either; the one
   rule accepted before it (template, D, 2026-09-29) fails it.
8. **One rule came within reach of the limit, and the model found the form by itself.** Seed 1, fold 2 (test variants 02, 03,
   15, 18), attempt 6: after five attempts at 2.1-2.4 alerts/KLOC with 84-94% of the alerts on a source line, the model wrote
   `"not_inside": ["free($X)"]` (a new metavariable) on every use. Result on the train files: recall 51%, 0 Juliet false
   positives, 38 real-world alerts (0.138/KLOC), none on a source line; not accepted because 0.138 is above 0.1. On the
   held-out test: recall 57.1%, precision 100%, 0 false positives, 13 real-world alerts (0.105/KLOC), also just above the limit.
   It is the model's own output (neither the form nor the metavariable was given), it is one attempt in 31, and its recall is
   half of the cases; it shows that the pipeline can reach the neighbourhood of the limit, not that it passes it. It did not
   reappear in the ten folds of seeds 3 and 4.
9. **Even that rule raises no true alert.** All 51 of its alerts on Git (38 train, 13 test) were read one by one: 0 are a use after
   free. 12 are loops that move to another element, 11 reassignments by macros, 9 array slots overwritten, 8 a different
   object, 6 out-parameter reassignments, 2 unreachable paths, 1 reassigned in place, 1 verified harmless and 1 borderline benign (a
   pointer compared after `free`). Reasons and locations are in `docs/alert_review_seed1_fold2_attempt6.csv`. Getting under the alert limit
   does not make the alerts correct: the real-world gate measures noise, not precision, and a rule can pass it by matching
   less of the same kind of code.
10. **The Semgrep documentation in the prompt makes no detectable difference.** Leaving out the pattern-syntax section (1,278 characters in
   the template format) changed recall by +0.024 (95% interval -0.10 to +0.16) and precision by -0.07 over 10 paired folds. The
   real-world alert rate was lower without it in 7 of 10 folds (-0.88 alerts/KLOC, interval -2.8 to +1.0), partly through broad rules
   with more Juliet false positives; by the pre-registered criterion that is not an effect, and it would have to be re-run on other
   seeds. The template prompt already carries the strategy, so the documentation adds little.

## Threats to validity and limits

- **One CWE with enough data (416), 20 variants, 4-6 per test group;** CWE-415 is a negative result with a template made for 416.
- **Seeds:** five seeds (0 to 4) of the final configuration, one seed for each of the others. Spread over folds
  (+-18 to +-45 points of recall) is large; differences of a few points between configurations are not conclusions.
- **Template arm:** the strategy (event, uses, resets as taint by side effect) was written by us; it is the knowledge being
  tested and the results must be reported apart from the yaml/spec arms. Template v2, the source-line warning and the `not`
  message are generic feedback aids (changes.md phases 12-14); the last one is close to giving the rule.
- **Real-world code is assumed correct**; a real bug there counts as a false positive. The triage (40 sampled alerts of one rule, all
  51 alerts of another) was done by one reviewer reading about 12 lines of context, plus the callee when needed, not by running
  code; the noisy rules (hundreds of alerts each) were not read alert by alert. The review concerns false positives only. Alert counts of one rule vary 1-2% between runs.
- **Fix-commit check:** 16 commits, one file each, window of 10 lines, the same line numbers before and after the fix; the
  commit filter was adjusted after seeing the first output (changes.md and experiments.md say how).
- **Juliet recall** counts a match anywhere in a BAD file of a case as a detection, so it can overstate detection of cases split
  across files (variants 63/64).
- **Models and machine:** 4B and 30B (IQ4_XS, partial GPU offload) on a GTX 1060; the 30B runs depend on free RAM (runs were
  stopped by the system three times; later seeds completed when enough RAM was free); no other model families were tried; one run of each model call is deterministic
  (temperature 0) except where `--samples` was used.

## Not done

Evaluation of the critic, merger, history and example-mode options (implemented, with a plan in `docs/ablation_plan.md`;
the documentation ablation is done, the rest is pending); the other CWEs (401, 457, 476); a second model family; CVE-fix evaluation beyond the 16 Git commits;
interprocedural flows (Semgrep OSS); the 4B model (combo C) with the final configuration.
