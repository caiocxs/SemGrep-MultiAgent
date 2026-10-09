# Plan for the comparisons of prompts and roles

Written on 2026-10-07, **before** the results of these comparisons. It fixes what is compared, with which metrics and what
counts as an effect, so that the criterion is not chosen after looking at the numbers.

## Base configuration (B0)

Combo D, `--format template` (template v2 with the source-line warning and the `not` feedback), CWE-416, 5-fold cross-validation
by flow variant, `--negatives ../git --max-negative-rate 0.1`, 6 fixes, Semgrep documentation in the prompts, no optional role.
Five seeds of B0 exist (0 to 4, 25 folds, see `findings.md`). Each experiment below changes **one** thing and runs on seeds 1 and 2
(10 folds), which makes it paired with B0 on the same folds and the same real-world files.

Combo E differs from combo D only in the role settings of the critic and the merger (the same 30B model, loaded the same way),
so with no option on it behaves as combo D and B0 is its baseline too.

## Experiments

| Name | What changes | Combo | Expectation |
|---|---|---|---|
| `nodocs` | the Semgrep documentation (1,278 characters of pattern syntax) is left out of the prompts | D | no difference: the text is short and the template prompt already explains the strategy |
| `history` | the corrector sees a summary of the earlier attempts | D | fewer repeated rules; at most a small gain |
| `nodiag` | the structural diagnoses of the gate (source-line warning, ineffective `not`) are off | E | more alerts/KLOC, since those messages are what made the model write `not_inside` |
| `critic` | an agent reviews each tested rule for the corrector, with the diagnoses on | E | unclear; it may add nothing to what the gate already says |
| `criticnodiag` | the critic with the diagnoses off | E | tests whether a critic agent can replace the hand-written diagnoses (compare with `nodiag` and with B0) |
| `merge` | a final attempt merges the best rule with one of a different strength | E | small gain in F1 or alerts |
| `pairs` | the generator sees vulnerable/safe pairs from the dataset labels instead of the detector's findings | D | higher recall and precision; it is an upper bound on the example information, not the pipeline as designed |
| `none` | the generator sees no example | D | lower recall; it measures what the detector's findings contribute |
| `qwen4b` | the 4B model (combo C) with the final configuration, which only had the older one | C | recall far below the 30B's, as before; it is the reference for the next row |
| `phi4` | a second model family, Phi-4-mini (combo F), same size class as the 4B | F | no better than the 4B; a result near the 30B's would be a surprise |

## Metrics

Primary (one per question): mean test recall over the folds, mean real-world alerts per KLOC, number of accepted folds.
Secondary: precision, Juliet false positives, the share of attempts that write a `not_inside`, the share of repeated rules, and the
attempt at which the best rule appears. A fold without a valid rule counts as recall 0 and has no precision or alert rate.

## Analysis

`python -m src.pipeline.compare --a <B0 summaries> --b <experiment summaries>` pairs the folds by (seed, fold) and reports the mean
paired difference with a bootstrap 95% interval over the folds. `--baseline <B0 summaries> --grouped logs/crossval/D logs/crossval/E`
does it for every experiment at once, labelling each summary by the options it recorded. `qwen4b` and `phi4` are compared with each
other (`--a` and `--b`), not with B0: they do not use the same model.

- **An effect is claimed only if** the interval excludes 0 **and** the mean difference is at least 0.10 in recall or at least
  25% in alerts per KLOC. Anything else is reported as "no difference that can be told from the spread over folds".
- Every comparison is reported, null results included, in `experiments.md`.
- Ten comparisons with five metrics each are many tests on 10 folds: they are exploratory. An effect found here is re-run on
  seeds 0, 3 and 4 before it is written as a finding.
- Results of different seeds are never compared with each other (different folds and real-world files).

## Limits that stay

One CWE with enough data, one model family, deterministic decoding at temperature 0 except where stated, real-world code assumed
correct. The spread of recall over folds (about 20 to 35 points) is larger than most differences these options can be expected
to make; with 10 folds the intervals are wide and a null result means "not detected", not "no effect".

## Cost

About 50 minutes per seed with the 30B model, so about 100 minutes per experiment with two seeds and about 14 hours for the eight that use it; the two small-model experiments take minutes.
`scripts/run_ablation_queue.ps1` runs them one after another and waits for free RAM (about 20 GB) before each.

## Exploratory additions (written on 2026-10-08, after the comparisons above were planned)

Two changes taken from the related work (`docs/changes.md`, phase 16). They are not part of the pre-registered list: whatever they show is
exploratory, and any effect must be repeated on other seeds before it is claimed.

| Name | What changes | Combo | Expectation, written before running |
|---|---|---|---|
| `guard` | the corrector always edits the best rule so far; worse corrections are discarded | D | fewer alerts/KLOC in the final rule than B0, because the best rule no longer gets lost; recall about the same |
| `apis` | the prompts list the memory functions the project defines | D | fewer alerts/KLOC on the real-world files; the effect, if any, is in the alerts after `FREE_AND_NULL`-style wrappers, not in the Juliet recall |
| `guardapis` | both | D | no more than the sum of the two; only run if one of them shows something |

Same criterion as the other rows: an effect is claimed only if the interval excludes 0 and the difference reaches 0.10 in recall or 25% of
the alerts. The comparison with B0 uses the same seeds (1 and 2) and `compare --grouped`. `apis` is a project-specific configuration: its
result is not comparable to a rule meant for any C code.
