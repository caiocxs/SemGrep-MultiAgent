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

## Metrics

Primary (one per question): mean test recall over the folds, mean real-world alerts per KLOC, number of accepted folds.
Secondary: precision, Juliet false positives, the share of attempts that write a `not_inside`, the share of repeated rules, and the
attempt at which the best rule appears. A fold without a valid rule counts as recall 0 and has no precision or alert rate.

## Analysis

`python -m src.pipeline.compare --a <B0 summaries> --b <experiment summaries>` pairs the folds by (seed, fold) and reports the mean
paired difference with a bootstrap 95% interval over the folds.

- **An effect is claimed only if** the interval excludes 0 **and** the mean difference is at least 0.10 in recall or at least
  25% in alerts per KLOC. Anything else is reported as "no difference that can be told from the spread over folds".
- Every comparison is reported, null results included, in `experiments.md`.
- Eight comparisons with five metrics each are many tests on 10 folds: they are exploratory. An effect found here is re-run on
  seeds 0, 3 and 4 before it is written as a finding.
- Results of different seeds are never compared with each other (different folds and real-world files).

## Limits that stay

One CWE with enough data, one model family, deterministic decoding at temperature 0 except where stated, real-world code assumed
correct. The spread of recall over folds (about 20 to 35 points) is larger than most differences these options can be expected
to make; with 10 folds the intervals are wide and a null result means "not detected", not "no effect".

## Cost

About 50 minutes per seed with the 30B model, so about 100 minutes per experiment with two seeds and about 14 hours for the eight.
`scripts/run_ablation_queue.ps1` runs them one after another and waits for free RAM (about 20 GB) before each.
