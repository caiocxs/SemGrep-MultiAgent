# Ablation table

What each change to the pipeline did, measured with the runs made so far. Everything comes
from the run logs in `logs/synthesis/<combo>/<cwe>/<run>.json` (not versioned) except the
three combo A rows, which were run on the other machine and are taken from the summary
kept in `CLAUDE.md`. Run ids are the log file names. Details of each change are in
[changes.md](changes.md); more context for each run in [experiments.md](experiments.md).

**How to read the numbers**
- *Train* = the gate on the training files, used to choose and accept the rule.
  *Test* = held-out variants, evaluated once for the chosen rule; the number that counts.
- "Rejected before gate" = the rule never reached Semgrep's matching (YAML/JSON error,
  schema check, `;` check, name lint or Semgrep's own parse error).
- Almost everything is **one run per cell, seed 0, CWE-416**. There is no variance estimate
  and the test set is small (47 vulnerable cases): read the tables as indications, not as
  statistics. Where another seed exists it is listed.
- The pipeline's planned ablation (without corrector / critic / merge / deterministic
  aids) is only partly possible: the critic and the merge agents are **not implemented
  yet**, so they cannot be ablated.

## 1. Main table: one factor changed at a time (CWE-416, seed 0)

Reference for all rows: the official Semgrep packs (`p/c`, `p/default`, `p/cwe-top-25`,
`p/security-audit`) reach **recall 0%** on the same test split.

### 1a. Feedback aids (combo C, Qwen3-4B, YAML format)

| Variant | Run | Best attempt | Test recall | Test precision | Test FP |
|---|---|---|---|---|---|
| Feedback v1 (structure check, repeated-rule detection, `;` check, name lint) | `20260928-213047` | 2 (train 58%, 104 FP) | 58.5% | 42.9% | 32 |
| + v2 (operator whitelist, false positives grouped by code) | `20260928-225422` | 2 (same) | 58.5% | 42.9% | 32 |
| + v3 (quoting hint for YAML errors) | `20260928-230500` | 6 (same) | 58.5% | 42.9% | 32 |

Same seed, same final rule quality: the aids did not change the result for seed 0. Other seeds:

| Seed | v2 | v3 |
|---|---|---|
| 1 | never reached the gate (`20260928-225744`) | never reached the gate (`20260928-230824`) |
| 2 | never reached the gate (`20260928-230227`) | train recall 100% / 1358 FP; test recall 100%, precision 28.2%, 494 FP (`20260928-231110`) |

Combo A (Qwen2.5-Coder-3B, CPU machine, from CLAUDE.md): no aids (`20260927-191315`):
not accepted, the 4 attempts had the same schema error; with `check_structure` and repeated-rule
detection (`20260927-193243`): valid structure at attempt 2, then `;` errors; with
`check_c_statements` (`20260927-200423`): valid syntax at attempt 1, test recall 0%.
The aids fixed the *form* of the rule but not its logic.

### 1b. Output format (same model, feedback v3)

| Model | Format | Run | Best attempt | Test recall | Test precision | Test FP |
|---|---|---|---|---|---|---|
| C (4B) | yaml | `20260928-230500` | 6 | 58.5% | 42.9% | 32 |
| C (4B) | spec | `20260928-233100` | 0 | 14.6% | 100% | 0 |
| C (4B) | template* | `20260929-171815` | 2 | 100% | 25.9% | 266 |
| D (30B) | yaml | `20260928-231645` | 1 | 7.3% | 100% | 0 |
| D (30B) | spec | `20260928-234055` | 0 | 9.8% | 100% | 0 |
| D (30B) | template* | `20260929-233004` | 1 | **48.8%** | **100%** | **0** (accepted) |

\*Template = the strategy (state change of a variable, taint by side effect) is written by
us and the model only fills in patterns. It is an arm that changes methodological
principle 1 and must be reported separately from yaml/spec.

- YAML -> spec removed every YAML-level error, but the models then used only sequence
  patterns that match almost nothing (high precision, recall under 15%).
- The template gave the only accepted rule (D, 30B). With the 4B model it gave high recall
  by accident (it marked the pointer at `malloc` and treated `free` as a reset) and 266 FP.
- Spec on seeds 1 and 2 (combo C): seed 1 test recall 56.1% / precision 79.3% / 6 FP
  (`20260928-233304`), seed 2 recall 7.3% / precision 100% / 0 FP (`20260928-233544`).

### 1c. Model (seed 0, CWE-416; the run that reaches the gate best in each format)

| Model | Size / quant | YAML | Spec | Template |
|---|---|---|---|---|
| A - Qwen2.5-Coder-3B Q6_K (CPU) | 3B | test recall 0% (`20260927-200423`, CLAUDE.md) | not run | not run |
| B - Qwen2.5-Coder-7B IQ4_XS | 7B | never reached the gate (`20260928-211316`) | not run | not run |
| C - Qwen3-4B-Instruct-2507 Q6_K | 4B | 58.5% / 42.9% / 32 FP | 14.6% / 100% / 0 | 100% / 25.9% / 266 FP |
| D - Qwen3-Coder-30B-A3B IQ4_XS | 30B (3B active, partial GPU offload) | 7.3% / 100% / 0 | 9.8% / 100% / 0 | **48.8% / 100% / 0 (accepted)** |

Cells are test recall / precision / false positives. Model size alone did not help in YAML
or spec (the 30B made the same syntax mistakes as the 3-7B models); with the template it made the
difference between a wrong and a correct choice of the event.

### 1d. Sampling: best-of-N (combo C, seed 0, temperature 0.7, 3 fixes per sample)

| Format | Run | Samples passing the gate | Best (chosen on train) | Test |
|---|---|---|---|---|
| yaml | `20260929-132030` | 0/10 | recall 0%, 0 FP | recall 0% |
| spec | `20260929-133716` | 0/10 | recall 0%, 0 FP | recall 14.6%, precision 100% |

Ten samples did not find an accepted rule and temperature 0.7 made YAML errors more
frequent. It costs 10 times the compute of a single run.

### 1e. Detector findings used as examples (combo C, seed 0)

| Findings | Format | Run | Test recall / precision / FP |
|---|---|---|---|
| v1 (Qwen 3B Q4_K_M, generic prompt) | spec | `20260928-233100` | 14.6% / 100% / 0 |
| v2 (Qwen 3B Q6_K, per-CWE prompt, literal evidence) | spec | `20260929-150456` | 14.6% / 100% / 0 |
| v1 | yaml | `20260928-230500` | 58.5% / 42.9% / 32 |
| v2 | yaml | `20260929-150237` | none (never reached the gate) |

Detector v2 alone (CWE-416, 300 files): BAD flagged 76/150 (v1: 150/150), GOOD flagged 69/150
(v1: 37/149). The v2 findings did not improve the synthesis.

## 2. Ablation of the corrector, derived from the logs

For each single-loop run (21 runs, all formats and combos), *generator only* = attempt 0;
*with corrector* = the best attempt of the loop.

| Outcome | Runs |
|---|---|
| Attempt 0 was the best attempt (the corrector did not improve on it) | 8 |
| A later attempt (after the corrector) was better | 13 |
| Runs accepted | 1 (`20260929-233004`, D, template, CWE-416) |
| Accepted runs where attempt 0 already passed | 0 |

In all 13 runs where the corrector helped, attempt 0 had been **rejected before the gate
or by Semgrep** (syntax, schema, `;`, name, parse error): the corrector's contribution is
mainly getting the rule to the gate. The accepted rule was produced at attempt 1, after
the corrector fixed a validation error of attempt 0 (`taint.sinks[3].not[0]` empty), so
**without the corrector that run would not have been accepted**. In the remaining runs the
corrector often repeated a previous rule (detected and reported by the loop), and, checked
over every attempt of every log (best-of-N samples included), it never turned a rule with
false positives into one with no false positives and recall above 0%.

## 3. Other CWEs (combo C and D, template, seed 0)

| CWE | Model | Run | Train (best) | Test recall / precision / FP | Accepted |
|---|---|---|---|---|---|
| 415 | C | `20260929-172047` | recall 0%, 0 FP | 0% / - / 0 | no |
| 415 | D | `20260929-233345` | recall 0%, 0 FP | 0% / - / 0 | no |
| 476 | C | `20260929-172323` | recall 59%, 964 FP | 38.8% / 15.8% / 308 | no |
| 476 | D | `20260929-233715` | recall 0%, 0 FP | 0% / - / 0 | no |

Nothing has been run on CWE-401 and CWE-457. Baseline packs: 415 -> 7.7% recall (precision
100%) with `p/security-audit`, 476 -> 0%.

## 4. What the table supports

1. The official Semgrep packs do not detect these weaknesses (0%, or at most 15.6% on CWE-401):
   there is a real gap.
2. The deterministic aids (structure/`;`/name checks, grouped feedback, hints) fixed the form of
   the rules, not their logic; on the same seed they did not change the best result.
3. Switching to the JSON spec removed YAML errors but not the semantic ones.
4. The only accepted rule came from the combination of the largest model, the strategy
   template and the corrector, on one CWE and one seed. The same setup failed on CWE-415 and
   CWE-476.
5. Best-of-N sampling and the v2 detector did not help in the runs made.
6. With real-world code in the gate and cross-validation (section 6): the largest model writes rules that generalize across
   Juliet variants (mean recall 76% over 25 folds), none passes the real-world limit, and the rule accepted on Juliet fails it.

## 5. Not evaluated yet

- Critic and merge agents: implemented (changes.md phase 15) but not run on the real pipeline; the comparisons are planned in
  `ablation_plan.md` and listed in section 6.
- Reproducibility of the accepted rule: done by cross-validation (section 6). The rule's family reproduces on Juliet and fails the
  real-world gate.
- Combo B and A in the spec/template formats; combos B/D with best-of-N.
- CWE-401 and CWE-457.
- A "no aids at all" run on the same model as the later runs (only combo A has one).
- Confidence intervals: section 6 reports means and spread over folds; sections 1 to 3 are still single runs.

## 6. Real-world gate and cross-validation (changes.md phases 10-15)

Everything here uses the gate with real C code (Git, limit 0.1 alerts per KLOC), CWE-416, the template format, and 5-fold
cross-validation by flow variant (every variant tested once). Means over folds; the spread is the standard deviation over folds.

### 6a. What the configuration changes did (cross-validation, one seed per row unless stated)

| Model | Configuration | Seed | Accepted | Recall | Precision | Alerts/KLOC |
|---|---|---|---|---|---|---|
| Qwen3-4B | template v1 | 0 | 0/5 | 20.0% +- 44.7 | 23.9% (1 fold) | 0.00 |
| Qwen3-Coder-30B | template v1 | 0 | 0/5 | 89.2% +- 18.6 | 69.8% +- 19.9 | 5.11 +- 2.56 |
| Qwen3-Coder-30B | v1 + source-line warning | 2 | 0/5 | 69.5% +- 23.7 | 87.4% +- 19.0 | 2.78 +- 2.02 |
| Qwen3-Coder-30B | final (v2 + warning + `not` feedback) | 0 to 4 pooled | 0/25 | 75.8% +- 25.6 | 83.1% +- 23.1 (24 folds) | 2.92 +- 2.29 |

On seed 2, the only seed with two 30B configurations on the same folds: v1 + warning against final, recall +0.022 (95% interval
+0.000 to +0.067), alerts/KLOC -0.11 (-0.87 to +0.48): no difference that can be told from the spread over folds
(`python -m src.pipeline.compare`).

### 6b. Comparisons planned (docs/ablation_plan.md), baseline = the final configuration on seeds 1 and 2

| Experiment | Change | Status |
|---|---|---|
| `nodocs` | no Semgrep documentation in the prompts | done, 10 paired folds: no effect by the plan's criterion (recall +0.024, interval -0.10 to +0.16); alerts/KLOC -0.88 in 7 of 10 folds, exploratory (interval -2.8 to +1.0) |
| `history` | the corrector sees the earlier attempts | done, 10 paired folds: no effect detected (recall +0.010, interval -0.04 to +0.08); repeated rules rose from 0/70 to 8/70 attempts (exploratory) |
| `nodiag` | structural diagnoses of the gate off | done, 25 paired folds (5 seeds): recall +0.084 (interval +0.013 to +0.157), below the 0.10 of the criterion, so not an effect; precision -0.074 and alerts +0.86 with intervals that include 0; valid attempts 60% against 74% |
| `critic` | a critic agent reviews each tested rule | not run |
| `criticnodiag` | the critic instead of the diagnoses | not run |
| `merge` | a final attempt merges the best and a complementary rule | not run |
| `pairs` | vulnerable/safe pairs as examples instead of the detector's findings | not run |
| `none` | no examples | not run |
| `qwen4b` | the 4B model with the final configuration | not run |
| `phi4` | a second model family (Phi-4-mini) | not run |

The results go into this table as they come, with the paired comparison against the baseline; null results are reported as such.

Exploratory options (see `docs/ablation_plan.md`, last section), seeds 1 and 2, 10 paired folds each:

| Name | What changes | Result |
|---|---|---|
| `guard` | the corrector always edits the best rule so far | no effect: recall +0.076 (-0.02 to +0.21), alerts +0.66 (-0.09 to +1.79), higher on average |
| `apis` | the prompts list the project's memory functions | no effect by the criterion, but alerts 6.28 against 2.53 (interval -1.6 to +12.1); the model copies the list into the event |
| `guardapis` | both | an effect, harmful: recall +0.259, precision -0.388, 101 Juliet false positives, 17 alerts/KLOC (interval of the alerts +0.33 to +34.2) |
