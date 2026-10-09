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
| `critic` | a critic agent reviews each tested rule | done, 10 paired folds: no effect (recall -0.069, interval -0.27 to +0.11; alerts -0.40, interval -2.5 to +1.7) |
| `criticnodiag` | the critic instead of the diagnoses | done, 10 paired folds: no effect (recall -0.069, interval -0.29 to +0.16; alerts +0.26); the critic does not replace the diagnoses, and adds nothing to them |
| `merge` | a final attempt merges the best and a complementary rule | not run |
| `pairs` | vulnerable/safe pairs as examples instead of the detector's findings | done, 10 paired folds: no effect by the criterion (recall +0.158, interval -0.10 to +0.37; alerts +0.95), but **2 of 10 folds accepted**, the only accepted folds of all comparisons (seed 1, folds 0 and 3: test recall 57% and 31%, 0 Juliet false positives, 0.03 and 0.02 alerts/KLOC); upper bound on the example information, not the designed pipeline; the two rules were not read |
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

## 7. Hosted models against the local ones: does a larger model pass the pipeline?

Question: if the generator and the corrector are a 120B-class hosted model instead of a local one, do the rules pass the pipeline's
gates (Juliet false positives and real-world alerts under 0.1 per KLOC on the train side)? Combos G, H and I use the same
loop, template, prompts, folds and real-world files as combo D; only the generator and the corrector call an API (`src/pipeline/remote.py`,
`configs/combos/combo_{g,h,i}.toml`; the models come from `.env`). Everything else, including the gate, is local and deterministic. These
arms are reported apart from the local ones: a hosted 120B model is not a small local model (principle 1 of the project), and the
prompts, with code from Juliet and Git, leave the machine.

### 7a. Result (CWE-416, template format, 5-fold cross-validation by variant, same seeds and folds as B0)

| Generator and corrector | Seeds | Folds | Accepted | Recall | Precision | Juliet FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|---|
| Qwen3-4B, local (combo C, template v1) | 0 | 5 | 0 | 20.0% | 23.9% (1 fold) | - | 0.00 (rules empty or broad) |
| Qwen3-Coder-30B, local (B0, final) | 1, 2 | 10 | **0** | 71.6% | 89.4% | 9.0 | 2.53 |
| gpt-oss-120b, Groq (G) | 1, 2 | 10 | **0** | **98.9%** | 84.1% | 11.4 | 2.59 |
| Nemotron-3-super-120b, OpenRouter free (I) | 1 | 5 | **0** | 92.7% | 75.5% | 20.4 | 3.77 |
| Gemini flash (H) | 1 | partial | - | - | - | - | - (see 7b) |

Paired with B0 on the same folds (`python -m src.pipeline.compare`, bootstrap 95% interval over folds):

| Comparison | Recall | Precision | Juliet FP | Real-world alerts/KLOC |
|---|---|---|---|---|
| G against B0, 10 folds | **+0.273** [+0.12, +0.41] | -0.053 [-0.21, +0.10] | +2.4 [-13.8, +18.6] | +0.06 [-2.15, +2.16] |
| I against B0 seed 1, 5 folds | +0.213 [+0.03, +0.40] | -0.155 [-0.36, +0.05] | +12.0 [-12.0, +37.2] | +1.37 [-1.85, +4.62] |

**Reading** (an effect found on two seeds is exploratory until repeated on seeds 0, 3 and 4, see the quota note in 7b). By the pre-registered criterion (interval excludes 0 and the difference reaches 0.10 in recall) the Groq model has a real
recall effect over the local 30B: it writes rules that detect almost every held-out Juliet variant. It does not pass the pipeline:
0 of 10 folds accepted, and the real-world alert rate is the same as the local model's (2.59 against 2.53 per KLOC, limit 0.1). The
larger model detects the Juliet cases more often, but its rules raise as many alerts on the Git sources as the local ones. The rules of G
and I were not read, so the reason is not known; the earlier reading of local rules (`findings.md`, items 3 and 9) found loops that move to
another element and reassignment through macros, and the equal alert rate suggests the same obstacle, which a larger generator does not remove. OpenRouter shows the same direction with less recall and more
false positives, on one seed only (5 folds, the interval of the recall barely excludes 0): exploratory.

The same holds for the only accepted folds of the whole study, which are from a **local** model with a different example source
(`pairs`, section 6b): they have low recall (57% and 31%), which suggests narrow rules, and were not read.

### 7b. Rate limits (from `logs/remote_usage.jsonl`, one line per call, keys never logged)

| Provider (free tier) | Limits seen | Calls | Seconds per call | 429 answers | Time waiting for limits |
|---|---|---|---|---|---|
| Groq, `openai/gpt-oss-120b` | 1000 requests/day and 8000 tokens/min (response headers `x-ratelimit-*`); **200,000 tokens/day** (only in the text of the 429 that came at 20:03: "tokens per day (TPD): Limit 200000, Used 199928") | 74 until seed 2, then the 429s | 2.2 (max 5.6) | the daily one, after about 8 folds | 9 s of pacing (`min_interval` 2.5 s); then Retry-After of 18 min |
| OpenRouter, Nemotron free | not exposed in headers | 54 so far | 17.9 | 5 | 2431 s |
| Gemini, `gemini-flash-latest`, two keys | not exposed in headers | 20 so far | 130.6 | 7 | 3464 s |

- **Groq's binding limit is the daily token quota, 200,000 tokens, about 8 folds a day** (a fold costs about 25 thousand tokens). The repeat of the
  recall effect on seeds 0, 3 and 4 (15 folds, about 350 thousand tokens) did not fit: the three runs stopped on the quota (Retry-After
  of 256 to 1092 s, longer than the 15 minutes the code waits) and were not completed. Per the plan the recall effect of G is therefore
  **not yet a finding**: it holds on seeds 1 and 2 and is waiting for the repeat, which needs two more days at this tier or a paid one.
- **Groq fits a full experiment inside the limits.** Ten folds (two seeds) took 74 calls (7% of the day's requests) and about 231 thousand
  tokens (181 thousand of prompt, 50 thousand of answer) in about two hours, and the time is dominated by the local Semgrep gate (the model call is
  2 s). A call is about 2.5 thousand prompt tokens, and about 700 of answer, so the 8000 tokens/min limit allows two to three calls per minute at full speed; the gate's
  time between calls kept the run far from it. A longer run (more seeds or CWEs) would hit the per-minute token limit first, then the
  daily one (not exposed by the headers).
- **OpenRouter's free model works, slowly:** 18 s per answer (about 2000 tokens each, longer than the other models, which write 500 to 700)
  and a 429 every ten calls, handled by waiting. One seed (5 folds) took about half an hour.
- **Gemini's free tier is the limit of this study:** 20 calls in an hour and a half, 7 of the 20 answered 429 even with two keys, 130 s per
  call on average. A 5-fold seed needs about 35 calls, so each seed takes many hours; only part of seed 1 exists and the arm is not compared.
  The quota, not the model, decides what can be measured with it.
- The pacing and retry code (`min_interval`, Retry-After, key rotation, stop when the wait suggests the daily quota is gone) is tested
  in `tests/test_remote.py`.

### 7c. Limits of this comparison

- Two hosted models on one or two seeds each; the 10-fold interval of G is the only one that supports a claim, the rest is exploratory.
- A hosted model is not deterministic across days (versions change) even at temperature 0; the run was made once.
- Prompts include code of the Juliet and Git sources; the free tiers may keep them.
- Not measured here: the 4B local model and Phi-4-mini with the final configuration (`qwen4b`, `phi4`, queued), which are the reference
  for the small-model end of the comparison.
