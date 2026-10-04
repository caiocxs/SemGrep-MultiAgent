# Experiment log

Results of rule-synthesis runs (`python -m src.pipeline.synthesize`). Full per-attempt
data (raw responses, rules, gate reports, timings) lives in
`logs/synthesis/<combo>/<cwe>/<run>.json` (not versioned).

All runs below: **CWE-416**, `--seed 0`, `--max-fix-attempts 6`, 3 detector findings as
examples, train 103 BAD / 103 GOOD, test 47 BAD / 47 GOOD (variants 01, 11, 15, 17, 18, 63).

## Summary

| Combo | Generator / corrector | Machine | Accepted | Held-out test |
|---|---|---|---|---|
| A | Qwen2.5-Coder-3B Q6_K | CPU notebook | no | recall 0% (best run) |
| B | Qwen2.5-Coder-7B IQ4_XS | GTX 1060 6 GB | no | never reached the gate |
| C | Qwen3-4B-Instruct-2507 Q6_K | GTX 1060 6 GB | no | recall 58.5%, precision 42.9%, 32 FP |

Single seed per combo: these are baselines, not conclusions.

## Combo A (Qwen2.5-Coder-3B Q6_K everywhere)

| Run | Adjustments | Outcome |
|---|---|---|
| `20260927-191315` | none | 4 attempts with the same error (`pattern:` holding a list); the corrector returned an identical rule. |
| `20260927-193243` | + `check_structure` + repeated-rule detection | Valid structure at attempt 2; missing `;` in C statements; attempt 3 repeated. |
| `20260927-200423` | + `check_c_statements`, 6 fixes (~20 min) | Valid syntax at attempt 1 (recall 0%, 0 FP); then invented the key `metavariable-patterns` (Semgrep accepted it silently) and `line_number()` functions; attempt 4 repeated. Test recall 0%. |

The rule **logic** was wrong in every run (searches `malloc → free → reassignment`, which
is not a use after free) and the model never tried taint mode.

## Combo B (Qwen2.5-Coder-7B IQ4_XS generator/corrector) — `20260928-211316`

7 attempts (0–6), 102–157 s each. All failed on the same `check_c_statements` error: a
multi-line C pattern with a statement without `;` (`$P = malloc(...)`). The corrector
received that message 6 times and never fixed it, so no attempt reached the gate: no
train/test recall or false-positive numbers exist for this run.

## Combo C (Qwen3-4B-Instruct-2507 Q6_K generator/corrector) — `20260928-213047`

7 attempts, 20–33 s each (vs. 100–157 s for B on the same GPU).

| Attempt | Failure |
|---|---|
| 0 | YAML syntax error: `- pattern: *$PTR` (unquoted `*` read as a YAML alias) |
| 1 | `focus-metavariable` / `metavariable-pattern` placed outside `pattern-sources`/`pattern-sinks` entries in a taint rule |
| 2 | gate: train recall 58%, 104 FP (**best attempt**) |
| 3 | gate: train recall 58%, 104 FP |
| 4 | missing `;` in multi-line C pattern (`malloc($SIZE)`) |
| 5 | schema error: `focus-metavariable`, `pattern` not allowed where placed |
| 6 | schema error: `pattern`, `pattern-either` not allowed where placed |

Best attempt (2), evaluated on the held-out test: **recall 58.5%, precision 42.9%, 32 FP**.
Not accepted (FP > 0 on train).

Observations:
- C is the only combo that used **taint mode**, which earlier analysis found far better
  than sequential patterns in Semgrep (138/150 vs 30/150 files on CWE-416).
- The corrector did not reduce the 104 false positives between attempts 2 and 3, and
  attempts 4–6 regressed to schema errors while the best attempt stayed at 2.
- Faster per attempt than B on the same 6 GB GPU.

## Combo C, more seeds and feedback changes

Feedback changes (deterministic aids, to be declared in the thesis):
- **v2**: `check_structure` rejects operator-like keys outside the Semgrep schema
  (e.g. `metavariable-patterns`); the gate feedback groups repeated false positives by
  matched code ("and N more like it").
- **v3**: YAML errors caused by unquoted `*`/`&`/`!`/`: ` get a quoting hint.

Seed 0 gave the same rule with v2 as before (recall 58.5%, precision 42.9%, 32 FP).
v2 alone did not help seeds 1 and 2: 4–6 of 7 attempts still died on `- pattern: *$P`
(YAML alias), which the PyYAML message does not explain to the model.

With v3 (`20260928-230500`, `-230824`, `-231110`), max 6 fixes:

| Seed | Test variants | Best attempt | Held-out test |
|---|---|---|---|
| 0 | 01, 11, 15, 17, 18, 63 | 6 (recall 58%, 104 FP on train) | recall 58.5%, precision 42.9%, 32 FP |
| 1 | 01, 06, 10, 12, 18, 64 | 0 (never passed schema: `focus-metavariable` misplaced, then repeated rules) | none |
| 2 | 07, 08, 09, 16, 18, 64 | 3 (recall 100%, 1358 FP on train) | recall 100%, precision 28.2%, 494 FP |

No run was accepted (all have false positives). The hint cut the YAML-syntax attempts from 4 to 2 (seed 1) and
from 6 to 2 (seed 2; seed 0 already had only 1), but the model then hits schema mistakes with
`focus-metavariable` / `metavariable-pattern` in taint rules, and the corrector repeats a
previous rule (attempts 4–6). The two runs that reach the gate are either narrow with 100+
FP (seed 0) or match almost every `free` (seed 2): the semantics are still missing.

## External baseline: official Semgrep rule packs

`python -m src.pipeline.baseline --cwe CWE-XXX --rules ...` grades rule files on the same
held-out test split (seed 0) with the same gate. Packs downloaded from
`https://semgrep.dev/c/p/<pack>` on 2026-09-28 into `rules/baseline/` (not versioned).
`p/c` has only 2 rules (`gets`, `/dev/urandom` fd exhaustion).

| CWE | test BAD/GOOD | p/c | p/default | p/cwe-top-25 | p/security-audit |
|---|---|---|---|---|---|
| 401 | 302/302 | 0% | 0% | 0% | recall 15.6%, precision 26.7% (59 TP, 162 FP) |
| 415 | 96/96 | 0% | 0% | 0% | recall 7.7%, precision 100% (6 TP, 0 FP) |
| 416 | 47/47 | 0% | 0% | 0% | 0% |
| 457 | 196/196 | 0% | 0% | 0% | 0% |
| 476 | 109/109 | 0% | 0% | 0% | 0% |

Caveat: the gate counts a match from any rule of the pack; `security-audit` hits in
CWE-401 come from rules that are not about memory leaks.

## Combo D (Qwen3-Coder-30B-A3B generator/corrector, partial GPU offload)

Config `configs/combos/combo_d.toml`: 10 of 48 layers on the GPU, the rest in RAM
(`llama-cpp-python` 0.3.35 does not expose `--n-cpu-moe`). Model (16.4 GB) downloaded to
`.models/`.

Seed 0, 6 fixes, feedback v3 (`20260928-231645`), 18–58 s per attempt (fast despite the
partial offload):

| Attempt | Outcome |
|---|---|
| 0 | `focus-metavariable` / `metavariable-pattern` at the top level of the rule |
| 1 | valid rule, train recall 0%, 0 FP (**best attempt**) |
| 2, 3 | unquoted `- pattern: *$PTR` (YAML alias), even with the quoting hint |
| 4 | recall 100%, 516 FP |
| 5 | `metavariable-pattern` at the top level |
| 6 | missing `;` in `$PTR = malloc(...)` |

Held-out test of the best attempt: recall 7.3%, precision 100%, 0 FP. Not accepted
(train recall 0%). The 30B model makes the same generic-syntax mistakes as the 3–7B ones
(alias, top-level operators, missing `;`), so parameter count alone did not fix them.

## Spec format (`--format spec`), CWE-416, 6 fixes, max 7 attempts each

The model writes a JSON of patterns and the program builds the YAML (see changes.md,
phase 5). Same splits and seeds as above.

| Combo / seed | Run | Best attempt | Held-out test |
|---|---|---|---|
| C / 0 | `20260928-233100` | 0 (train recall 0%, 0 FP) | recall 14.6%, precision 100%, 0 FP |
| C / 1 | `20260928-233304` | 4 (train recall 20%, 6 FP) | recall 56.1%, precision 79.3%, 6 FP |
| C / 2 | `20260928-233544` | 4 (train recall 3%, 0 FP) | recall 7.3%, precision 100%, 0 FP |
| D / 0 | `20260928-234055` | 0 (train recall 0%, 0 FP) | recall 9.8%, precision 100%, 0 FP |

None accepted (train recall below the 50% threshold). Compared with the YAML format:
- **All YAML-level errors are gone** (alias, unquoted `:`, misplaced `focus-metavariable`,
  `metavariable-pattern`, top-level operators). Every attempt now either passes the
  builder checks and reaches the gate, or fails on a real pattern problem.
- Remaining format-level failures are inside the patterns: alternatives written as text
  inside one pattern (`or`, `|` between statements, seed 1 attempts 0/2 and seed 2, which
  also produced `Invalid pattern for C` from Semgrep), empty `inside`/`not_inside` lists,
  and missing `;`. The corrector often resubmitted the same rule (attempts 3-6 of C/0,
  attempt 3 in the others).
- **The models chose `search` in every run and never `taint`**, using sequences like
  `free($P); ... <use of $P>`, which the docs already say do not cross block boundaries
  (30/150 files on CWE-416 in the earlier analysis). This is why recall stays low.
  Both C and D also put full statement sequences in `not`, which does not express
  "reassigned after free" (a `not` pattern excludes matches equal to it).
- Rules are safe but narrow: precision 100% with 0 FP in three of four runs and recall
  under 15%. Best result overall: C / 1, recall 56.1% / precision 79.3% on test, still
  below the train recall needed for acceptance.
- The 30B model (D) did not do better than the 4B one in this format either.

Conclusion so far: the form of the rule was a real obstacle (fixed by the spec format),
but the deeper problem is the choice of matching strategy and the semantics of the
operators, which none of the tested models handles.

## Best-of-N sampling (`--samples 10`), combo C, CWE-416, seed 0

10 independent loops, temperature 0.7, 3 fixes each (4 attempts per sample; earlier runs
used 6 fixes). The gate picks the best attempt on train; test is evaluated once for it.

| Format | Run | Samples passing | Best (train pick) | Held-out test |
|---|---|---|---|---|
| yaml | `20260929-132030` | 0/10 | sample 0, attempt 3: recall 0%, 0 FP | recall 0%, no matches |
| spec | `20260929-133716` | 0/10 | sample 0, attempt 0: recall 0%, 0 FP | recall 14.6%, precision 100%, 0 FP |

- No sample passed in either format; best-of-N did not find an accepted rule.
- **Temperature 0.7 made the YAML format worse**: most samples died on YAML-level errors
  (unquoted `*($P)` alias in 3 samples for all 4 attempts, `message:` with a colon,
  operators at the top level, `pattern-either` indentation, `pattern` as a list). Only
  one attempt reached the gate with something (sample 3, attempt 1: train recall 58%,
  104 FP - the same profile as the temperature-0 run of this combo).
- **Spec format**: no YAML errors, but half of the samples ended in Semgrep
  `Invalid pattern for C` (parsing error of a pattern) or empty `inside`/`not` lists, and
  the rest were valid rules with train recall 0% and 0 FP (sequence patterns that match
  nothing). The corrector repeated its previous rule in 2 of the 3 later attempts of most
  samples.
- Because the chosen "best" is simply the first valid rule with 0 FP and 0% recall (the
  `_score` ranks fewest FP first), selection has nothing to work with when every valid
  rule matches nothing.

Reading: sampling more does not fix a missing capability. With this model and prompts the
chance of a passing rule per sample is below 1/10 in both formats.

## Detector v2 (per-CWE prompt, Qwen2.5-Coder-3B Q6_K), CWE-416

`python -m src --models QWEN_CODE --datasets CWE_416 --prompt per_cwe/cwe_416` with
`QWEN_CODE` pointing to the Q6_K file and `N_GPU_LAYERS=-1` in `.env` (not versioned).
All 300 CWE-416 files (150 BAD / 150 GOOD), ~13 s per file on the GTX 1060, logs in
`logs/per_cwe/cwe_416/QWEN_CODE/CWE_416/`. Compared with the v1 logs (`logs/dataset/`,
generic prompt, Q4_K_M):

| Detector | BAD flagged | GOOD flagged (false positive) | Findings kept | Rejected by evidence check |
|---|---|---|---|---|
| v1 (generic prompt, Q4_K_M) | 150/150 | 37/149 | 187 | - (no check) |
| v2 (per-CWE prompt, Q6_K), validated | 76/150 | 69/150 | 145 | 136 |
| v2, raw model verdict | 98/150 | 131/150 | 145 | 136 |

On CWE-416 the v2 detector is **worse than v1 on both sides**: it detects half of the BAD
files and flags more GOOD files (46% vs 25%). The evidence validation removes many
findings (136 rejected, typically `violation_code does not match line N`: the model
quotes real code with a wrong line number), and the raw model flags 131/150 GOOD files
before validation, so the "conservative" per-CWE prompt is not conservative with this
model. What v2 does give is literal `source_code`/`violation_code` on every kept finding,
which v1 lacks. Numbers are for CWE-416 only (GOOD files also contain never-called
`helperBad` code, which counts as a flag here).

### Synthesis with the v2 findings (`--logs logs/per_cwe/cwe_416/QWEN_CODE/CWE_416`)

Combo C, CWE-416, seed 0, 6 fixes, 103 usable findings (vs 126 with v1), same split.

| Format | Run | Best attempt | Held-out test |
|---|---|---|---|
| yaml | `20260929-150237` | 0 (nothing valid reached the gate; attempts 3-6 repeated attempt 2) | none |
| spec | `20260929-150456` | 1 (train recall 0%, 0 FP) | recall 14.6%, precision 100%, 0 FP |

Not accepted. The spec result is identical to the v1-findings run of the same seed
(recall 14.6%, precision 100%), and the yaml run failed on schema errors as before, so
the literal-evidence findings did not change the outcome. With one seed this is only an
indication.

## Strategy template (`--format template`), combo C, seed 0, 6 fixes

Experimental arm: the strategy (a state change of a variable, run as Semgrep taint mode
by side effect) is written by us and the model only fills in `event`, `uses` and `resets`
(changes.md, phase 8). Findings from the v1 detector. Reported separately from yaml/spec.

| CWE | Run | Best attempt (train) | Held-out test |
|---|---|---|---|
| 416 | `20260929-171815` | 2: recall 100%, 854 FP | recall 100%, precision 25.9%, 266 FP |
| 415 | `20260929-172047` | 0: recall 0%, 0 FP | recall 0%, no matches |
| 476 | `20260929-172323` | 5: recall 59%, 964 FP | recall 38.8%, precision 15.8%, 308 FP |

None accepted (false positives on train in every case). Compared with the CWE-416 runs
without a template (best test: recall 58.5% / precision 42.9% in YAML, 14.6% / 100% in
spec), the template gives **more recall with much worse precision**.

What the models wrote shows that they do not grasp the state-change idea even when it is
given:
- CWE-416, attempt 2: `event` = `$X = malloc($SIZE);` (marks the pointer at allocation),
  `uses` = `free($X);`, `$X->...`, `($X)[...]`, `$X = $E`, and `resets` = `free($X);`. The
  free is placed as a *reset* instead of as the event, so almost every use after any
  allocation is reported: the 100% recall is an accident, not detection of the weakness
  (top false positives are `data = malloc(...)`, `data[i] = 5LL;`).
- CWE-476, attempt 5: `event` = `$P = $E` (any assignment) with resets on NULL checks:
  reports nearly every dereference (false positives such as `data = &tmpData;`).
- CWE-415: `event` = `malloc($P) -> $P` (not valid C, matches nothing) and uses with `not`
  patterns such as `free($P) && $P == NULL`; recall 0% in all attempts. A `uses` key
  written twice in one attempt was silently overwritten until duplicate keys were
  reported (changes.md, phase 8).
- The corrector repeated a previous rule in 3 of 6 corrections in CWE-416 and CWE-476.

Reading: given the strategy, the recall problem changed into a precision problem, and
the failure moved to the semantics of *which event puts the variable in the bad state*.
The strategy alone does not make a 4B model produce a usable rule.

### Template with the 30B model (combo D), seed 0, 6 fixes

| CWE | Run | Best attempt (train) | Held-out test |
|---|---|---|---|
| 416 | `20260929-233004` | 1: recall 54%, 0 FP - **ACCEPTED** | recall 48.8%, precision 100%, 0 FP |
| 415 | `20260929-233345` | 1: recall 0%, 0 FP | recall 0%, no matches |
| 476 | `20260929-233715` | 1: recall 0%, 0 FP | recall 0%, no matches |

**First accepted rule of the project**: `rules/accepted/D/cwe-416.yaml` (CWE-416, combo D,
template format, seed 0, accepted at attempt 1 of the loop). Re-evaluated independently
with `python -m src.pipeline.baseline --cwe CWE-416 --rules rules/accepted/D/cwe-416.yaml`
on the held-out test split: recall 48.8% (20 detected cases), precision 100%, 0 false
positives. Baseline packs on the same split: 0%.

What the rule does (written by the model, see the JSON in the run log): taint by side
effect; source `free($P)` with focus on `$P`; sinks `$P[...]`, `$P->...`, `* $P`,
`memcpy($P, ...)` and `strcpy($P, ...)` (with `not` for self-copies); sanitizers
`$P = NULL`, `$P = malloc(...)`, `$P = calloc(...)`, `$P = realloc(...)`. It uses only
metavariables, no example-specific names.

Caveats, all to be stated with the result:
- It belongs to the **template arm**: the strategy (state change of a variable, taint by
  side effect) was provided by us; the model chose the event, the uses and the resets. The
  same template with the 4B model (combo C) gave recall 100% / precision 25.9% with 266 FP
  (wrong event, see above), and no rule was accepted without the template.
- One seed and one run: recall on test is 48.8%, the variants unreachable for intraprocedural
  Semgrep (63/64) are part of the misses, and the test set is small (47 cases).
- **The same model and format did not work for CWE-415 and CWE-476**: every attempt was a
  valid rule with 0 false positives and 0 recall (patterns that match nothing), and the
  corrector repeated the same rule in 5 of 6 corrections for CWE-415.
- The rule was accepted on the train split (recall 54%, 0 FP, threshold 50%); the test
  split was only used to report the number.
- CWE-416 had been set aside as a target (see below); this result comes from the last run
  on it and does not change that decision by itself.

## Data available per CWE (2026-09-29)

Dataset (`datasets/cwes_mixed`, Juliet) and detector v1 logs (`logs/dataset/QWEN_CODE`,
Qwen2.5-Coder-3B Q4_K_M, generic prompt). Flow variants counted with `split.flow_variant`.

| CWE | BAD / GOOD files | Flow variants | BAD flagged | GOOD flagged (false positive) | Findings in BAD / GOOD |
|---|---|---|---|---|---|
| 401 (memory leak) | 976 / 976 | 42 | 973/974 | 361/972 (37%) | 973 / 488 |
| 415 (double free) | 380 / 380 | 42 | 373/375 | 230/379 (61%) | 373 / 242 |
| 416 (use after free) | 150 / 150 | 20 | 150/150 | 37/149 (25%) | 150 / 37 |
| 457 (uninitialized variable) | 616 / 616 | 20 | 598/599 | 104/616 (17%) | 598 / 191 |
| 476 (NULL dereference) | 386 / 386 | 38 | 383/384 | 115/385 (30%) | 383 / 123 |

External baseline (official Semgrep packs, test split of seed 0; see above): only
`p/security-audit` detects anything, on CWE-401 (recall 15.6%, precision 26.7%) and CWE-415
(recall 7.7%, precision 100%); all packs are at 0% on CWE-416, 457 and 476.

Rule synthesis has **only been run on CWE-416**. There is no synthesis data for the other
four CWEs. The other CWEs have 2.5-6.5 times more files than CWE-416 (380-976 pairs vs
150), which gives a larger held-out test set. The v1 detector flags almost every BAD file
in all of them; its weakness is false positives (17% on 457 up to 61% on 415). Detector v2
has only been run on CWE-416 (worse than v1 there, see above).

## Status of CWE-416

Decision (2026-09-29, before the combo D template run above): CWE-416 is set aside as a target for new runs. It stays in the
results as a negative case: with combos A-D, the YAML and spec formats, the feedback aids,
best-of-N and the v2 findings, no run was accepted (best held-out test: recall 58.5% /
precision 42.9% with 32 FP in YAML, or recall 14.6% / precision 100% in spec). The runs,
logs and docs remain and the decision can be reversed. CWE-416 also has the fewest files,
so it is the weakest CWE to compare on.

## Next steps

1. **CWE-415 and CWE-476 first** (closest to 416 in shape): combo C, seed 0, 6 fixes, both
   `--format yaml` and `--format spec`, feedback v3. 415 is the simplest to express
   (`free($P)` followed by another `free($P)`), so it shows whether the failure is specific
   to use-after-free or general. Needs detector findings for those CWEs: the v1 logs
   already exist (`logs/dataset/`), so no new detector run is needed.
2. Depending on step 1: repeat with 2 more seeds and combos B/D for the CWE that gets
   furthest; then 401 and 457 (harder to express, larger datasets).
3. Decide with the advisor whether to keep the current research question or add
   **predefined strategy templates** written by us (e.g. a taint template with slots for
   source/sink/sanitizer) that the model only fills in. Not to be confused with the spec
   format, which is already implemented: in spec mode the model still chooses the
   strategy (search or taint) and writes every pattern, and the code only builds the YAML.
   Templates would move the strategy knowledge from the model into the code, which changes
   methodological principle 1 (the models generate the rules) and has not been done.
4. Change `_score` (ranking of attempts, see changes.md phase 7) if the decision is to rank
   by precision and recall instead of by false positives first.
5. Critic and merge only when at least one rule has been accepted.
6. Detector v2: run on the other CWEs only if step 1 shows the example quality matters;
   on CWE-416 it did not help.
7. Ablation table for the thesis from the runs already made: no aids, feedback v2/v3, spec
   format, larger model, best-of-N, v2 findings, baseline packs.
8. Fix `python -m src.config --download` on the Windows console (replace the "✓" character).

## Environment notes (GTX 1060 machine, Windows)

- `llama-cpp-python` with CUDA (`sm_61`, CUDA 12.4) must be built inside a Visual Studio
  developer environment (`vcvars64.bat`), otherwise Ninja does not find `cl.exe`.
- `python -m src.config --download` crashes at the final `print("✓ ...")` on the default
  Windows console (cp1252, `UnicodeEncodeError`) after the file is already saved.
  Workaround: `PYTHONUTF8=1`.
- `pytest`: 36 passed (~40 s).

## Combo D, strategy template, CWE-416 (`20260929-233004`) - first accepted rule

Format `template`, combo D (Qwen3-Coder-30B-A3B), seed 0, v1 findings (126). Accepted at
attempt 1 (train: recall 53.6%, 0 FP). Held-out test: **recall 48.8% (20/41 cases),
precision 100%, 0 FP** (`rules/accepted/D/cwe-416.yaml`).

- The rule is the model's own output (raw response in the run log). Its resemblance to the
  gate fixture comes from the template strategy (event / uses / resets, taint by side
  effect), which we wrote for this arm.
- It belongs to the **template arm** (changes.md, phase 8), where the strategy is given by
  us, and must be reported separately from yaml/spec. One seed, one run: an indication.
- Variants 63/64 are unreachable for Semgrep OSS and the seed-0 test split includes 63, so
  part of the missing recall is a ceiling, not a model failure.

## Ensemble by greedy set cover (`src/pipeline/ensemble.py`), CWE-416

114 distinct candidates from all runs; 53 valid on train, 23 with recall > 0, but only **one**
with 0 FP (the rule above). The cover therefore has one rule and the union equals it
(test recall 48.8%, 0 FP). The hypothesis "many narrow safe rules cover different variants"
did not hold here: the 0-FP rules of the yaml/spec arms have train recall 0% (their test
recall came from the test variants, not from generalization), and the rules with recall
have 6-104 FP. The tool is ready for `--max-fp > 0` and for other CWEs.
