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

## Real-world negatives (Git source), CWE-416, 2026-10-04

Reference code: `git/git` at commit `8103b44651` (644 `.c` files, 447 KLOC), split by file hash
into 446 train files (287.7 KLOC) and 198 test files (111.9 KLOC), seed 0. The code is assumed
correct: every match is an alert. Gate and feedback changes are in changes.md, phase 10.

**The accepted rule of combo D (template arm)** raises 2.15-2.19 alerts/KLOC on the train side
and 2.54-2.61 on the test side (about 900 alerts in all), against 0 false positives on Juliet.
In a random sample of 40 alerts none was a real use after free (24 sequences of `free` on sibling
fields in release functions, 10 loops over different elements, 5 reassignments by wrappers such
as `xstrdup`, 1 correct callee). Upper bound of its precision on this code: about 7.5% (95%).

**Combo C, template, seed 0, 6 fixes, `--negatives ../git --max-negative-rate 0.1`**
(log `logs/runs/c416_negatives_seed0.log`, candidates `rules/candidates/C/CWE-416/20261004-150835`).
**Interrupted**: attempt 5 took 2729 s (the others 18-30 s; cause unknown) and the process hit
the 50 minute limit during attempt 6, so there is no run JSON. Attempts as printed:

| Attempt | Outcome |
|---|---|
| 0 | rejected before the gate: lint (`printLine` copied from the example) |
| 1 | train recall 100%, 906 Juliet FP, 38 real-world alerts (0.13/KLOC) |
| 2 | exactly the same rule as attempt 1 (not re-tested) |
| 3 | recall 100%, 854 FP, 32 real-world alerts (0.11/KLOC) |
| 4 | recall 100%, 516 FP, 12 real-world alerts (0.04/KLOC) |
| 5 | rejected before the gate: `taint.sinks[1].focus must be a metavariable` (2729 s) |

Final step redone by hand with the saved rules (same split, `_score`): best on train = the
854-FP rule; **held-out test: recall 100%, precision 25.9%, 266 FP, 4 real-world alerts
(0.04/KLOC)**. It is the same test result as the earlier combo C template run
(`20260929-171815`). Not accepted. The replay also graded attempts 0 and 2, which the real
run skipped; it does not change the choice (they match attempt 1).

What it shows (one partial run, no conclusion about the corrector):
- The loop with real-world negatives and counterexamples works end to end: the per-attempt
  real-world alerts are in the output and in the corrector's feedback.
- The two kinds of false positive are independent. This rule has recall 100% and 854 FP on
  Juliet but only 0.11 alerts/KLOC on Git (narrow on real code), while the accepted D rule has
  0 FP on Juliet and 2.1 alerts/KLOC on Git. A gate with only one of them accepts a rule that
  the other would reject.
- Juliet false positives went 906 -> 854 -> 516 over attempts 1-4. Without counterexamples
  the same combo and seed stayed at 854 between attempts 2 and 3 (changes.md, phase 3), but a
  single run does not tell whether the snippets caused the drop.

The combo D run with the same options was killed by the system for low memory before the first
attempt (the 30B model needs ~16.4 GB and 18.7 GB were free); it has no result.

## Combo C, template, real-world negatives: complete run, 5-fold cross-validation, CWE-415 (2026-10-04/05)

All with `--format template --seed 0 --max-fix-attempts 6 --negatives ../git --max-negative-rate 0.1`
(Git `8103b44651`, 446 train / 198 test files), Qwen3-4B-Instruct-2507 Q6_K as generator and
corrector. Rules under `rules/negatives/` and `rules/crossval/`, run logs in
`logs/synthesis/C/`, summary in `logs/crossval/C/CWE-416/20261004-232956.json`, console output
in `logs/runs/c416_negatives_seed0_rerun.log`, `c416_cv5.log`, `c415_negatives_seed0.log`.

**CWE-416, seed 0, complete run** (`20261004-224705`; it repeats the interrupted run above and
gives the same attempts, as expected at temperature 0): attempts 1/3/4 reach recall 100% with
906/854/516 Juliet false positives and 38/32/12 real-world alerts; attempt 6 ends in a Semgrep
parse error. Best on train: attempt 3. **Held-out test: recall 100%, precision 25.9%, 266 FP,
4 real-world alerts (0.04/KLOC). Not accepted.** Model calls took 282-434 s each (the earlier
combo C runs took 18-30 s). The 600 s limit was not reached. The cause is unknown; the GPU is
shared with other programs on this machine (not checked in this run).

**CWE-416, 5-fold cross-validation by variant** (each variant tested once, 4 per fold):

| Fold | Test variants | Accepted | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 0 | 06, 11, 16, 18 | no | 100% | 23.9% | 204 | 0.00 |
| 1 | 08, 09, 12, 63 | no | 0% | - | 0 | 0.00 |
| 2 | 02, 03, 05, 17 | no | 0% | - | 0 | 0.00 |
| 3 | 04, 14, 15, 64 | no | 0% | - | 0 | 0.00 |
| 4 | 01, 07, 10, 13 | no | 0% | - | 0 | 0.00 |

**Accepted in 0 of 5 folds. Mean test recall 20.0% +- 44.7%** (one fold at 100%, four at 0%).
Precision exists only for fold 0 (23.9%). In folds 1-4 every attempt that reached the gate was a
valid rule that matched nothing (recall 0%, 0 FP, 0 alerts), or was rejected before the gate
(copied names, `not` lists that are empty, repeated rules). The rule of fold 0 found every case
with 204 false positives on Juliet: the same profile as the 4B model had in the single split
(its rule was not inspected here).

**CWE-415, seed 0, complete run** (`20261005-002007`): attempts either match nothing (recall 0%,
0 FP, 0 alerts) or are rejected before the gate (duplicate `uses` key, empty `not` list, repeated
rule). **Test recall 0%, not accepted.** Same as the earlier combo C template
run of this CWE.

What these runs say, with their limits (one seed per fold, one model):
- Over the whole of CWE-416 the 4B model does not write a usable rule in the template arm: the
  single-split 100% recall (precision 25.9%) was one fold in five, and the other four found
  nothing. The mean recall of 20% is not a recall of the method but the average of a rule that
  finds everything with many false positives and rules that find nothing.
- Real-world alerts are not the binding constraint for this model: its rules are either broad on
  Juliet or empty, and raise 0.00-0.13 alerts/KLOC on Git. They matter for the combo D rule.

## Combo D, template, real-world negatives: complete run, 5-fold cross-validation, CWE-415 (2026-10-05)

Same options as the combo C runs above (`--format template --seed 0 --max-fix-attempts 6
--negatives ../git --max-negative-rate 0.1`), Qwen3-Coder-30B-A3B IQ4_XS (10 of 48 layers on the
GPU) as generator and corrector, 14-61 s per attempt (one of 213 s, the first of each run 125 s
with the model load). Rules under `rules/negatives/` and `rules/crossval/`; **the accepted rule
`rules/accepted/D/cwe-416.yaml` of 2026-09-29 was not touched**. Console output in
`logs/runs/d416_negatives_seed0.log`, `d416_cv5.log`, `d415_negatives_seed0.log`; run logs in
`logs/synthesis/D/`; summary `logs/crossval/D/CWE-416/20261005-004132.json`.

**CWE-416, seed 0, complete run** (`20261005-003303`), attempts reaching the gate:

| Attempt | Train recall | Juliet FP | Real-world alerts |
|---|---|---|---|
| 1 | 54% | 0 | 626 (2.18/KLOC) |
| 3 | 100% | 162 | 1844 (6.41/KLOC) |
| 4 | 54% | 0 | 629 (2.19/KLOC) |
| 5 | 87% | 6 | 681 (2.37/KLOC) |

Attempts 0, 2 and 6 were rejected before the gate (empty `not`, copied name, Semgrep parse
error). Attempts 1 and 4 are the profile of the rule accepted on 2026-09-29 (recall 54%, 0 FP):
with the real-world limit **it is no longer accepted**. Best on train: attempt 5. **Held-out test:
recall 87.8%, precision 85.7%, 6 FP, 297 real-world alerts (2.66/KLOC). Not accepted.**

**CWE-416, 5-fold cross-validation by variant:**

| Fold | Test variants | Accepted | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 0 | 06, 11, 16, 18 | no | 100% | 60.9% | 36 | 7.38 |
| 1 | 08, 09, 12, 63 | no | 100% | 52.9% | 48 | 6.46 |
| 2 | 02, 03, 05, 17 | no | 100% | 55.3% | 42 | 7.04 |
| 3 | 04, 14, 15, 64 | no | 88.9% | 80.0% | 6 | 2.66 |
| 4 | 01, 07, 10, 13 | no | 57.1% | 100% | 0 | 2.01 |

**Accepted in 0 of 5 folds. Mean test recall 89.2% +- 18.6%, mean precision 69.8% +- 19.9%, mean
real-world rate 5.11 +- 2.56 alerts/KLOC (limit 0.1).** Compared with combo C (mean recall 20.0%):
the 30B model finds a rule that detects most of every group of variants, including the unseen
ones, so on Juliet the 2026-09-29 result was not luck of the split; what the models do not
write is a rule that is quiet on real code.

**CWE-415, seed 0** (`20261005-011941`): attempt 1 is a valid rule that matches nothing (recall
0%, 0 FP); the corrector then returned exactly that rule five times (attempts 2-6).
**Test recall 0%, not accepted**, as in the earlier combo D template run.

What the real-world gate and the counterexamples did (three runs, 7 attempts each, one seed per
fold; no ablation of the snippets was made):
- **No attempt that detected anything came close to the limit.** The lowest real-world rate
  among attempts with recall above 0, in all D runs, was 1.64 alerts/KLOC (16 times the limit);
  the usual value is 1.9-2.6 for the recall-50% rules and 6-7 for the recall-100% ones. The
  corrector, which received the alerts with the code around them, did not remove the pattern
  that dominates them (a `free` of a field followed by other statements in a release function;
  changes.md phase 10) within 6 corrections.
- Alerts do not predict Juliet quality: the recall-100% rules of folds 0-2 raise 6.5-7.4
  alerts/KLOC, the recall-57% rule of fold 4 raises 2.0, and both kinds have 0.1 as limit.
- On Juliet alone the loop works better than any earlier combination (cross-validated recall
  89%), and the failures that remain are semantic: repeated rules (up to 5 in a row in
  CWE-415), names copied from the example, and empty or misplaced `not` lists.
- Variants 63 and 64 are in the test sets of folds 1 and 3, and fold 1 still reaches recall 100%.
  This does not show that the rule follows the flow across files: the gate counts a match anywhere
  in a BAD file of the case as a detection (changes.md, gate), so a rule can "detect" a 63 case by
  matching another statement of its file. Not checked here.

## What the best combo D rule fires on in Git, and whether it finds real fixes (2026-10-05)

Rule analysed: attempt 5 of the combo D run `20261005-003303` (recall 87% on train, 6 Juliet FP;
709 alerts on the whole Git tree in directory mode, 2.4/KLOC). Scripts were run from the scratchpad,
not versioned.

**Where its alerts are.** 562 of 709 (79.3%) are on a line that is itself a `free()` call: 309 with no
other `free` in the 6 lines before and 253 with one. 67 (9.4%) are assignments, 64 are other calls,
16 other statements. 367 (51.8%) are in a function whose name contains release/free/clear/destroy/
cleanup/reset/...: a correlation, because those functions are mostly sequences of `free`. So the
dominant defect is structural: the use patterns (`$P->...`, `$F($P, ...)`...) also match the statement
that marks the variable. A minimal reproduction with a generic sink `$F($X, ...)` shows it: after
`mark(p)` the next `mark(p)` is reported, and so is the first one (tests/test_gate.py). Even without
these alerts the rule would raise about 0.5 alerts/KLOC, five times the limit, so this is the largest
cause and not the only one (the rest: reassignment by wrappers, loops).

**Does it find real bugs?** 16 commits of Git since 2018 whose subject names a use-after-free, a double
free or a freed pointer (filter: `use[- ]after[- ]free|double[- ]free|\bfreed\b|memory after`, no merges;
`dangling` was in the first filter and was dropped after seeing that most of the 15 commits it added were
about refs (dangling symrefs) or docs; two of them were about memory (`alloc: fix dangling pointer...`,
`builtin/help: fix dangling reference...`) and left out as well. This choice was made after looking at the
output). The changed
`.c` file of each commit was taken before and after the fix and the rule run on both; an alert counts if
it is within 10 lines of a line changed by the fix.

| Rule | Commits with an alert near the fixed lines (before) | ...and gone after the fix |
|---|---|---|
| accepted 2026-09-29 (`rules/accepted/D/cwe-416.yaml`) | 5/16 | 2/16 |
| attempt 5 above | 5/16 | 3/16 |

The chance level is high, not low: 3% of the lines of those files are within 10 lines of an alert, but a
line with `free()` has an alert within 10 lines in 120/334 = 36% of the cases (121/334 for the second rule),
and a fix of a use after free is made around `free()`. **5/16 (31%) is not above 36%: the rules do not
point at these fixes better than at any `free()`**. Limits: 16 commits, one file each, window of 10 lines
and the same line numbers for the "after" file (approximate), no manual check of what each alert was.
`rules/accepted/D/cwe-416.yaml` is the 2026-09-29 rule.

## Combo D, 5-fold cross-validation with seed 1: interrupted after 2 folds (2026-10-05)

`crossval --combo D --cwe CWE-416 --folds 5 --seed 1` (same options as seed 0). The seed changes the
fold assignment, the examples shown to the generator and also the split of the real-world files (455
train / 189 test files instead of 446 / 198). The system stopped the run for low memory during fold 3
(a game and other programs were open at the same time; a leftover process of the run was still holding
13 GB and was ended by hand). No summary file exists. The two finished folds (run logs in
`logs/synthesis/D/CWE-416/20261005-111138.json` and `-112149.json`, console output in
`logs/runs/d416_cv5_seed1.log`):

| Fold | Test variants | Accepted | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 0 | 01, 04, 11, 12 | no | 57.1% | 100% | 0 | 1.61 |
| 1 | 06, 09, 14, 17 | no | 100% | 22.0% | 354 | 0.07 |

Fold 1 is the first D result under the real-world limit (0.07 alerts/KLOC, limit 0.1), but with 354
Juliet false positives, so it was not accepted either. It shows again that the two kinds of false
positive move independently. Two folds of one seed are not a result; seed 2 was not started.

## Combo D, template, with the source-line warning and with `not_inside` (2026-10-05)

Both runs: CWE-416, seed 0, 6 fixes, `--negatives ../git --max-negative-rate 0.1`, `--rules-dir rules/negatives`,
combo D. Compared with the run `20261005-003303` above (no warning).

**With the warning only** (`20261005-141707`, console `logs/runs/d416_negatives_seed0_warning.log`): the warning
reached the corrector (82-93% of the alerts of the recall-54% rule were on a line one of its own sources
matches). Every attempt that reached the gate had recall 54%, 0 Juliet FP and 559-645 real-world alerts
(1.94-2.24/KLOC); 1 of 7 attempts was a repeated rule. Best on train: attempt 2. **Held-out test: recall 48.8%,
precision 100%, 0 FP, 257 real-world alerts (2.30/KLOC). Not accepted** (the same test numbers as the rule
accepted on 2026-09-29, which is the profile the corrector kept returning to).
The model understood the warning in words ("it matched the free() call itself as a use") and wrote the right idea
in every use, `"not": ["free($P)"]`. That cannot work: Semgrep's `pattern-not` only excludes a match equal to the
pattern, and the sink `$P->...` matches the argument `x->f` inside `free(x->f)`, not the call. Diagnostic (a
hand-made copy of attempt 5 with `pattern-not-inside: free(...)` instead of `pattern-not`, not a result): same
train recall 54% and 0 Juliet FP, real-world alerts 637 -> 116 (2.21 -> 0.40/KLOC), none left on a source line.

**With `not_inside` in the template** (template v2, changes.md phase 13; `20261005-143203`, console
`logs/runs/d416_negatives_seed0_notinside.log`): all 7 attempts reached the gate with recall 54% and 0 Juliet FP;
real-world alerts 460-474 (1.60-1.65/KLOC), 95% of them on a source line (438-447 of 460-474). **No attempt wrote
`not_inside` in a use**; every use kept `"not": ["free($P)"]`, and the corrector's explanations say "added a `not`
condition to exclude the free() call". Best on train: attempt 1. **Held-out test: recall 48.8%, precision 100%, 0 FP,
226 real-world alerts (2.02/KLOC). Not accepted.**

Reading (one seed, one model): the missing operator was part of the problem, because without it the right idea is
inexpressible, but making it available is not enough: the 30B model keeps the form it wrote in the first attempt
and the prompt text that says `not` only matches equal patterns did not change what it writes. The lower real-world
rate of this run (1.6 against about 2.2/KLOC) comes from a different first rule, not from `not_inside`, since it was
never used. Template v1 and v2 results must not be mixed.

## Combo D, final configuration (template v2 + source-line warning + ineffective-`not` feedback), seed 0 (2026-10-05)

`--format template --max-fix-attempts 6 --negatives ../git --max-negative-rate 0.1`, combo D. The feedback now also says,
when real-world alerts sit on a source line and a use has a `not` equal to a source pattern, that such a `not` does not
remove them and that `not_inside` does (changes.md phase 14). Console: `logs/runs/d416_final_seed0.log`,
`d416_final_cv5_seed0.log`; summary `logs/crossval/D/CWE-416/20261005-150232.json`.

**Complete run** (`20261005-145350`): attempts at the gate reach recall 54%/1.61 alerts per KLOC, 100% (162 Juliet FP,
6.43/KLOC), 87% (6 FP, 1.80/KLOC) and 100% (6 FP, 1.84/KLOC). Best on train: attempt 6. **Held-out test: recall 100%,
precision 87.2%, 6 FP, 251 real-world alerts (2.24/KLOC). Not accepted.**

**5-fold cross-validation:**

| Fold | Test variants | Accepted | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 0 | 06, 11, 16, 18 | no | 85.7% | 100% | 0 | 2.73 |
| 1 | 08, 09, 12, 63 | no | 100% | 52.9% | 48 | 6.55 |
| 2 | 02, 03, 05, 17 | no | 57.1% | 100% | 0 | 1.16 |
| 3 | 04, 14, 15, 64 | no | 100% | 52.9% | 48 | 6.44 |
| 4 | 01, 07, 10, 13 | no | 85.7% | 100% | 0 | 2.28 |

**Accepted in 0 of 5 folds. Mean test recall 85.7% +- 17.5%, mean precision 81.2% +- 25.8%.** The first cross-validation
of combo D (template v1, no warning) gave recall 89.2% +- 18.6% and precision 69.8% +- 19.9%: the same level.

**Did the model use `not_inside`?** Over the six runs (plain + 5 folds, 42 attempts) it wrote a `not_inside` in a use in 21
attempts, and the ineffective-`not` feedback was shown in 11 reports. Without that feedback it never wrote it (0 of 7
attempts in the run above). So the direct feedback changed what the model writes. The effect on the alerts is partial: the
lowest real-world rate among attempts with recall above 0 was 1.04 alerts/KLOC (median 2.14; limit 0.1). What the model
writes is `"not_inside": ["free($P)"]`, repeating the metavariable `$P` of the use: it only excludes a use inside a `free`
whose argument is the same variable, and `x->f` inside `free(x->f)` is not (the hand-made diagnostic that reached 0.40/KLOC
used `free(...)`). In the rule with 1.04/KLOC 64% of the alerts are still on a source line (191 of 298), against 82-95% in
the earlier runs. Some attempts that used it lost all recall (a rule with both `not` and `not_inside` of `free($P)` on its
uses matched nothing). The next level of feedback (explaining the metavariable) was not added: it would be giving the rule.

## Cross-validation runs that were interrupted or ran unnoticed (2026-10-05)

**Seed 2, complete, with the source-line warning, template v1** (`logs/crossval/D/CWE-416/20261005-115707.json`,
console `logs/runs/d416_cv5_seed2.log`). It was started by the shell script of the interrupted seed-1 run when
I ended that run's Python process by hand (the script outlived the memory stop and went on to the next seed); it ran to
the end in the background, 11:57-13:07, and I did not notice it until later. The modules were loaded when it started,
after the warning of phase 12 and before `not_inside` (phase 13): every report has `negative_on_source`, no response has
a `not_inside`. It is a valid cross-validation of the configuration "template v1 + warning":

| Fold | Test variants | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|
| 0 | 06, 08, 15, 16 | 100% | 57.1% | 42 | 6.36 |
| 1 | 05, 07, 12, 14 | 57.1% | 100% | 0 | 1.86 |
| 2 | 01, 11, 18, 63 | 44.4% | 100% | 0 | 2.26 |
| 3 | 03, 04, 09, 13 | 57.1% | 100% | 0 | 1.67 |
| 4 | 02, 10, 17, 64 | 88.9% | 80.0% | 6 | 1.74 |

Accepted 0/5; mean recall 69.5% +- 23.7%, precision 87.4% +- 19.0%, real-world 2.78 +- 2.02 alerts/KLOC. The real-world
split of this seed differs from seed 0 (seed-dependent), so the rates are not paired with the seed-0 runs.

**Seed 1, template v1, no warning: 2 folds** (run stopped by the system, see above): recall 85.7% / precision 100% /
1.61 alerts/KLOC and recall 100% / precision 22.0% / 0.07 alerts/KLOC (already listed).

**Seed 1, final configuration: 1 fold** (stage D2, stopped by the system during fold 2; console
`logs/runs/d416_final_cv5_seed1.log`): fold 0, variants 01, 04, 11, 12: recall 85.7%, precision 100%, 0 FP, 231 real-world
alerts (1.86/KLOC). **Seed 2 of the final configuration was never run.** In this stop the leftover script started the seed-2 run
as soon as I ended the seed-1 process, and I ended both by hand within a minute.

## Combo D, final configuration, cross-validation seeds 1 and 2 (2026-10-06)

Run with `scripts/run_crossval_seeds.ps1 -Seeds 1,2` (combo D, template v2, source-line warning and `not` feedback, 5 folds,
6 fixes, `--negatives ../git`); both seeds completed without being stopped. Summaries
`logs/crossval/D/CWE-416/20261006-001149.json` (seed 1) and `20261006-005913.json` (seed 2); logs
`logs/runs/crossval_D_CWE-416_seed{1,2}_20261006-001149.log`.

| Seed | Fold | Test variants | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 1 | 0 | 01, 04, 11, 12 | 85.7% | 100% | 0 | 1.82 |
| 1 | 1 | 06, 09, 14, 17 | 57.1% | 100% | 0 | 1.63 |
| 1 | 2 | 02, 03, 15, 18 | 57.1% | 100% | 0 | **0.105** |
| 1 | 3 | 13, 16, 63, 64 | 100% | 55.3% | 42 | 6.81 |
| 1 | 4 | 05, 07, 08, 10 | 57.1% | 100% | 0 | 1.61 |
| 2 | 0 | 06, 08, 15, 16 | 100% | 57.1% | 42 | 7.02 |
| 2 | 1 | 05, 07, 12, 14 | 57.1% | 100% | 0 | 0.37 |
| 2 | 2 | 01, 11, 18, 63 | 44.4% | 100% | 0 | 1.93 |
| 2 | 3 | 03, 04, 09, 13 | 57.1% | 100% | 0 | 2.13 |
| 2 | 4 | 02, 10, 17, 64 | 100% | 81.8% | 6 | 1.90 |

Seed 1: accepted 0/5, recall 71.4% +- 20.2%, precision 91.1% +- 20.0%, real-world 2.40 +- 2.56 alerts/KLOC.
Seed 2: accepted 0/5, recall 71.7% +- 26.3%, precision 87.8% +- 18.9%, real-world 2.67 +- 2.53 alerts/KLOC.
Seed 2 has the same folds and real-world files as the earlier run with template v1 + warning (recall 69.5% +- 23.7%,
precision 87.4% +- 19.0%, 2.78 +- 2.02): the differences are within the spread over folds.

**Use of `not_inside`** (70 new attempts): written in 25, the ineffective-`not` feedback was shown in 20 reports. Over the
three seeds of the final configuration (112 attempts), 42 attempts reached the gate with a `not_inside`; of the 31 of them
with recall above 0, 30 use a pattern with the use's own metavariable (typically `free($P)`: lowest real-world rate 1.04, median
2.37 alerts/KLOC) and one uses a new one.

**Seed 1, fold 2, attempt 6** (`logs/synthesis/D/CWE-416/20261006-003406.json`, candidate under `rules/crossval/`): attempts 0-5
had train recall 51%, 0 Juliet FP and 585-671 real-world alerts (2.1-2.4/KLOC, 84-94% on a source line); attempt 1 was
rejected before the gate (copied name). Attempt 6 wrote `"not": ["free($P)"], "not_inside": ["free($X)"]` on its six uses
(`$P[...]`, `$P->...`, `*$P`, and `memcpy`, `strcpy`, `strncpy` with `$P` as an argument), with the resets `$P = malloc(...)`,
`calloc`, `realloc`, `NULL` and `$P = $Q`. Train: recall 51%, 0 Juliet FP, 38 real-world alerts (0.138/KLOC), none on a source line:
not accepted (limit 0.1). **Held-out test: recall 57.1%, precision 100%, 0 FP, 13 real-world alerts (0.1047/KLOC).** Neither the
`$X` nor `free(...)` was given to the model; the diagnostic of 2026-10-05 used `free(...)` by hand. One attempt in 31, half of the
cases detected, one seed: an observation that the neighbourhood of the limit is reachable, not an accepted rule.

## Alert-by-alert review of the rule nearest to the limit (2026-10-07)

The rule of seed 1, fold 2, attempt 6 (finding 8 of findings.md) raises 38 alerts on the train files and 13 on the test files of
Git, 51 in the 644 `.c` files: few enough to read **every** one. Each was read with 12 lines before and 3 after the alert and,
where that was not enough, with the rest of the function and the helpers it calls (checked in the Git source). The list, with a
category and a reason per alert, is `docs/alert_review_seed1_fold2_attempt6.csv`.

| Why the alert is not a use after free | Alerts |
|---|---|
| a loop moves on to another element (index or pointer advances after the `free`) | 12 |
| the pointer is assigned again by a macro (`FLEX_ALLOC_STR`, `CALLOC_ARRAY`, a `for_each` iterator) | 11 |
| the slot of the freed element is overwritten (`MOVE_ARRAY`, `memmove`: remove-from-array idiom) | 9 |
| a different object was freed (the elements, then the array; or a sibling field) | 8 |
| the pointer is assigned again through an out-parameter (`git_config_string(&x->f, ...)`, `&content`) | 6 |
| the path is unreachable (`die()` does not return; `continue` after the `free`) | 2 |
| assigned again in place (`free(p); p = xmalloc(sizeof(*p))`) | 1 |
| checked: not a double free (`string_list_clear` on a list that does not own its strings) | 1 |
| the pointer value is compared after the `free` and never dereferenced (`pack-objects.c:2945`; undefined by the letter of C, deliberate and harmless) | 1 |
| **real use after free** | **0** |

**0 real bugs in 51 alerts**, with one borderline benign case. With every alert read, the precision of this rule on Git is 0 of 51
(no sampling error; the limit is that the reviewer is one person and that a bug that the reading missed would count as a false
positive). The categories show what the rule does not model: reassignment by macros and out-parameters, loops that advance, and the
remove-from-array idiom. They are the same families as in the 40-alert sample of the rule accepted on 2026-09-29 and in the 709 alerts
classified by line type, so the larger, noisier rules were not read alert by alert: that would be several hundred to a few thousand alerts per rule.

The review covers the alerts the rules **raise** (false positives). It says nothing about what they **miss** (false negatives);
that is measured only on Juliet and on the 16 fix commits.

## Combo D, final configuration, cross-validation seeds 3 and 4 (2026-10-07)

`scripts/run_crossval_seeds.ps1 -Seeds 3,4` (combo D, same options as seeds 1 and 2). Summaries
`logs/crossval/D/CWE-416/20261007-195027.json` (seed 3) and `20261007-204711.json` (seed 4). Both completed.

| Seed | Fold | Test variants | Test recall | Test precision | Test FP | Real-world alerts/KLOC |
|---|---|---|---|---|---|---|
| 3 | 0 | 09, 12, 14, 17 | 100% | 25.0% | 156 | 0.009 |
| 3 | 1 | 03, 04, 05, 11 | 100% | 53.8% | 48 | 6.36 |
| 3 | 2 | 07, 13, 18, 64 | 88.9% | 80.0% | 6 | 2.33 |
| 3 | 3 | 01, 06, 10, 63 | 100% | 56.3% | 42 | 6.53 |
| 3 | 4 | 02, 08, 15, 16 | 85.7% | 100% | 0 | 2.58 |
| 4 | 0 | 07, 16, 18, 63 | 44.4% | 100% | 0 | 1.57 |
| 4 | 1 | 01, 13, 17, 64 | 88.9% | 80.0% | 6 | 1.77 |
| 4 | 2 | 04, 11, 12, 14 | 85.7% | 100% | 0 | 2.24 |
| 4 | 3 | 02, 05, 10, 15 | 57.1% | 100% | 0 | 2.15 |
| 4 | 4 | 03, 06, 08, 09 | 0% (no valid rule) | - | - | - |

Seed 3: accepted 0/5, recall 94.9% +- 7.0%, precision 63.0% +- 28.4%, real-world 3.56 +- 2.82 alerts/KLOC. Seed 4: accepted 0/5, recall
55.2% +- 36.2% (the fold without a valid rule counts as 0), precision 95.0% +- 10.0% and 1.93 +- 0.32 alerts/KLOC over the 4 folds with a rule.

Seed 3, fold 0 is the broad kind of rule: 0.009 alerts/KLOC on Git with 156 Juliet false positives, so it is far under the limit
without being acceptable. The near-miss of seed 1 (0.105 alerts/KLOC, 0 Juliet false positives) did not reappear in these ten folds.

**Pooled over the 25 folds of the final configuration** (seeds 0 to 4): 0 accepted; recall 75.8% +- 25.6 (median 85.7%, range 0-100%);
precision 83.1% +- 23.1 over 24 folds (median 100%); real-world 2.92 +- 2.29 alerts/KLOC (median 2.14); 14 of 24 folds with 0 Juliet
false positives, and among those 14 (recall above 0) the median real-world rate is 1.88 alerts/KLOC. Three folds are under 0.5
alerts/KLOC: seed 1 fold 2 (0.105, 0 false positives), seed 2 fold 1 (0.37, 0 false positives) and seed 3 fold 0 (0.009, 156 false positives).

**Use of `not_inside`, five seeds** (189 attempts, which include the single complete run and one interrupted fold): 76 reached the gate
with a `not_inside`; the ineffective-`not` feedback was shown in 53 reports. Of the 56 with recall above 0, 55 use the use's own
metavariable (median 2.40 alerts/KLOC) and one a new one (seed 1, fold 2, attempt 6: 0.138).

## Comparison `nodocs`: the Semgrep documentation left out of the prompts (2026-10-08, incomplete)

`scripts/run_crossval_seeds.ps1 -Seeds 1,2 -NoDocs -MinFreeGB 19` (combo D, template v2, final configuration, `--no-docs`: the
1,278-character pattern-syntax section is replaced by a one-sentence note). The system stopped the run for low memory in the
second seed: **seed 1 is complete (5 folds), seed 2 has 1 of 5 folds**, so the planned 10 paired folds were not reached. Summary of
seed 1: `results/crossval/D/CWE-416/20261007-230503.json`; the finished fold of seed 2 is only in its run log.

Paired with the final configuration on seed 1 (same folds, same real-world files), `python -m src.pipeline.compare`:

| Metric | with docs | no docs | no docs - with docs | 95% interval | no docs better / worse (folds) |
|---|---|---|---|---|---|
| recall | 0.714 | 0.727 | +0.013 | -0.171 to +0.242 | 1 / 2 |
| precision | 0.911 | 0.848 | -0.063 | -0.257 to +0.068 | 1 / 1 |
| Juliet false positives | 8.4 | 10.8 | +2.4 | -18.0 to +25.2 | 1 / 1 |
| real-world alerts/KLOC | 2.396 | 2.514 | +0.118 | -3.03 to +3.51 | 2 / 1 |
| accepted folds | 0 | 0 | 0 | - | - |

By the criterion of `ablation_plan.md` (interval excluding 0 and a difference of at least 0.10 recall or 25% of the alerts), **no
effect was detected**. Fold 1 has identical recall, false positives and alert rate with and without the documentation, which
suggests the model reached the same rule there. The other folds move in both directions: fold 0 recall 0.86 to 0.57, fold 2 recall 0.57 to
1.00 with 42 false positives, fold 3 alerts 6.81 to 1.76/KLOC. The near-miss of seed 1, fold 2 (0.10 alerts/KLOC with the
documentation) did not reappear without it: it was one attempt in 31, and changing the prompt changes the whole trajectory of a
deterministic run, so this is an observation about that path and not evidence about the documentation.

One finished fold of seed 2 without documentation (variants 06, 08, 15, 16; run log `20261008-001126.json`): recall 85.7%,
precision 100%, 0 Juliet false positives, 0.48 alerts/KLOC, not accepted. It is the lowest real-world rate among the folds of this
configuration with 0 false positives and high recall, five times the limit; one fold, no comparison drawn.

Limit of this result: 5 paired folds from one seed, and a spread over folds that is larger than the differences one would care about
(recall +-0.2); a null result here means "not detected", not "no effect". The remaining 5 folds of the plan (seed 2) were not run.

### `nodocs` completed: 10 paired folds (2026-10-08)

Seed 2 was finished with `-ResumeSince` (fold 0 reused from the interrupted run, folds 1 to 4 run; no stop this time). Summary
`results/crossval/D/CWE-416/20261008-200024.json`: accepted 0/5, recall 75.2% +- 23.4, precision 80.6% +- 33.4, real-world 0.78 +- 0.60
alerts/KLOC (with the documentation, same seed: 2.67 +- 2.53).

Paired on seeds 1 and 2 (10 folds, same folds and real-world files as the final configuration with documentation),
`python -m src.pipeline.compare`:

| Metric | with docs | no docs | no docs - with docs | 95% interval | no docs better / worse (folds) |
|---|---|---|---|---|---|
| recall | 0.716 | 0.740 | +0.024 | -0.101 to +0.164 | 2 / 4 |
| precision | 0.894 | 0.827 | -0.068 | -0.272 to +0.105 | 2 / 3 |
| Juliet false positives | 9.0 | 23.6 | +14.6 | -13.2 to +54.0 | 2 / 2 |
| real-world alerts/KLOC | 2.533 | 1.649 | -0.883 | -2.774 to +1.021 | 7 / 1 (2 ties) |
| accepted folds | 0 | 0 | 0 | - | - |

By the criterion of `ablation_plan.md` **no effect was detected**: every interval includes 0. The alert rate is the one metric that goes
the same way in most folds (lower without documentation in 7 of 10; -0.88 alerts/KLOC, 35% of the baseline, above the plan's 25% size
but with an interval that includes 0). It is an exploratory signal, and part of it comes from broad rules: in seed 2 fold 1 the
alerts fall from 0.37 to 0.05 per KLOC while the Juliet false positives go from 0 to 176 (the two kinds of false positive move
independently, finding 5). Four other folds of seed 2 do fall without that: 7.02 to 0.48, 1.93 to 1.67, 2.13 to 1.01 and 1.90 to 0.71.
Per the plan, an effect is re-run on seeds 0, 3 and 4 before it is written as a finding; this one was not.

Seed 2 fold 0 without documentation (variants 06, 08, 15, 16) is the rule noted above: recall 85.7%, precision 100%, 0 Juliet false
positives, 0.48 alerts/KLOC, five times the limit. The near-miss of seed 1 (0.105) did not reappear in any `nodocs` fold.

Reading: the 1,278 characters of pattern syntax in the prompt are not what decides the result, which agrees with the expectation of
the plan; the trajectory of a deterministic run changes with any change of the prompt, so single folds can move a lot in both
directions without that being an effect of the documentation. A null result on 10 folds means "not detected" (recall spread over
folds is about 0.2).
