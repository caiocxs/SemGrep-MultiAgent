# Errors found and changes made

Chronological record of what went wrong in the rule-synthesis runs, why, and what was
changed in response. Run numbers and outcomes are in [experiments.md](experiments.md).
Everything here has to be declared in the thesis: each change is either a
**deterministic aid** (improves the feedback the model gets, the rule stays the model's)
or a **format change** (changes what the model has to write). None of them writes or
edits a rule that ends up in the results.

Methodological limits kept throughout: the models write the rules; the gate is
Semgrep + Python with no LLM; prompts contain no CWE- or Juliet-specific hints; the
fixture `tests/fixtures/rules/cwe416_uaf.yaml` is only used to test the gate.

## Phase 1 - combo A (CPU notebook), before this file existed

Source: the first three combo A runs (see experiments.md).

| # | Error observed | Cause | Change | Kind |
|---|---|---|---|---|
| 1 | 4 attempts with `pattern:` holding a list; corrector returned an identical rule | Semgrep only says `is not of type 'string'` | `check_structure` in `rules.py`: explains common schema mistakes in actionable terms | feedback |
| 2 | Corrector resubmitted the same rule with a new explanation | Small model ignores that nothing changed | Repeated-rule detection in `synthesize.py`: the attempt is not re-tested and the feedback says "exactly the same rule as attempt N" | feedback |
| 3 | Multi-line C patterns without `;` | Semgrep answers only `Parse_error` | `check_c_statements`: lists the statements missing `;` | feedback |
| 4 | Rule copied variable/function names from the examples | Overfit to the 3 examples | `lint`: rejects names from the detector findings and Juliet helpers (`printLine`, `CWE..._` names) | feedback |
| 5 | Invented operator `metavariable-patterns` accepted silently by Semgrep | Semgrep ignores unknown keys in some places | Noted as future work; done in Phase 3 (change 8) | - |

## Phase 2 - GTX 1060 machine (Windows), 2026-09-28

Environment problems, fixed or worked around (documented in README.md too):

| # | Error | Cause | Solution |
|---|---|---|---|
| E1 | `setup_windows.ps1 -Gpu` could not find the compiler | `cl.exe` is only on the PATH inside a Visual Studio developer environment | Run the script after `vcvars64.bat` (batch wrapper); llama-cpp-python 0.3.35 built with CUDA `sm_61` |
| E2 | `--download` crashed with `UnicodeEncodeError` on "✓" | Windows console uses cp1252; the file was already saved | Workaround `PYTHONUTF8=1` (code not changed) |
| E3 | Passing the log path through `Start-Process` produced no log | Quote handling of `cmd /c ... > file` | Use a `.bat` file |
| E4 | `Monitor` and `sleep` tool calls rejected | Tool schema not loaded / blocked sleeps | Use `until` loops in background commands |

Results of the first runs of combos B and C (experiments.md) showed that the generator
gets stuck on syntax, so the feedback was improved.

## Phase 3 - feedback improvements

| # | Error observed | Cause | Change (files) | Kind |
|---|---|---|---|---|
| 6 | Combo B: 7 attempts, all with the same `;` error | (model-related) | none; recorded as a result | - |
| 7 | Combo C: gate reported 104 false positives but the feedback listed 5 near-identical lines | Feedback showed the first N matches | `GateReport.feedback` in `gate.py`: groups false positives by matched code, most frequent first, with "and N more like it" | feedback |
| 8 | `metavariable-patterns` (combo A) and other made-up operator names | Semgrep tolerates unknown keys | `check_structure` in `rules.py` rejects keys starting with `pattern`/`metavariable`/`focus` that are not Semgrep operators (`KNOWN_OPERATORS`); `metadata` is skipped | feedback |
| 9 | Combo C seeds 1 and 2: 4-6 of 7 attempts died on `- pattern: *$P` (YAML alias) or `message:` with a colon | PyYAML says "while scanning an alias", which does not tell the model to quote | `normalize` in `rules.py` appends a quoting hint to those YAML errors | feedback |
| 10 | Still failing after 9: taint operators misplaced, repeated rules, `*$P` unquoted even with the hint (combo D, 30B) | The model has to get YAML quoting and operator nesting right | Change 11 | format |

Effect of 7-9 (experiments.md): YAML-syntax attempts dropped from 4 to 2 (seed 1) and
from 6 to 2 (seed 2), but the models moved on to schema mistakes. The larger model
(combo D, Qwen3-Coder-30B-A3B) made the same generic-syntax mistakes, so model size alone
did not fix them.

## Phase 4 - new models

| # | Change | Why |
|---|---|---|
| 12 | Combo D (`configs/combos/combo_d.toml`): Qwen3-Coder-30B-A3B as generator/corrector/merger, 10 of 48 layers on the GPU | Test whether a much stronger code model handles Semgrep where 3-7B models do not (suggested in the model discussion). `llama-cpp-python` 0.3.35 has no `--n-cpu-moe`, so partial layer offload is used |
| 13 | External baseline: `src/pipeline/baseline.py` grades any rule file on the same held-out split; official packs `p/c`, `p/default`, `p/cwe-top-25`, `p/security-audit` | Reference numbers (recall 0% on CWE-416 for all of them) |

## Phase 5 - structured output ("spec" mode)

Problem: across combos A-D the models fail on the *form* of the rule (YAML quoting,
where operators may go, `;`), not only on the idea; they even tried taint mode.

Change 11 (`--format spec`, default remains `yaml`):
- `src/pipeline/spec.py`: the model writes a small JSON with only patterns:
  `{"message", "search": {pattern|either, inside, not, not_inside}}` or
  `{"message", "taint": {sources, sinks, sanitizers}}` (entries: `pattern`, `focus`,
  `by_side_effect`, `not`). The program builds the rule dict, dumps it as YAML (so `*$X`
  gets quoted), and then runs the same `normalize`, `check_structure`,
  `check_c_statements`, `lint` and gate as before.
- Nothing is added, removed or rewritten in the model's patterns; the builder only reports
  problems (unknown keys, empty patterns, `by_side_effect` without `focus`, JSON syntax).
- `prompts/spec_generator.md` and `prompts/spec_corrector.md`: only the "Pattern syntax"
  section of `prompts/semgrep_docs.md` is included (`load_pattern_docs`), plus a short
  description of how search and taint rules match and of the JSON keys. **This
  description is written by us, in generic terms, and paraphrases the official Semgrep
  behaviour (search operators, taint sources/sinks/sanitizers, by-side-effect). It
  contains nothing about any CWE. It goes beyond the earlier decision that prompts
  carry only official Semgrep documentation ("option 1"), so it must be declared, and
  approved, as a decision in the thesis.**
  The only example names used in the JSON examples (`make_tainted`, `sink`, `clean`)
  come from the Semgrep taint documentation.
- The corrector sees the spec JSON as "current rule".
- Run logs record `"format": "spec"`.
- Known limitation: the spec cannot express `metavariable-pattern`, `metavariable-regex`,
  `metavariable-comparison` or nested `patterns`/`pattern-either` inside taint entries.
  It is a subset of what the YAML mode can write; the results should say so.
- Tests: `tests/test_spec.py` (builder, quoting, problem messages, end-to-end loop with
  a fake model). Whole suite: 34 passed.

Outcome of phase 5 (details in experiments.md): YAML-level errors disappeared, but no run
was accepted. The models only used `search` sequences (never `taint`), put alternatives
as text inside a single pattern (`or`, `|`), and used full sequences in `not`. So the
format change removed one class of errors and exposed the next one: the choice of
strategy and operator semantics. No further change has been made yet for that.

## Phase 6 - best-of-N sampling (`--samples N`)

Problem: with temperature 0 each run is one deterministic draw, and the models only
occasionally hit a good strategy (e.g. the combo C run that used taint). A single run
therefore says little about how often a model *can* produce a passing rule.

Change 14 (`synthesize.py`, `llm.py`; default behaviour unchanged):
- `--samples N` runs N independent generator -> gate -> corrector loops with the same
  split and examples. `--temperature T` sets the sampling temperature of generator and
  corrector (0.7 when `--samples > 1` and none is given, because identical samples would
  be pointless). `--stop-on-pass` ends at the first passing sample.
- The **gate picks the winner**, using only the train files (same `_score` as before:
  valid, fewest false positives, then recall). The held-out test files are evaluated once,
  for that winner only, so selection never sees the test set.
- The LLM still writes every rule; nothing is edited by code.
- Run log gains `samples`, `temperature`, `sample_summary` (per sample: attempts, passed,
  best attempt), `samples_passed`, `best_sample`; each attempt has a `sample` index.
  Candidates are saved as `sample<k>_attempt_<n>.yaml`.
- Metric for the thesis: the fraction of samples that pass the gate (`samples_passed / N`)
  per model, format and CWE. Note that best-of-N spends N times the compute of a single
  run; it must be reported next to single-run results, not instead of them.
- Tests: `tests/test_synthesize.py` (independence of samples, temperature passed, gate
  choice, `--stop-on-pass`). Whole suite: 36 passed.

## Phase 7 - best-of-N and detector v2 results (no code change)

- Best-of-N (10 samples, temperature 0.7) passed 0/10 in both formats: sampling more does
  not fix a missing capability; temperature 0.7 made YAML errors more frequent.
- Observed limitation, **not changed**: `_score` (synthesize.py) ranks valid attempts by
  fewest false positives first, so a rule that matches nothing (recall 0%, 0 FP) beats a
  rule with recall 58% and 104 FP. It only affects which rule is reported as "best" and
  evaluated on the test set, not acceptance (`passed` still needs recall >= `--min-recall`
  and no FP). Changing it alters the reported numbers, so it is left as a decision.
- Detector v2 on CWE-416 (per-CWE prompt, Q6_K) was worse than v1 (BAD 76/150 vs 150/150
  flagged, GOOD 69/150 vs 37/149) but gives literal evidence; using its findings in the
  synthesis did not change the outcome. `.env` was switched to the Q6_K file with
  `N_GPU_LAYERS=-1` (file not versioned).

## Phase 8 - strategy template (`--format template`), an experimental arm

Requested to test whether giving the strategy helps. **This changes methodological
principle 1 for this arm only**: the strategy is written by us, the model fills in
patterns. It is reported as a separate arm and never mixed with the yaml/spec results.

Change 15 (`spec.py`, `synthesize.py`, `prompts/template_generator.md`,
`prompts/template_corrector.md`):
- The predefined strategy is a generic **state change on a variable** (Semgrep taint mode
  by side effect): an `event` marks a variable, `uses` are the problem when they touch a
  marked variable, `resets` (optional) clean it. Model answer:
  `{"message", "event": {"pattern", "variable"}, "uses": [...], "resets": [...]}`.
- The code builds the taint rule: source = event pattern + `focus-metavariable` + by-side-
  effect, sanitizers = resets in the same way, sinks = uses (optionally `focus`/`not`).
  It reuses the spec builder, `normalize`, `check_structure`, `check_c_statements`, `lint`
  and the same gate. Nothing in the model's patterns is changed.
- The prompt describes the strategy in generic terms (event / use / reset) and names no
  CWE and no Juliet function. It does, however, tell the model *how* to look for the
  weakness (as a state change of a variable), which is exactly the knowledge whose effect
  is being measured. The strategy also cannot express weaknesses that are an absence
  (e.g. a missing release) or need `metavariable-*` operators.
- Validation errors are explained (variable not in the pattern, missing `event`, empty
  `uses`, unknown keys). Tests in `tests/test_spec.py`; suite: 39 passed.

- Fix after the first template runs: `json.loads` silently kept the last of two equal keys
  (a `uses` key written twice in a CWE-415 attempt), so `_load_json` in `spec.py` now
  reports duplicate keys with an explicit message; the JSON-syntax message no longer
  prints an actual line break where it meant "backslash n". Applies to spec and template.
  Test added; suite: 40 passed.

Outcome of phase 8 (details in experiments.md): with the 4B model the template turned the
recall problem into a precision problem; with the 30B model (combo D) it produced the first
accepted rule (CWE-416, recall 48.8% / precision 100% on test), but not for CWE-415 and
CWE-476. It is a result of the template arm only.

The ablation table built from all runs is in [ablation.md](ablation.md).

## Decision - CWE-416 set aside (2026-09-29)

After the changes above no run on CWE-416 was accepted, so it is no longer a target for
new runs (results kept as a negative case; reversible). Per-CWE data and next steps
are in [experiments.md](experiments.md#next-steps): start with CWE-415 and CWE-476.

## Files added or changed (2026-09-28/29), none committed

- New: `docs/experiments.md`, `docs/changes.md`, `configs/combos/combo_d.toml`,
  `src/pipeline/baseline.py`, `src/pipeline/spec.py`, `prompts/spec_generator.md`,
  `prompts/spec_corrector.md`, `tests/test_spec.py`, `rules/baseline/*` (downloaded packs,
  not versioned).
- Changed: `src/pipeline/rules.py` (operator whitelist, YAML hint), `src/pipeline/gate.py`
  (grouped false positives), `src/pipeline/synthesize.py` (`--format`,
  `load_pattern_docs`), `README.md` (Windows notes, link), `tests/test_rules.py`,
  `tests/test_gate.py`.
- `CLAUDE.md` intentionally untouched.

## Phase 9 - ensemble by set cover (`src/pipeline/ensemble.py`)

Change 16: grades every candidate rule of a CWE on the train split, drops invalid ones and
those above `--max-fp` (default 0), and picks rules by greedy set cover of Juliet cases;
the test split is evaluated only for the chosen rules. Writes a merged YAML (ids get an
`-ens<k>` suffix; nothing else is touched). Kind: selection over rules the models wrote,
no LLM. Report next to single-run results: it uses the compute of every earlier run.
Tests: `tests/test_ensemble.py` (9).

## Phase 10 - real-world negatives, counterexamples and attempt ranking (2026-10-04)

Motivation: the accepted rule of phase 8 (`rules/accepted/D/cwe-416.yaml`) had 0 false
positives on Juliet, but on the source of Git (`git/git` at commit `8103b44651`, 644 `.c`
files, 447 KLOC, used as a real-world reference) it raised **927 alerts (2.1 per KLOC)**.
A sample of 40 alerts (random, seed 7), read with 11-15 lines of context each, had **no real
use after free**: 24 were sequences of `free` on sibling fields in release functions, 10 were
loops over different elements or with an advancing index, 5 were a reassignment after the
`free` by a function the rule does not know as a sanitizer (`xstrdup`, `xcalloc`, an output
parameter), 1 was checked in the code of the callee and was also correct. With 0/40 the
95% upper bound of the precision on this code is about 7.5%. Limits: the judgment was made
by reading, not by running the code, and the sample is small.

Everything below is part of the gate or the feedback: **deterministic aids**, no LLM, the
rule stays the model's. Principle 7 (the system does not know which detector findings are
right) is not touched.

| # | Change | Where | Kind |
|---|---|---|---|
| 17 | Real-world negatives: `evaluate(..., negative_files, max_negative_rate)`. Every match in those files is an alert (kept apart from the Juliet false positives, so Juliet precision stays comparable with the baseline packs); the report has the alert count, the number of lines scanned and the rate per KLOC; a rule passes only if the rate on the train side is at most `max_negative_rate` (default 0.1 in `synthesize`, not enforced in the gate CLI unless given). The files are split by `split_negatives`: a hash of the path relative to the repository root and the seed, so the split is the same on any machine and a file never changes side when others are added; the test side is scanned once, for the final report | `gate.py`, `split.py`, `synthesize.py` | gate |
| 18 | Counterexamples in the feedback: the first false positives (Juliet: 3 groups; real code: one example per file, files with most alerts first) come with 8 lines before and 2 after, the alert line marked `>`. The corrector used to receive a single line | `gate.py` | feedback |
| 19 | `_score` ranks attempts as: valid, passed, detects at least one case, F1 (alerts on real code count as false positives), fewest alerts. It used to rank by fewest false positives first, so a valid rule that matches nothing beat every rule that detected something (the best-of-N runs of phase 7 reported such rules as "best"). This is the decision left open in phase 7. It changes which attempt is called "best" and evaluated on the test set, never acceptance | `synthesize.py` | selection |
| 20 | Gate speed: Semgrep runs from the home directory with absolute paths (inside a git repository it asks git about each target, about 0.5 s per file on Windows: 446 files took 299 s, now 23 s), without the function-definition rule on real code (that rule is only used to grade Juliet matches by function name), and with `--timeout 30` | `gate.py` | infrastructure |

Notes to declare:
- The temp directory was *not* used as the working directory: an empty directory under
  `AppData/Local/Temp` made the same scan ten times slower on this Windows machine (30 s
  against 3 s). The reason was not investigated.
- The alert count of the same rule on the same files varies by about 1-2% between runs
  (train side, accepted CWE-416 rule: 618, 629, 623 alerts in 287.7 KLOC; test side 284, 285,
  292 in 111.9 KLOC), also with `--timeout 30`. The acceptance threshold must not depend on
  exact counts.
- The negatives are *assumed* correct. A real bug in them counts as a false positive.
  `max_negative_rate` is a parameter chosen by us, not derived from data.
- Rates of the accepted CWE-416 rule on the Git split (seed 0, 30% test): train
  2.15-2.19 alerts/KLOC, test 2.54-2.61 alerts/KLOC. That rule would not pass the gate at 0.1.
- Runs made before this phase used the old `_score`; their "best attempt" is not recomputed.
- Tests: `tests/test_split.py` (5), additions to `tests/test_gate.py` and
  `tests/test_synthesize.py` (including the loop with real-world code). Suite: 66 passed.

## Phase 11 - time limit per model call and k-fold cross-validation (2026-10-04)

Both are infrastructure; neither writes or edits a rule.

| # | Change | Where | Why |
|---|---|---|---|
| 21 | `LocalLLM.complete` streams the answer and cuts it after `max_seconds` (role setting, default 600 s), returning the partial text; the parser rejects it like any malformed answer and the loop goes on | `llm.py` | One combo C attempt took 2729 s (others 18-30 s, cause unknown) and the run hit the 50 minute limit of the background shell, losing the run log. A single forward pass that never produces tokens still cannot be interrupted |
| 22 | `split.fold_split`, `synthesize --folds K --fold i`: the flow variants are shuffled (seed) and dealt into K groups, group i is the test side; GOOD files follow the variants as before | `split.py`, `synthesize.py` | A 30% random split tests 6 of 20 variants of CWE-416; the number depends on which 6. Over all folds every variant is tested exactly once |
| 23 | `python -m src.pipeline.crossval`: runs `synthesize` once per fold sharing one model load, and summarizes the held-out numbers per fold and as mean and standard deviation. Recall counts a fold with no valid rule as 0; precision is averaged only over folds whose rule matched something. Rules go to `rules/crossval/<run>/fold<i>/` and the summary to `logs/crossval/<combo>/<cwe>/<run>.json` | `crossval.py` | Replaces single-split numbers by a mean with a spread. It never writes `rules/accepted/` |
| 24 | `synthesize --rules-dir` (default `rules`) | `synthesize.py` | Experiments that must not overwrite the versioned `rules/accepted/` (it holds the first accepted rule of the project) |

Notes to declare:
- The real-world files are split once (seed 0, 30% test) and are the same in every fold; only
  the Juliet variants change between folds. The examples shown to the generator change with
  the fold because the train side changes.
- Each fold is a separate generator -> gate -> corrector run with its own acceptance, so
  "accepted in k of K folds" is a result of its own, next to the mean of the test numbers.
- Variants 63 and 64 (free and use in different files) cannot be detected by Semgrep OSS; the
  fold that holds them has a recall ceiling. This is part of the spread.
- Tests: `tests/test_llm.py` (4), `tests/test_crossval.py` (11). Suite: 80 passed.

## Phase 12 - alerts on the statement that marks the variable (2026-10-05)

Motivation: 79% of the real-world alerts of the best combo D rule are on a line that is itself the
`free()` the rule treats as the source (experiments.md). One alert line does not show that, and the
corrector never removed it in 6 corrections.

| # | Change | Where | Kind |
|---|---|---|---|
| 25 | `evaluate` counts the real-world alerts that sit on a line also matched by the rule's own `pattern-sources` (it extracts the pattern strings of the sources, ignoring `pattern-not*`, `metavariable*` and `focus*`, and runs them as a search rule over the files with alerts). The feedback adds "N of these M alerts (P%) are on a line that one of the rule's own source patterns also matches: the alert is raised on the statement that marks the variable. A sink must not match the statement that marks the variable." Search rules and rules without such alerts get no line. Stored as `negative_on_source` in the report | `gate.py` | feedback |

Notes to declare:
- It is generic: it knows nothing about any CWE, function or Juliet file, and works for any taint rule.
  It does say what is wrong with the rule's structure, which is more than the earlier feedback, so
  it is a feedback aid like the others in changes.md and must be reported as one.
- It costs one more Semgrep run on the files with alerts (a few seconds).
- Tests: three in `tests/test_gate.py`. Whether it helps the corrector is measured in experiments.md.

## Phase 13 - `not_inside` in the template entries (template v2, 2026-10-05)

Cause: in the run with the source-line warning the model wrote the right idea (exclude the `free()` statement from the
uses) with `not`, which cannot express it (experiments.md). A format change, not feedback: it widens what the model can
write, it does not write it.

| # | Change | Where | Kind |
|---|---|---|---|
| 26 | Taint entries (sources, sinks, sanitizers, hence also the template `uses`) accept `not_inside: [...]`, built as `pattern-not-inside` after the `pattern-not` entries. Errors: an empty list or a non-string is explained; the unknown-key message lists it | `spec.py` | format |
| 27 | The template prompts (generator and corrector) describe it: `not` excludes a match only when it is exactly one of the patterns, `not_inside` excludes a use located anywhere inside code matching one of them; the JSON example shows it with the generic name `wrapper(...)` | `prompts/template_generator.md`, `prompts/template_corrector.md` | prompt |

Notes to declare:
- The sentence about what `not` matches paraphrases the Semgrep behaviour of `pattern-not` and tells the model there
  is a difference to use; it names no CWE, function or file. The spec prompts were not changed (the builder accepts the
  key there too).
- Results before and after this change are template v1 and v2: report them separately.
- Tests: three in `tests/test_spec.py`, one of them runs Semgrep and shows that `not` keeps the alert inside the marking
  call while `not_inside` removes it and keeps the later use.

## Phase 14 - feedback on a `not` that equals a source pattern (2026-10-05)

Cause: with `not_inside` available (phase 13) the model still wrote `not` in every use. The alerts on the marking statement
(phase 12) said what was wrong, not why the `not` it wrote did nothing.

| # | Change | Where | Kind |
|---|---|---|---|
| 28 | When real-world alerts sit on a source line, the gate looks at the sinks of the rule for `pattern-not` strings that are also a source pattern (`_sink_nots_equal_to_sources`; stored as `ineffective_nots`) and the feedback adds: "Your `not` of `P` on the uses does not remove them: a `not` (Semgrep `pattern-not`) only excludes a match that is exactly that pattern, and a use is usually just part of a statement (for instance the argument of a call). `not_inside` (Semgrep `pattern-not-inside`) excludes the uses that sit anywhere inside code matching it." Up to three patterns | `gate.py` | feedback |

Notes to declare:
- It is generic (Semgrep semantics of `pattern-not` against `pattern-not-inside`), names no CWE, function or file, but it is
  close to telling the model what to write: it is the strongest feedback aid so far and the result of runs with it must be
  reported as a result of the pipeline *with* that aid.
- It only triggers when the problem has been measured (alerts on source lines) and the specific mistake is present.
- Tests: two in `tests/test_gate.py`, one with Semgrep (a `not` equal to the source pattern is flagged and the alert stays;
  `pattern-not-inside` removes the alert and the flag).

## Phase 15 - the roles around the loop, a paired comparison and a queue of experiments (2026-10-07)

The evidence so far says that the models can state the right idea and cannot always write it, and that feedback written by us
(phases 12-14) gets close to giving the rule. These changes make the other roles of the multi-agent design usable, so that their
contribution can be measured instead of replaced by hand-written aids. All options are off by default: no earlier result changes.

| # | Change | Where |
|---|---|---|
| 29 | `--history`: the corrector sees a summary of the earlier attempts (it kept returning the same rule) | `roles.py`, correctors |
| 30 | `--critic`: another agent reviews each tested rule (why it fails, what kind of change would fix it) and the corrector gets the review as a fallible opinion. `--no-diagnosis` turns off the structural diagnoses of phases 12-14 in the gate feedback, to compare the critic with them | `roles.py`, `prompts/critic.md`, `gate.evaluate(diagnose=)` |
| 31 | `--merge`: a final attempt in which a merger combines the best rule with one of a different strength (quieter, else stronger); the gate judges it like any attempt | `roles.py`, `synthesize.py` |
| 32 | `--example-mode findings\|pairs\|none`: the detector's findings (as before), vulnerable/safe file pairs from the dataset labels, or no examples. `pairs` uses the labels, not the detector: it measures what better examples could give, not the pipeline as designed | `roles.py` |
| 33 | `--no-docs`: the Semgrep documentation in the prompts is replaced by a note. In the spec and template formats that text is only the 1,278-character pattern-syntax section | `synthesize.py` |
| 34 | The loop of `synthesize` is split into `step`, `review_by_critic` and `run_sample`; the role logic is in `roles.py` as pure helpers; an empty prompt marker removes its own line, so the prompts are unchanged when an option is off | `synthesize.py` |
| 35 | Combo E: the 30B model in every role with identical load settings, so switching role never reloads it (the critic of combo D, Phi-4-mini, would swap models on every call) | `configs/combos/combo_e.toml` |
| 36 | `python -m src.pipeline.compare`: paired comparison of two configurations run on the same seeds (same folds and real-world files): mean difference b - a, bootstrap interval over the folds, how often each side is better | `compare.py` |
| 37 | `scripts/run_ablation_queue.ps1`: runs the planned comparisons one after another, waiting for free RAM before each | `scripts/` |
| 38 | `compare --baseline ... --grouped DIR...`: every summary found under the folders is labelled by the options and the model it recorded (no docs, history, critic, merge, example mode, no diagnosis, model of another combo) and each group is compared with the baseline on the seeds they share. Summaries written before the options were recorded are skipped | `compare.py` |
| 39 | Combo F: Phi-4-mini in every role, to test a second model family in the same size class as the 4B; `qwen4b` and `phi4` are in the queue with their own (small) RAM requirement | `configs/combos/combo_f.toml`, `scripts/run_ablation_queue.ps1` |

Notes to declare:
- Critic, merger and history are LLM agents; their output only changes the prompt of the next attempt, and every rule still goes
  through the gate. The merger's rule is graded like any other attempt.
- The pre-registered analysis (hypotheses, metrics, what counts as an effect) is in `docs/ablation_plan.md`; it was written before the
  results of these comparisons.
- Tests: `tests/test_roles.py` (21, with a fake model and a fake gate, no Semgrep), `tests/test_compare.py` (8), a prompt test per
  format for `--no-docs`. The suite with Semgrep (111 tests, before `test_compare.py`) passed on 2026-10-07 after the refactor of the
  loop; the 8 comparison tests pass on their own.
