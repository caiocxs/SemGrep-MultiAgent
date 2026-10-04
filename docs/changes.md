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
