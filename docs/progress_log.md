# Progress log

Chronological record of what was done and **how far it moved the project** (or not). Dates come from the git history and the run
logs; times of 2026-10-09 are from the logs of that day. New entries go at the bottom. Details of each result stay in
[experiments.md](experiments.md), [ablation.md](ablation.md) and [findings.md](findings.md).

Progress marks: **Advance** (a measured result moved the goal), **No advance** (tried, result null or negative, informative),
**Setup** (infrastructure, no result yet), **Blocked** (stopped by something outside the experiment).

The goal that the marks refer to: local small models generate Semgrep rules that pass two gates at once, Juliet (held-out variants,
no false positives) and real-world C code (at most 0.1 alerts per KLOC), for CWE-416 first.

## Until 2026-09-27: the detector

| Date | What | Result | Progress |
|---|---|---|---|
| 2026-08-19 to 08-31 | Detector benchmark: Qwen2.5-Coder-3B on the Juliet files, first batch of logs | 99.8% of BAD files flagged, 34% false positives on GOOD (847/2496), about 122 s per file on CPU | Advance (the detector exists), but its false positives are a threat to the whole pipeline |
| 2026-09-14 | All dataset logs finished | Logs for the five CWEs | Setup |
| 2026-09-25 | Per-CWE prompts for the detector | v2 prompts, literal evidence in the findings | Setup |

## 2026-09-27 to 09-29: first rule synthesis (Juliet only, no real-world gate)

| Date | What | Result | Progress |
|---|---|---|---|
| 09-27 | Pipeline with Semgrep (generator, gate, corrector); combo A (3B) on CWE-416, three runs adding structure/`;` checks and repetition detection | Syntax became valid, logic stayed wrong (it never tried taint mode), test recall 0% | No advance in rules, **Advance** in feedback (the loop converges on syntax) |
| 09-28 | Combos B and C (7B, 4B), YAML and JSON-spec output formats | Best: 4B YAML, recall 58.5%, precision 42.9%, 32 false positives; spec removes YAML errors but the rules match almost nothing | No advance (format changes the errors, not the logic) |
| 09-29 | Template format (we give the strategy, the model fills the patterns) and combo D (Qwen3-Coder-30B) | **First accepted rule** (recall 48.8%, precision 100%, 0 false positives); the same setup gave 0% on CWE-415 and, on CWE-476, 0% (30B) and 38.8% with 308 false positives (4B); best-of-10 sampling did not help | **Advance**, with the caveat that the template arm changes principle 1 and is reported apart |

## 2026-10-04 to 10-06: real-world gate and cross-validation

| Date | What | Result | Progress |
|---|---|---|---|
| 10-04/05 | Gate with real C code (Git, 644 files, 400 KLOC) as assumed-correct negatives; time limit per model call; k-fold cross-validation by flow variant | The accepted rule of 09-29 raises 2.1 alerts/KLOC and none of 40 sampled alerts is a real bug: **0 false positives on Juliet does not predict real code** | **Advance in method** (the earlier success was an artifact), no advance in rules |
| 10-05 | Cross-validation, template v1: 4B accepts 0/5 (recall 20%), 30B accepts 0/5 (recall 89%, 5.1 alerts/KLOC) | The 30B generalizes across Juliet variants; nothing passes the real-world limit | Advance (the evidence is now honest), the goal is not reached |
| 10-05/06 | Template v2 with `not_inside`, warning for alerts on the line of the source, feedback on a useless `not`; seeds 1 and 2 | One rule reached 0.138 alerts/KLOC on train (limit 0.1), 0.105 on test, recall 57%; still above the limit | **Closest approach to the goal**, not accepted |

## 2026-10-07 to 10-08: reading the alerts, roles, planned comparisons

| Date | What | Result | Progress |
|---|---|---|---|
| 10-07 | All 51 alerts of the near-miss rule read by hand | **0 are a use after free**: loops that move on, macro reassignment, other objects. The gate measures noise, not precision | Advance in understanding; shows passing the gate is not the same as being correct |
| 10-07 | Critic, merger, history and example-mode roles implemented; comparison plan **written before the results** (`ablation_plan.md`); paired comparison tool; seeds 3 and 4 of the final configuration | Final configuration over 25 folds: 0 accepted, recall 75.8%, 2.92 alerts/KLOC | Setup, and the 25-fold baseline |
| 10-08 | `nodocs` (no Semgrep documentation in the prompt) and `history` (corrector sees earlier attempts), 10 paired folds each | No effect by the plan's criterion in either (recall +0.02 and +0.01) | No advance (two ideas ruled out) |
| 10-08 | `guard` (edit only the best rule), `apis` (list the project's memory functions), `guardapis` | `guard` and `apis`: no effect; together: recall 97.5% but 101 Juliet false positives and 17 alerts/KLOC (harmful) | No advance (three ideas ruled out) |

## 2026-10-09: the day of this entry

| Time | What | Result | Progress |
|---|---|---|---|
| morning | `nodiag` (gate diagnoses off) repeated on five seeds | Recall +0.084 (interval +0.013 to +0.157): below the 0.10 of the criterion; the +0.119 of the first 10 folds did not hold up | No advance (a promising effect did not replicate: the plan's rule of repeating before claiming worked) |
| 11:09 | The Semgrep settings file was corrupted (zero bytes) by an interrupted run; two restarts of the queue failed at once | File removed (with the user's authorization), Semgrep works again; each parallel process now gets its own settings file | Blocked, solved |
| 11:16 onward | Local queue resumed: `pairs`, `critic`, `criticnodiag` | `critic` and `criticnodiag`: no effect (recall -0.07). `pairs` (pairs of vulnerable/safe code from the dataset labels): no effect by the criterion (recall +0.16), but **2 of 10 folds accepted** (recall 57% and 31%, 0.03 and 0.02 alerts/KLOC); an upper bound on the example information, the two rules not read yet | **Advance**: the first folds accepted by both gates in the study, with low recall and from a source of examples that is not the designed pipeline |
| 11:18 | Remote backend for the generator and corrector (`remote.py`, combos G, H, I): pacing, retry on 429, usage log, tests | A first call failed with 403 (the provider rejects the default Python user agent); fixed | Setup |
| 11:54 to 13:08 | Combo G (Groq, `gpt-oss-120b`) on seeds 1 and 2 | Recall +0.273 over the local 30B (interval +0.12 to +0.41, an effect by the criterion), alerts/KLOC the same (2.59 against 2.53), **0/10 accepted**. Limits: 1000 requests/day and 8000 tokens/min; 74 calls and 231 thousand tokens, no 429 | **Advance in recall, no advance in the gates**: a larger model does not remove the real-world obstacle |
| 18:07 | Combos H (Gemini) and I (OpenRouter free) | I, seed 1: recall 92.7%, 3.77 alerts/KLOC, 0/5 accepted. Gemini free tier throttles heavily (20 calls in 90 min, 130 s per call): the arm cannot be completed in reasonable time | No advance in rules; useful measurement of the limits |
| 18:11 | The remote runs made the queue's "another synthesis is running" guard refuse `merge`, `none`, `qwen4b`, `phi4` | The guard now ignores the remote combos (they load no model); the queue was restarted at 19:39 and waited for 20 GB of free RAM until the user freed it | Blocked, solved |
| afternoon | **Event-graph analyzer** (branch `feat/graph-analyzer`): SQLite schema, recursive path query, tree-sitter extractor, scoring on Juliet and Git | Use after free: Juliet 126/138 cases and 0 false positives (as the hand-checked reference rule), Git **0.014 alerts/KLOC on train and 0.063 on test** (first version, untuned: 0.32 and 0.23). The conventions were chosen by reading train alerts only; the 11 alerts left (4 train, 7 test) were read and none is a real bug. CWE-415 without tuning: 150/272 cases, 6 false positives of one Juliet pattern, 0.295 alerts/KLOC on test | **Advance**: the first approach under the real-world limit on both sides with Juliet recall at the reference level; it does not use a language model yet, and whether it finds real bugs is not measured |
| 20:03 | G on seeds 0, 3 and 4 (to repeat the recall effect) | The Groq free tier answered 429 with Retry-After of 256 to 408 s (a token quota), the code stopped on it and the three runs died | Blocked: the wait limit (2 min) was too short; now 15 min, and the error text is logged. Seed 0 resumed (finished folds are reused), seeds 3 and 4 restarted |
| ~20:15 | Local queue running again (`merge`, `none`, `qwen4b`, `phi4`) | In progress | - |
| 20:21 | Groq stopped again: the text of the 429 says **tokens per day, limit 200,000, used 199,928**, Retry-After 18 min | The repeat of the recall effect on seeds 0, 3, 4 (about 350 thousand tokens) does not fit in a day on this tier; the three runs were not completed | Blocked by the provider's quota; the effect of G stays exploratory (two seeds) |
| 20:25 | Graph analyzer against the **16 fix commits of Git** (same protocol and filter as for the rules; `src/graph/fixcommits.py`) | 2/16 files with an alert near the fix, **both are the bug the commit fixed** and both alerts are gone after the fix (`read-cache.c`, `notes.c` through a call summary); 0 other alerts in those files. The rules had 5/16 at the level of chance. Recall is low: reading the other 14 diffs, 4 use a pointer derived from the freed object, 4 free through a project function acting on a structure, 4 are lifetimes of objects in structures, 2 are not a use after free as written | **Advance**: the first approach that points at real bugs better than chance (2 of 2 alerts, against 9% for any `free()`), with a recall far below what is needed for a detector |
| 20:35 | Graph analyzer: loops that run once, and `&p` passed to functions that free or use what they load from `*param` (with a reset rule for list pops) | Use after free: Juliet **134/138** (was 126), 0 false positives, Git 0.014 / 0.063 alerts/KLOC (unchanged); double free: Juliet **162/272** with 0 false positives (was 6), Git 0.059 train, **0.295 test** (above the limit). The 33 test alerts (and 17 train ones) were read as a list: none looked like a double free, 41 of 50 are `ref_transaction_commit` then `ref_transaction_free`, a summary that says "frees on some path". The code was not changed after reading them, so 0.295 is the clean held-out number | **Advance** on Juliet for both CWEs; **No advance** on the real-world gate for CWE-415 (open) |
| 20:40 | Decision on the LLM judge for the graph | **Not implemented**: it can only drop candidates, the false positives are already under the limit (4 train, 7 test alerts for CWE-416) and the misses come from derived pointers and data-structure lifetimes, which a filter cannot add | Decision recorded with its numbers in `graph_analyzer.md`; revisit if the query grows to hundreds of alerts per KLOC |

## 2026-10-10 (overnight results and the correction of one of them)

| Time | What | Result | Progress |
|---|---|---|---|
| 21:53 to 00:23 | Local queue finished: `merge`, `none`, `qwen4b`, `phi4` (10 folds each) | `merge`: no effect (recall +0.035). `none`: recall -0.33, interval includes 0 (not detected at 10 folds, direction as expected). `qwen4b`: recall 30%, rules that match nothing, 0 accepted. `phi4`: recall 0%, no rule detected anything | No advance for the rules (each planned comparison is now answered; the pipeline's gate is still never passed); the planned comparisons are complete |
| 02:38 | Gemini (H) and OpenRouter (I) finished their two seeds | I over 10 folds: recall +0.048 over the 30B (the +0.21 of its first seed did not hold), 0 accepted. Gemini: 13 answers in 8.5 hours | No advance; the "+0.21" would have been a false claim from one seed |
| 02:40 | **Error found in my own measurement**: a call that gave up on a 429 was returned as an empty answer and counted as a failed attempt of the model (all 35 attempts of one Gemini run, up to 15 of the OpenRouter ones) | The H and part of the I numbers measure the quota, not the model: H is declared not a comparison, I exploratory; `remote.py` now stops with an error in that case (tested). The Groq runs used for the claim had no such case | Correction of a result; section 7c of `ablation.md` |
| 02:50 | Documents updated: section 7 of `ablation.md` rewritten with the final numbers, items 14 to 18 of `findings.md`, summaries exported to `results/crossval/` | - | - |

## Scorecard (as of 2026-10-10)

| Question | Status |
|---|---|
| Can a local model write rules that generalize across Juliet variants? | Yes for the 30B (recall 76% over 25 folds), no for the 4B (20%) |
| Does any rule pass both gates? | **No** in 40+ folds of the designed pipeline; only 2 folds with `pairs` (narrow rules) |
| Is more help to the generator an answer? (docs, history, guard, apis, critic, pairs) | No: each tried, none moves alerts/KLOC |
| Does a larger hosted model pass? | No: Groq 120B has better recall (+0.27, not yet repeated), the same alerts (0/10 accepted); OpenRouter no effect; Gemini not measurable |
| Is there any approach under the real-world limit with Juliet recall at the reference level? | **Yes, the event-graph query without any model** for CWE-416 (Juliet 134/138, Git 0.014 / 0.063 against 0.1); it finds 2 of the 16 real fix commits, both exactly the bug. For CWE-415: Juliet 162/272, Git 0.059 train but **0.295 test** (open) |
| What is left of the planned comparisons? | **All the planned ones are done** (`nodocs`, `history`, `nodiag`, `critic`, `criticnodiag`, `merge`, `pairs`, `none`, `qwen4b`, `phi4`, and the exploratory `guard`, `apis`, `guardapis`); not done: G repeated on seeds 0, 3, 4 (two more days of Groq quota or a paid tier); the graph: a summary that requires the free on every path (CWE-415 on Git), pointers derived from freed objects; the LLM judge was decided against |

## Log of next entries

Append below: date and time, what was run, the number, the mark.
