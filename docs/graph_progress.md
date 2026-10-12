# Progress log of the event-graph analyzer

Chronological record of the graph arm and how far each step moved it. This arm is **separate from the rule synthesis** (branch
`feat/graph-analyzer`): it does not generate Semgrep rules and uses no language model. Design and measurements:
[graph_analyzer.md](graph_analyzer.md). Progress marks: **Advance**, **No advance**, **Setup**, **Blocked**.

The goal the marks refer to is the same as for the rule synthesis: find the memory-lifetime weakness on held-out Juliet cases and stay
quiet on real C code (at most 0.1 alerts per KLOC on the Git sources, assumed correct), for CWE-416 first.

| Date, time | What | Result | Progress |
|---|---|---|---|
| 2026-10-09, afternoon | Idea: store the events of a whole repository (alloc, free, use, reassignment) with control-flow edges and ask for paths from a `free` to a later use. Opinion given: worth a separate arm, a graph database is not needed (SQLite), the extractor is the hard part, "a pointer without a free" is CWE-401, not 416 | Design sketch, schema (`schema.sql`), recursive path query (`paths.py`), tests on hand-built graphs | Setup |
| 2026-10-09, afternoon | tree-sitter extractor (`extract.py`): statements to events and flow edges (if, loops, switch, break/continue, goto, return), call summaries to a fixed point, scoring with the gate's rules on Juliet and on Git split by file hash as in the synthesis (`evaluate.py`) | First version, untuned: Juliet CWE-416 126/138 cases, 0 false positives (the same as the hand-checked reference rule of the gate); Git 0.320 alerts/KLOC on train and 0.232 on test | Setup with a first number: Juliet at the reference, the real-world side above the limit of 0.1 |
| 2026-10-09 | Five general conventions chosen by reading **train** alerts only: `exit`/`die` end the flow, `&p` passed to a call is a reset, a name declared in a block is gone when the block is left (also by `break`/`continue`), macros `*ALLOC*` assign their first argument, `*foreach*` macros are loops | Juliet unchanged (126/138, 0 false positives); Git **0.014 train, 0.063 test**, both under 0.1. The 11 alerts left (4 train, 7 test) were read: none is a use after free (a summary that says "the callee frees its parameter on some path") | **Advance**: the first approach under the real-world limit on both sides with Juliet recall at the reference level; the rule synthesis stays near 2.9 |
| 2026-10-09 | The same extractor on CWE-415 (double free), no tuning | Juliet 150/272 cases, 6 false positives (all one pattern: a loop `for (j = 0; j < 1; j++)` that runs once); Git 0.059 train, 0.295 test | No advance on the real-world side for this CWE (the rule synthesis got 0% on it) |
| 2026-10-09, 20:25 | The 16 fix commits of Git (the filter of `experiments.md`, reproduces exactly 16), the query on each file before and after the fix (`fixcommits.py`) | 2/16 with an alert near the fix, **both exactly the fixed bug**, both gone after the fix, 0 other alerts in those files (the rules were at chance, 5/16). Reading the other 14 diffs: 4 pointers derived from the freed object, 4 releases by project functions acting on structures, 4 lifetimes of objects in structures, 2 not a use after free as written | **Advance**: points at real bugs better than chance (2 of 2 alerts against 9% for any `free()`), with a recall far from a detector |
| 2026-10-09, 20:35 | Loops that run once (constant bounds, step 1: no back edge) and `&p` passed to a function that frees or reads what it loads from `*param` (also through a cast), with a reset rule when the callee assigns `*param` (a list pop) | CWE-416: Juliet **134/138** (variants 63, 64 now 4/6 each), 0 false positives, Git unchanged (0.014 / 0.063; without the reset rule 25 new train alerts, 0.101); CWE-415: Juliet **162/272**, 0 false positives, Git 0.059 train and **0.295 test** | **Advance** on Juliet for both CWEs; open on the real-world side for CWE-415 |
| 2026-10-09, 20:40 | Reading the 50 CWE-415 alerts on Git (17 train, 33 test) as a list | None looked like a double free; 41 of 50 are `ref_transaction_commit(t, ..)` followed by `ref_transaction_free(t)`, the summary "frees on some path". Code not changed afterwards: **0.295 is the clean held-out number** | Diagnosis only |
| 2026-10-09, 20:40 | Decision on the LLM judge (a filter that may only drop candidates) | **Not implemented**: the alerts are already under the limit (4 train, 7 test), the misses are of a kind a filter cannot add (derived pointers, structure lifetimes), and in the fix files it could only lose one of the 2 true alerts | Decision with numbers in `graph_analyzer.md` |
| 2026-10-12 | **First measurement on curl, as pre-registered** (head `70c084a01`, 795 files, 267 KLOC, no change to the extractor) | Use after free: 1 alert on train, 0 on test (**0.005 alerts/KLOC**); double free: 1 on train, 0 on test. The criterion written beforehand (at most 0.1) is met, **but the coverage diagnostic says it means nothing**: the extractor saw 133 `free` events in curl (0.5 per KLOC) against 3976 in Git (10.0 per KLOC), because curl frees through `curlx_free` (765 uses), `curlx_safefree` (488) and `curl_free` (165), names the extractor does not know, and only 119 calls are a plain `free(`. The test is blind, not quiet | **No advance, informative**: the 0.014 / 0.063 on Git is not shown to carry over; the held-out test on another project is inconclusive and the reason is a limit of the extractor (it recognizes releases by a fixed list of names) |
| 2026-10-11 | The graph arm was separated from the rule-synthesis branch (it had been merged into it only to let a running experiment queue keep a script fix) | `feat/graph-analyzer` is `main` plus the graph work only; this file is its own log | Housekeeping |

## Protocol for a second code base (written on 2026-10-11 **before** the run)

Purpose: the conventions of the extractor were found by reading alerts on the Git sources, and the Git test side comes from the same
project. A different project is the only clean test of whether 0.014 / 0.063 alerts per KLOC is a property of the method or of Git.

- **Code base:** curl (`https://github.com/curl/curl.git`), a blobless clone next to the repository (`../curl`, not inside it), at its
  current head. All `.c` files, as for Git (`lib/`, `src/`, `tests/`, `docs/examples/`). No file is excluded after seeing the output.
- **No change to the extractor, the query or the lists of allocation and release names before or after the first measurement.** Names
  curl uses that the extractor does not know (for example `Curl_safefree`) stay unknown: that is part of what is measured (it can only
  lower recall or add alerts, and the alerts are then read, not fixed).
- **Measured, once:** alerts per KLOC for use after free and for double free, on all curl files and on the two sides of the same split
  by file hash (seed 0) that the synthesis uses; Juliet numbers do not change.
- **Reading:** only after the numbers are written down here. All alerts of the use-after-free query are read (expected to be few); for
  double free a sample of 30, picked by the sorted order of file name and line, not by what they look like.
- **Fix commits of curl:** the same filter as for Git (`use[- ]after[- ]free|double[- ]free|\bfreed\b|memory after`, no merges, since
  2018-01-01), whatever count it gives; same window of 10 lines; the filter is not adjusted after seeing the output.
- **What counts as success:** the use-after-free query at or below 0.1 alerts/KLOC on curl as a whole. What counts as a result against
  the method: above 0.1 there, which would mean the conventions are Git-specific. Either is reported as it comes out, and if the extractor is
  changed afterwards for curl, the curl numbers are no longer a held-out test and the entry says so.

## Where the arm stands (2026-10-11)

| Question | Status |
|---|---|
| Juliet, CWE-416 | 134/138 cases, 0 false positives |
| Real-world gate, CWE-416 | 0.014 train, 0.063 test, limit 0.1 (met on both sides) |
| Real bugs | 2 of 16 fix commits, both exactly the fixed bug, no other alert in those files |
| CWE-415 | Juliet 162/272, 0 false positives; Git 0.059 train, **0.295 test** (open) |
| LLM judge | decided against |
| Tuned on | train alerts of Git only; CWE-415 not tuned; the same Git sources used for the train and the test side (split by file hash), so there is **no second code base yet** |

## Next steps (not done)

Written down so that the arm's claims stay honest: a code base other than Git as a clean held-out (the conventions were found on Git); an
ablation of the conventions (what each one removes on train and on test); a summary that requires the free on every path (CWE-415 on
Git, no longer a clean test for the seed-0 split); the other CWEs with the same events (leak, null dereference, uninitialized use); pointers
derived from freed objects.
