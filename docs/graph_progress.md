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
| 2026-10-12 | **Release macros** (generic, from the coverage diagnostic, not from the alerts): `#define`s are read as text from the `.c` and `.h` files (the `#define`s of curl's `curl_setup.h` sit inside a syntax-error node, so the tree-sitter route failed first), the ones that lead to a deallocator are found by a fixed point and expanded at their calls with the arguments substituted; `do { .. } while (0)` has no back edge. 8 new tests | Coverage on curl: 133 `free` events (0.5/KLOC) become 1781 (6.7/KLOC; Git: 10.2). Git unchanged (0.014 / 0.063 and 0.059 / 0.295), Juliet unchanged. **curl, no longer held-out because the extractor was changed after seeing it:** use after free 3 train alerts (0.016) and 6 test (0.080), 0.034 on all 795 files; double free 6 train (0.031), 2 test (0.027) | **Advance**, with the test on curl now a development set |
| 2026-10-12 | All 17 curl alerts read (9 use after free, 8 double free) | **0 real**: 6 are the call summary (`thrdpool_unlink(tpool, ..)` frees on one path and the code checks the return value), 2 are infeasible paths that need a condition to be seen (`ghiper.c`: after `g_free(all)` the loop always ends because `while (len ..)` is false there; `hostip4.c`: `h = NULL` then `if (h)`), the rest repeat those. The `ghiper.c` one looked like a real latent bug until the loop condition was read | No advance for finding bugs; shows the two limits of the graph (some-path summaries, no condition evaluation) on a second project |
| 2026-10-12 | **Held-out test on two untouched projects, as pre-registered** (Redis `38087a9f7`, 479 files, 320 KLOC; OpenSSL `122db7eb07`, 1695 files, 862 KLOC; no change to the extractor) | Coverage is fine (Redis 8.5 and OpenSSL 13.2 `free` events per KLOC, so not blind). **Use after free: Redis 4.131 alerts/KLOC on train and 2.561 on test; OpenSSL 0.290 and 0.628. Double free: Redis 0.866 and 1.039; OpenSSL 0.133 and 0.223.** All above the limit of 0.1 | **No advance, and the important negative result**: the 0.014 / 0.063 on Git did **not** carry over to two other projects; by the criterion written beforehand the method fails on both |
| 2026-10-12 | Diagnosis of the Redis and OpenSSL alerts (a systematic sample of 40 per project, every k-th in file and line order, then a count over all alerts) | **98-99% of the alerts of Redis and OpenSSL have a "free" that is a call classified by the callee's summary, not a direct `free`** (Redis: 1162 of 1174 use-after-free alerts, e.g. `addReplyArrayLen(c, 2)` seen as freeing the client `c`; OpenSSL: 327 of 330, e.g. `ossl_ssl_init(ssl, ctx, ..)` as freeing `ctx`); in Git it was 100% and 92% (use after free, double free), in curl 89% and 75%. One wrong summary yields dozens of alerts in one function (222 in `xinfoReplyWithStreamInfo`). The Git 0.014 was low because Git has few badly summarized calls, not because the method was precise | Diagnosis: the cause is the summary "frees its parameter on some path", known since the first measurements; the held-out projects show how much it weighs. Next: a summary that requires the free on every path to the exit, and `#if/#else` as alternatives (they were walked in sequence) |
| 2026-10-12 | **Second iteration** from the diagnosis: a call summary says "frees" only if the free lies on **every** path from the entry to a return (explicit entry and return/end marker events; a path ending in `exit`/`die` is not a return); `#if`/`#else` are alternatives. 3 new tests (49 in all). A first version without explicit return markers still failed its own test (a path that returns with no event before it left no trace in the graph), which is why the markers exist | Juliet CWE-416 unchanged (134/138, 0 false positives); Juliet CWE-415 **162 -> 150/272** (variants 21 and 22 are lost: the callee frees only if a global flag is set, a true double free that a free on every path cannot see), 0 false positives. **Alerts per KLOC on the four development projects (train / test):** Git use after free 0.000 / 0.000, double free 0.010 / 0.009; curl 0.005 / 0.000 and 0.010 / 0.000; Redis 0.040 / 0.031 and 0.009 / 0.031; OpenSSL 0.024 / 0.000 and 0.026 / 0.004 (before: Redis 4.131 / 2.561, OpenSSL 0.290 / 0.628 for use after free) | **Advance on the real-world side, with a recall cost**: all four projects under 0.1 on both sides and both queries, but all four are development sets now (the extractor changed after seeing each), so this is not yet a held-out result |
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

## Protocol for two untouched projects (written on 2026-10-12 **before** the run)

The curl test taught two things: a held-out result is worthless when the extractor is blind to the project's release names, and once the
extractor is changed after seeing a project, that project is a development set. So the check is repeated on projects the extractor has
not seen, and the coverage diagnostic is part of the criterion.

- **Projects:** OpenSSL (`openssl/openssl`) and Redis (`redis/redis`), blobless clones next to the repository, at their head, all `.c`
  files, headers read for their `#define`s. Chosen because their release conventions differ from Git and curl (`OPENSSL_free`,
  `zfree`...).
- **No change to the extractor, the query or the name lists before the numbers are written down here, and none afterwards that would be
  presented as a held-out result.** If something is changed, those projects become development sets and the entry says so.
- **Measured once per project:** `free` events per KLOC (coverage) and the textual release-like names with the most uses; use after
  free and double free alerts per KLOC, on all files and on the train and test sides of the same split by file hash (seed 0).
- **Valid only with coverage:** a project whose `free` events are below 3 per KLOC (curl before the macros: 0.5, Git: 10.0) is reported as
  **blind**, not as passed, whatever the alert rate. The extractor is then not changed in the same step: the unknown names are listed, and a
  later change makes the project a development set.
- **Success on a project:** coverage at or above 3 events per KLOC and use after free at most 0.1 alerts/KLOC on all files. All alerts of the
  use-after-free query are read afterwards (a sample of 30 in sorted order of file and line for double free).

## Protocol for two fresh projects (written on 2026-10-12 **before** the run, after the second iteration)

Git, curl, Redis and OpenSSL are development sets (the extractor changed after seeing each of them). The claim "under 0.1 alerts per KLOC
on real code" needs projects nobody tuned on. Same rules as the previous protocol, with the lesson of OpenSSL and Redis added: the number
that matters is the one measured **once** on projects not yet seen.

- **Projects:** nginx (`nginx/nginx`) and libxml2 (`GNOME/libxml2`), blobless clones next to the repository, head of the default branch,
  all `.c` files, headers read for their `#define`s. libxml2 frees through its own `xmlFree` (a function pointer variable, which the
  extractor cannot see through) and nginx through `ngx_free`/pools: both are expected to stress the name recognition, and that is
  part of what is measured.
- **No change** to the extractor, the query or the name lists before the numbers are written here; any later change makes the project a
  development set and the entry says so.
- **Measured once per project:** coverage (`free` events per KLOC), use after free and double free alerts per KLOC on all files and on
  the train and test sides of the split by file hash (seed 0).
- **Valid only with coverage:** below 3 `free` events per KLOC the project is reported as **blind**, not as passed.
- **Success:** coverage at or above 3 per KLOC and use after free at most 0.1 alerts/KLOC on all files, on both projects. If it fails on
  either, the claim is restricted to the projects it was tuned on. All use-after-free alerts are read afterwards, up to 40 per project in
  sorted order of file and line.

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
