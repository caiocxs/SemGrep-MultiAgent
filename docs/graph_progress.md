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
| 2026-10-12 | **Fresh projects, measured once, as pre-registered** (nginx `2b5c2b60`, 271 files, 242 KLOC; libxml2 `c43dc98d`, 88 files, 190 KLOC; extractor as at `8e81dfb`) | **Both are blind, not passed**: 130 and 88 `free` events, **0.5 per KLOC** (the minimum was 3). 0 alerts of either query on either side means nothing. nginx releases through pools and its own functions (`ngx_pfree` 21, `ngx_slab_free_locked` 32, `ngx_free_chain` 30; only `ngx_free` is an alias of `free`, 134 uses), libxml2 through `xmlFree`, a function-pointer variable the extractor cannot see through, and its own macros (`FREE_AND_NULL` 140, `DICT_FREE` 17) | **No advance, informative**: the claim "under 0.1 alerts per KLOC on real code" is **not extended** beyond the four projects it was developed on; the coverage rule of the protocol did its job (it kept two empty results from being read as two passes) |
| 2026-10-12 | **No hand-written names** (the request): every list was removed but the C standard library (`free`; `malloc`...; `exit`, `abort`, `longjmp`...). Macros are read from the sources and headers and expanded when their body calls something with a parameter, assigns one or frees one; loop macros come from a loop in the body or from the parser (a call with no `;` followed by a block); a function that never returns is found from its body (no return reachable, to a fixed point); release functions with no body are learned (next row). 62 tests | See the next rows | Setup of the change the protocol asked for |
| 2026-10-12 | **First learned version (usage statistics only): failed.** A name was a release function if at least 8 call sites and its argument was almost never used afterwards, relative to `free`'s rate in the same project | Juliet use after free fell to 98/138 and double free got 12 false positives; double free on Git 46.8 and 22.0 alerts/KLOC, on curl 242 and 255, on Redis 334 and 11.7; OpenSSL use after free 1.51 and 0.83. 378 names learned on Git, among them real ones (`close`, `fclose`, `commit_list_free`, `CloseHandle`) and many that are not (`clar__assert_compare_i`, `parse_options`, `sha1_f1`): a call that is the last use of a constant, a parameter or an option looks like a release, and so does `printLine(data)` in Juliet | **No advance, informative**: usage statistics alone cannot tell a reader that happens to be the last use from a deallocator |
| 2026-10-12 | **Second learned version, three signals, all calibrated on the project's own `free` and on the functions its bodies prove**: (1) the after-use rate at most max(2 x that of `free`, 0.02); (2) the argument was acquired (assigned from a call) at least half as often as `free`'s argument (and 20%); (3) the words of the name look like the names of the functions the code proves to free a parameter on every path (a small naive-Bayes model against the functions with parameters proven to free none; words in more than a quarter of the names are project prefixes and ignored; a word must be seen in 2 proven releases) | Juliet use after free back to 134/138, 0 false positives; the alerts fell by orders of magnitude. Two bugs of mine were found by reading why `curl_multi_remove_handle(multi, easy)` was learned as a release: calls whose callee has a body that does nothing with the parameter were not counted as uses (they became `join` events), and `&p` behind a cast (`(void **)&reply`) was not seen | Advance; found by looking at what the model had learned |
| 2026-10-12 | **Noreturn from the declarations**: `_Noreturn`, `__attribute__((noreturn))`, or a macro whose body is that attribute (read from the headers), and macros that call such a function (Git's `BUG`) | Git's `die` (2968 uses), `die_errno`, `BUG`, `usage`, `pthread_exit` are recognized without a name list | Advance |
| 2026-10-12 | **What the old hand-written names became** (recovery table, `docs/graph_analyzer.md`) | Recovered by the code: Git `g_free` (learned), `FREE_AND_NULL` (macro expanded), `die`, `die_errno`, `BUG`, `usage`, `pthread_exit` (declared); Redis `xfree` (alias of `free`), `die`, `usage` (from their bodies); OpenSSL `OPENSSL_free` (learned, 3595 uses), `usage`; PostgreSQL `die`. **Not recognized:** curl `g_free` and `OPENSSL_free` (7 and 8 uses, libraries outside the code), OpenSSL `CRYPTO_free` (15 uses, goes through a hook), Redis `panic`, PostgreSQL `usage` and `OPENSSL_free` | Honest: most are recovered, the ones that are not have few uses or no definition in the code |
| 2026-10-12 | **Development sets with no hand-written names** (Git, curl, Redis, OpenSSL; alerts/KLOC, train / test) | Use after free: Git 0.000 / 0.000, curl 0.016 / 0.093, Redis 0.071 / **0.231**, OpenSSL 0.016 / 0.021. Double free: Git 0.017 / 0.009, curl 0.021 / 0.080, Redis 0.004 / 0.042, OpenSSL 0.018 / 0.025. Juliet: CWE-416 134/138 and CWE-415 150/272, 0 false positives in both | Advance: all under 0.1 but Redis use after free on the test side; the version with hand lists had Redis at 0.040 / 0.031 |
| 2026-10-12 | **Never-seen projects, as the protocol said, measured once** (tmux `95c1c3d7`, 200 files, 109 KLOC; PostgreSQL `9e7d152488`, 1546 files, 1597 KLOC). A first run of PostgreSQL crashed on a recursion error (expressions nested thousands of levels deep in generated code) and a second showed 0 events because the failure on the worker thread was not propagated: both fixed (big stack, errors re-raised, a failed file dropped whole and listed), and the run repeated; the extractor's *logic* was not changed | Coverage **15.2** and **3.9** `free` events per KLOC. **tmux: use after free 0.000 / 0.000, double free 0.058 / 0.000. PostgreSQL: use after free 0.006 / 0.005, double free 0.002 / 0.005**. Both meet the success criterion (coverage at least 3, use after free at most 0.1 on all files). nginx (0.5 events/KLOC) and libxml2 (0.1) are still **blind**: 0 alerts mean nothing there | **Advance, the first held-out pass**: two projects the extractor had not seen, one of them 1.6 million lines, pass with no list of names in it |
| 2026-10-12 | What the PostgreSQL run says about the learning (read, not tuned: the extractor was not changed afterwards) | Learned correctly: `CloseTransientFile`, `FreeFile`, `FreeDir`, `ExecDropSingleTupleTableSlot`, `list_free`, `PQclear`. Learned wrongly: `pg_log_error_hint`, `bms_next_member`, `SET_VARSIZE`, `pg_rotate_left32`. **Missed `pfree`**, its most used release (2616 uses): the name is one word, so the word model cannot see `free` in it (`sdsfree`, `xfree`, `zfree` have the same shape). The coverage of 3.9 is just above the minimum of 3 | Limit written down: the name model needs word boundaries or sub-word matching |
| 2026-10-12 | **Sub-word names, first version** (protocol written before): a word the model never saw that starts or ends with a word learned from at least 2 proven releases takes that word's weight; functions that only hand their parameter on to a call are no longer negative examples (`pfree` hands it to a hook, so it had counted against its own name). 3 new tests (65) | Juliet unchanged (134/138, 150/272, 0 false positives); Git, curl, OpenSSL, tmux, nginx, libxml2 unchanged. **Redis worse** (use after free 0.071 / 0.231 to 0.084 / 0.283, double free test 0.042 to 0.136: now above 0.1), PostgreSQL slightly up (test 0.005 to 0.021). Redis learned `zfree` (771 sites) and `hi_sdsfree` (819), which it missed before, and its coverage went from 7.3 to 13.8 free events per KLOC | Mixed: the project's own releases are now seen, and with them more false alerts |
| 2026-10-12 | `pfree` still not learned. Debugging the three signals: after-use 0.005, acquired 0.40, name score +3.09, all passing; the missing piece was word support: PostgreSQL defines a frontend `pfree` that calls `pg_free`, so the word `pfree` had **one** proven example, which blocked the sub-word rule and failed the minimum of 2. Fix: a known word with fewer than 2 proven examples and no negative example is read through the word it ends or starts with | `pfree` learned (3029 sites, score 3.6). **PostgreSQL now fails**: use after free 0.135 / 0.101 (0.126 in all), double free 0.039 / 0.018; its coverage went from 3.9 to 11.0 events per KLOC. The earlier pass (0.006 / 0.005) was partly blindness to `pfree` | **No advance for the result, advance for honesty**: seeing the project's most used release exposes the false alerts that not seeing it hid |
| 2026-10-12 | **Never-seen projects, measured once, as pre-registered** (vim `7eb646597`, 220 files, 572 KLOC; SQLite `6e35c19f1`, 318 files, 440 KLOC). The extractor was not changed after this run | Coverage 5.2 and 7.1 free events per KLOC. **SQLite passes**: use after free 0.100 / 0.023 (0.077 in all), double free 0.042 / 0.000. **vim fails**: use after free 0.515 / 0.146 (0.409 in all), double free 0.120 / 0.085 (0.110 in all). In vim 234 use-after-free alerts come from only 20 free sites and 179 of them from one function (`enter_buffer`); every one has a free that is a call summary | **Held-out result: 1 of 2 passes.** With tmux (0.000 / 0.000, passed at the time) the never-seen record under this analyzer is tmux, SQLite pass and vim fails |
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

## Protocol: no hand-written names, the analyzer learns them (written on 2026-10-12 **before** the change)

Request: the extractor must not be given alternatives of `free` (and the like) by hand; it has to associate them by itself. Today it carries
lists written by hand: release names (`kfree`, `g_free`, `av_free`, `OPENSSL_free`...), `FREE_AND_NULL`-style macros, allocator names, noreturn
names (`die`, `BUG`, `usage`...), and two name patterns (`*ALLOC*` macros assign their first argument, `*foreach*` macros are loops).

- **What stays given:** only the C standard library as the starting point: `free` (release), `malloc`/`calloc`/`realloc`/`strdup`/`strndup`
  (allocation), `exit`/`_exit`/`_Exit`/`abort`/`quick_exit` (the path ends). Constants of the language (`0`, `1`, `NULL`, `true`).
- **What is inferred, from the project's own code, with no list:**
  1. *A function that frees its parameter on every path* (already so, by summaries), now seeded by `free` alone, so `curl_dbg_free`,
     `strbuf_release`-like or `ref_transaction_free`-like functions are found because their body ends in `free`.
  2. *A macro that frees or assigns a parameter* (generic expansion of function-like macros whose body does either), replacing the lists of
     `FREE_AND_NULL`-style and `ALLOC` macros.
  3. *A function that never returns* (every path ends in a noreturn call or in another such function), replacing the list of `die`, `BUG`...
  4. *A loop macro*: a call with a block argument, or a macro whose body contains `for`/`while`/`do`, replacing the `foreach` pattern.
  5. *Release functions with no usable body* (a library, a function pointer, `xmlFree`, `OPENSSL_free` going through a hook): learned from how the
     code uses them. For every callee name and argument position, over its call sites with a plain pointer argument, the **after-use rate** is the
     share of sites where the argument variable is read, freed or passed again on some path after the call before it is reassigned. The rate of
     `free` itself in the same project is the reference. A name is a release function if it has at least 8 sites and an after-use rate at most
     `max(2 x the rate of free, 0.02)`. No other threshold and no project-specific value.
- **Checks written before looking at results:** on the four development projects (Git, curl, Redis, OpenSSL) and Juliet: how many of the
  names that used to be hand-listed are recovered by the inference (reported as a table), the alerts per KLOC (must stay under 0.1), and the
  inferred names listed for reading (precision of the list reported, thresholds not changed by reading it; if the rule is changed, those projects
  are development sets, which they already are).
- **Held-out:** nginx and libxml2 were measured once (blind) and their most common release-like names were printed in that step, so they
  are no longer untouched; two projects not seen at all are added: **tmux** (`xfree`, `free_*`) and **PostgreSQL** (`pfree`, memory
  contexts). Measured once with the same coverage rule (at least 3 `free` events per KLOC, else blind) and success at most 0.1 alerts/KLOC
  for use after free on all files. nginx and libxml2 are re-measured and reported as "seen".
- **No language model is used for the association.** The names are associated from the code's own statistics (deterministic and
  reproducible); a local model confirming each candidate could be added, but nothing here shows it is needed, and it would be one more thing the
  numbers depend on.

## Protocol: sub-word names and fresh projects (written on 2026-10-12 **before** the change)

The PostgreSQL run showed that the model of name words misses `pfree` (2616 uses, the project's own release). Reading the code for the fix
showed two causes, not one:

1. **One word.** `pfree` is not split, so the word `free` that the model learned from `pg_free` or `list_free` is not seen in it.
2. **A wrong negative example.** `pfree` has a body that hands its parameter to a function pointer, so it counts as a function "proven to free
   nothing" and its own word becomes evidence against it. A function that passes its parameter on to another call has proven nothing.

- **Change:** (a) a word the model has not seen that starts or ends with a word seen in at least MIN_SUPPORT proven releases (at least 4 letters;
  the longest such word) takes that word's weight (`pfree`, `sdsfree`, `xfree`); (b) the negative examples are only functions with parameters that
  are proven to free none **and** never pass any of them on to a call. No new threshold, no list of words.
- **Checks written before the result:** Juliet unchanged (134/138 and 150/272, 0 false positives); the four development projects and PostgreSQL
  stay under 0.1 or the change is reported as harmful; the table of what is learned is printed (is `pfree` now recognized, what else is added,
  how many wrong names).
- **Held-out:** two projects never seen, blobless clones at their head, all `.c` files, headers read for `#define`s: **vim** (`vim/vim`,
  `vim_free`, heavy conditional code) and **SQLite** (`sqlite/sqlite`, `sqlite3_free`, `sqlite3DbFree`). Measured once, with the coverage rule (at
  least 3 `free` events per KLOC, else blind) and success at most 0.1 use-after-free alerts/KLOC on all files. PostgreSQL, nginx and libxml2 are
  re-measured and reported as seen.
- **Known gap, not part of this change:** release through `&p` (`av_freep(&p)`, `avcodec_free_context(&ctx)`) is not learned: only by-value
  arguments are measured.

## Where the arm stands (2026-10-12, final extractor)

| Question | Status |
|---|---|
| Juliet (the controlled benchmark) | CWE-416: 134/138 cases, 0 false positives. CWE-415: 150/272, 0 false positives |
| Real code, use after free, **all files** (limit 0.1 alerts/KLOC) | Git 0.000, curl 0.037, OpenSSL 0.017, tmux 0.000, SQLite 0.077: **pass**. Redis 0.144, PostgreSQL 0.126, vim 0.409: **fail**. nginx and libxml2: blind (0.5 and 0.1 free events per KLOC), not a result |
| Real code, double free, all files | Git 0.015, curl 0.037, Redis 0.059, OpenSSL 0.020, PostgreSQL 0.033, tmux 0.046, SQLite 0.030: pass. vim 0.110: fail |
| Projects never seen by the extractor at the time of the run | tmux pass, PostgreSQL pass (before the sub-word fix, 0.006 / 0.005), SQLite pass, vim fail |
| Hand-written names | none but the C standard library: names come from bodies, macro definitions, declarations and a three-signal model calibrated on the project's own `free` |
| Where it breaks | one call classified as a release by mistake produces dozens of alerts in a function (vim: 179 alerts from one function, 234 from 20 free sites); coverage and false alerts rise together; nginx pools and libxml2's `xmlFree` pointer are out of reach |
| LLM judge | decided against; no language model is involved in the association |

## Next steps (not done)

Written down so that the arm's claims stay honest: grouping alerts by the free site (one wrong call yields many alerts, so the count per KLOC
overstates the number of independent mistakes); one more pair of projects never seen, with the coverage rule; nginx-style pool allocators and function-pointer releases (`xmlFree`); an ablation of what each learned
piece removes on the development projects; the fix commits of curl, Redis, OpenSSL and PostgreSQL with the learned names; the other CWEs with
the same events (leak, null dereference, uninitialized use); pointers derived from freed objects; telling a conditional free that depends on
a flag (variants 21 and 22 of CWE-415) from one that depends on an error.
