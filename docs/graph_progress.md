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
| 2026-10-13 | **CWE-401 implemented** (protocol written before): new events `escape` and `null`, the callee of each allocation, the leak query (an allocation of a local that reaches a return on a path where it is not freed, handed on, stored, returned or overwritten), `p = realloc(p, n)` as a leak on the failure path, and `prepare_leaks` (allocators proved by the code, who keeps a pointer, readers learned from the frees that follow). 18 tests | First run on Juliet CWE-401 (868 BAD, 868 GOOD; 216 C++ files left out): **108 of 868 cases, 0 false positives** | Setup |
| 2026-10-13 | Read why the plain cases were missed: the event that marks a variable going out of scope is a `reset` of the pointer, and the query read it as "overwritten, stop following". Leaving scope still holding the allocation is the leak. Those events now carry a marker (`<scope-end>`) and count as the leak point | Juliet 401: **648 of 868 (74.7%)**, but **520 false positives** | Advance in recall, false positives appear |
| 2026-10-13 | The 520 false positives were all in `goodB2G1` and `goodB2G2` of variants 02 to 15: the `free` sits behind a constant condition (`if(1)`, `if(5==5)`, `if(staticTrue)`, `if(staticReturnsTrue())`, `switch(6)`) and the graph took both sides as possible. Added constant folding: literals, comparisons, macros with an integer value, file-level variables with a literal initializer that are `const` or never assigned, functions that only return a literal, and a switch on a constant | False positives 520, then 240, then **200**. The 200 left are variants 09, 10, 11, 13, 14, whose flags (`globalTrue`, `GLOBAL_CONST_TRUE`, `globalReturnsTrue()`) are defined in support files that are not in the data. CWE-416 and CWE-415 on Juliet unchanged (134/138, 150/272, 0 false positives) | Advance; remaining false positives are a limit of the data |
| 2026-10-13 | **First reading on the development projects** (Git, curl, Redis, OpenSSL): allocation sites followed and alerts per KLOC (train / test) | Git 4.9 per KLOC, 0.792 / 1.278; curl **57 sites (0.2 per KLOC)**, Redis 5.5, 0.480 / 0.619; OpenSSL **60 sites (0.1)**. curl and OpenSSL are blind to allocation (`curlx_malloc`, `OPENSSL_malloc` wrap functions the code defines) | No advance: two blind, two far above 0.1 |
| 2026-10-13 | Read the Git alerts (a sample of 30 of 228): `getenv`, `branch_get`, `locate_simplify_state`, `tr2tls_get_self` taken for allocators because they return something allocated that is also kept in a table or cache; `hashmap_add(&map, &e->ent)` and `odb_source_free(&source->base)` hand a pointer **into** the block, which hands the block; wrapper macros not followed to the function they call. Three changes: an allocator proof that rejects a function that also stores what it returns, a call that receives `&p->f` or `p->f` and keeps it hands `p`, and macros followed to the function they wrap (also aliases of allocators) | Juliet 401 **fell to 276 of 868 (31.8%) with 80 false positives**: the integer and struct cases call `printIntLine(data[0])` and `printStructLine(&data[0])`, derived paths, and the new rule took them for hand-offs because the reader learning did not see that `free(data)` after using `data[0]` counts. Fix: freeing a base counts for its derived paths, and `&x` arguments enter the reader learning. Juliet back to 648 | Regression found by the benchmark, fixed |
| 2026-10-13 | Reordered `prepare_leaks`: readers, then who keeps what, then allocators, so that an allocator that hands the pointer to a call that keeps it is rejected too (a registry) | Git 0.163 / 0.152; curl 0.109 / 0.066; **Redis 0.027 / 0.031 but 0.7 sites per KLOC**; OpenSSL 38 sites. The same proof now rejects honest wrappers that pass the pointer to a helper (`zmalloc` updates a counter) | Alerts down, coverage down with them |
| 2026-10-13 | **Learned allocators**, the mirror of the learned releases: a name with at least 8 sites whose result is freed afterwards at least half as often as `malloc`'s (and 25%), and whose name carries the word of a standard allocator (`zmalloc`, `OPENSSL_malloc`, `xcalloc`) | Allocation sites per KLOC: Git 3.2, curl 2.2, Redis 1.8, OpenSSL 1.0. Alerts per KLOC train / test: Git 0.177 / 0.170, curl 0.109 / 0.066, Redis 0.098 / 0.073, OpenSSL 0.085 / 0.110 (0.175, 0.097, 0.091, 0.092 in all). **Query frozen here**; CWE-416 and 415 on Juliet unchanged; 83 tests | Development ends: near the limit on all four |
| 2026-10-13 | **Never used to design the leak query, measured once, frozen** (coverage rule: at least 1 allocation site per KLOC) | **tmux** 7.1 sites per KLOC, 0.277 / 0.495 (0.321 in all): **fails**. **SQLite** 0.8 per KLOC: **blind** by the rule (0.084 / 0.084 means little). **vim** 1.1, 0.044 / 0.043 (0.044): **passes**. **PostgreSQL** 3.6, 0.259 / 0.202 (0.244): **fails** | **Held-out: 1 pass of 3 measurable.** The leak query does not generalize as use after free did (5 of 8 projects) |
| 2026-10-13 | **Third round (protocol `f516c2a`).** Reading the alerts of OpenSSH (33) showed one general cause in at least five: the allocation is inside a compound test, `if (n < 0 \|\| (p = malloc(n)) == NULL) return -1;`, and the NULL branch was not recognised because the test was not a single comparison. The lexical split by exit type (error-like returns 29% Git, 42% OpenSSH, 4-6% curl and Redis) was inconclusive and drove no change | One change: null tests are read through `&&` and `\|\|` | Diagnosis |
| 2026-10-13 | First version cleared the NULL side of every test in a compound condition. A unit test showed it was unsound (`p = malloc(); if (n > 0 && p != NULL) free(p);` loses a real leak when `n <= 0`), so it was narrowed: on the true side of `\|\|` only an assignment test in a **later** operand counts (p is not even set when an earlier operand decides), on the false side of `&&` likewise; all-false of `\|\|` and all-true of `&&` always count | Sound version, unit tests added (93 graph tests pass) | Error found by a test, fixed |
| 2026-10-13 | Effect of the sound version. Juliet 401 unchanged (648 of 868, 200 false positives), 416 and 415 unchanged. Development projects: OpenSSH 0.210 to **0.153**, OpenSSL 0.078 to **0.069**, tmux, curl, Redis, Git unchanged. OpenSSH is now development (alerts read) and still fails | Kept: no project got worse | Result |
| 2026-10-13 | **Independent test, query frozen, measured once**: zlib `767c4c94` (26 KLOC, 1.9 sites per KLOC) 0.038; memcached `2d51e364` (42 KLOC, 1.9 sites per KLOC) **0.095**; libpng `18ea3e94` (83 KLOC) 0.4 sites per KLOC: **blind** (it allocates through `png_malloc` wrappers the rule does not follow) | zlib and memcached pass (memcached on the line), libpng blind | Held-out |
| 2026-10-13 | **Ownership, second round, as pre-registered.** Read all 35 alerts of tmux and the 389 of PostgreSQL by cause. tmux: objects made by `xcalloc`/`xmalloc` and linked into trees and lists by macros (`RB_INSERT`, `TAILQ_INSERT_TAIL`), constructors that also register what they return, `copy = s = xstrdup(p)`. PostgreSQL: about 190 of 389 from `palloc*`, `repalloc_array` and `pg_malloc_array` (memory a context frees), functions that return part of something that already exists (`defGetString`, `bms_add_member(set, i)`, `list_make1`) | Causes named; no code changed yet | Diagnosis |
| 2026-10-13 | Changes, all general: (1) a macro whose body uses token pasting (`##`) is an opaque call that takes the pointer, and a macro whose body the parser cannot read falls back to an ordinary call instead of swallowing it; (2) a macro that copies its parameter somewhere (`*head->last = (elm)`, `x = &(elm)->field`) is expanded, and `&p->f` stored anywhere gives `p` away; chained assignments give the first name the value; (3) `p = f(p, ..)` is not an acquisition for a learned allocator; (4) "returns an allocation" needs **every** `return` to be its own allocation or NULL; (5) an allocator whose own sites the query flags more than 3 times as often as malloc's (and 15%) is an arena's; (6) a variable or function declared as `int`, `char`, a struct by value cannot own an allocation; (7) `return &p->f` gives the block away | See next rows | Setup |
| 2026-10-13 | First run of these: Juliet 401 fell to **458 of 868 (52.8%)**, 140 false positives. Two causes found by variant: `p = f(p)` also excluded `realloc(NULL, n)` and the wrappers `data = badSource(data)` of variants 42 and 61 (limited to learned allocators), and the arena filter judged the `static badSource` of 26 files as one allocator with 100% flagged sites (it now leaves out names whose sites sit in the files that define them) | Juliet back to **648 of 868 (74.7%)**, 200 false positives; CWE-416 and 415 unchanged | Regressions found by the benchmark, fixed |
| 2026-10-13 | Development projects (total alerts per KLOC in all files), before and after the round | tmux **0.321 to 0.037**; PostgreSQL 0.244 to **0.147**; Git 0.175 to **0.103** (with the type rule and the field-address return); curl 0.097 to 0.064; Redis 0.091 to 0.081; OpenSSL 0.092 to 0.078. Four of six under 0.1, Git on the line. In PostgreSQL even `malloc` is flagged in 4.6% of its sites, so about 5% of allocation sites is the query's noise floor on real code; `palloc` is flagged less often than that (1.5%), so it is not told apart as an arena by rate | Advance on four projects; PostgreSQL stays above |
| 2026-10-13 | **Not used to design the leak query, never measured, query frozen**: libuv `ad0679ae` (331 files, 102 KLOC), OpenSSH portable `773771be` (310 files, 157 KLOC), Lua `b35736b` (40 files, 28 KLOC) | libuv 1.7 sites per KLOC, 0.055 / 0.138 (**0.078** in all): **passes**. OpenSSH 6.9, 0.249 / 0.154 (**0.210**): **fails**. Lua **0.0** sites per KLOC (it allocates through `l_alloc`, a function pointer): **blind**. Each alert is one allocation site, so the alert count is the number of distinct sites | **Held-out: 1 pass of 2 measurable**; with vim (0.028 now) the independent record for the leak query is vim and libuv pass, OpenSSH fails, SQLite and Lua blind |
| 2026-10-13 | CWE-416 and CWE-415 re-measured with the current extractor on all eight projects | Unchanged to the third decimal except Redis (use after free test 0.283 to 0.273, double free test 0.136 to 0.115) and PostgreSQL (use after free test 0.101 to 0.098); Juliet 134/138 and 150/272 | Confirmation |
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

## Protocol: CWE-401, memory leak (written on 2026-10-13 **before** the change)

New CWE for the graph arm. It uses the same events (allocation, free, uses, reassignment, flow) plus three new ones and a new query. The
learning of names follows the rule of the previous protocol: **no list of allocators, readers or owners written by hand**.

- **Query:** an allocation of a local variable that can reach a return (or the end of the function) on some path along which the variable is not
  freed, not handed on (stored, returned, passed to a function that keeps it) and not overwritten. Intraprocedural plus call summaries.
- **New events:** `escape` (a pointer copied into something else: `return p`, `x = p`, `s->f = p`, `*out = p`), `null` (the branch of an `if` where the
  pointer is known to be NULL, from `if (!p)`, `p == NULL`, `p != NULL`, `if (p)` and the same with an assignment inside the condition), and the
  allocation's callee name.
- **Allocators:** the C standard library only (`malloc`, `calloc`, `realloc`, `strdup`, `strndup`, `wcsdup`), plus functions the code proves to
  return one (a body that returns the result of an allocator, to a fixed point). No learned allocators in this version (a known gap).
- **Who takes ownership:** a call that receives the pointer stops the tracking only if the callee keeps it (a body that stores, returns or passes it on
  to something that keeps it, to a fixed point), or if the callee has no body and is not a **reader**. A reader without body is learned like the
  releases of the earlier protocol: at least 8 call sites and the pointer freed afterwards by the caller in at least 25% of them (a reader such as a
  printing function is followed by the caller's `free`; a function that takes ownership is not).
- **`p = realloc(p, n)`** keeps the old block alive on the path where `p` becomes NULL (the classic leak when `realloc` fails).
- **Data:** Juliet CWE-401, C cases only (the `new_*` and flows 81 to 84 are C++ and are left out, counted and named). Classification as in the gate (a
  report in a `*bad*` function of a BAD file is a hit, in a `*good*` function a false positive).
- **Development:** Juliet CWE-401 and Git, curl, Redis, OpenSSL. **Held-out:** tmux, SQLite, vim and PostgreSQL, which were not used to design
  this query; measured once after the query is frozen, with the coverage rule (the number of allocations the extractor sees per KLOC, at least 1) and success
  at most 0.1 alerts/KLOC. The alert count overstates independent mistakes, so the number of distinct allocation sites is reported with it.
- **Not in this change:** the CWE-401 variants through function pointers, pointer-to-pointer and static globals (flows 32, 44, 45, 54 to 68 are expected to be
  partly missed), learned allocators, C++ `new`.

## Protocol: ownership, second round (written on 2026-10-13 **before** the change)

The first held-out measure of the leak query failed on two of three measurable projects (tmux 0.321, PostgreSQL 0.244; vim passed, SQLite was blind). The
question the query cannot answer well is who owns a pointer after it leaves the function's hands. This round reads the alerts of those two projects, so they join
Git, curl, Redis and OpenSSL as **development** projects for the leak query, and improves how ownership is decided, with changes that are general and learned from
the code (no list of names).

- **Plan:** read the alerts of tmux and PostgreSQL grouped by cause (not one by one), name the cause of each group, and change the analyzer only for causes that
  are general (a pattern of C, not a name). Keep every change if it lowers the alerts on the six development projects without costing Juliet 401 more than 1 point
  of recall or adding false positives, and without changing CWE-416 and CWE-415 on Juliet.
- **Held-out:** three projects never used for the leak query and never measured before, blobless clones at their head, all `.c` files, headers read for `#define`s:
  **libuv** (`libuv/libuv`), **OpenSSH portable** (`openssh/openssh-portable`) and **Lua** (`lua/lua`). Measured once with the query frozen, the coverage rule (at
  least 1 allocation site per KLOC, else blind) and success at most 0.1 alerts/KLOC on all files. The number of **distinct allocation sites** that raise an alert is
  reported next to the alert count, since one wrong ownership decision yields many alerts.
- **Not in this change:** C++ `new`, the Juliet flows through pointer copies, pointer-to-pointer, function pointers and static globals.

## Protocol: error paths and arenas, third round of the leak query (written on 2026-10-13 **before** the change)

After the second round the leak query is under 0.1 alerts/KLOC in six of nine measurable projects and about 5% of allocation sites remain flagged in correct code. The
next suspects are paths that leave the function through an error and memory that an arena or a context frees. This round measures first, then changes.

- **Measure first:** for the alerts of Git, PostgreSQL, OpenSSH portable and the other development projects, count by **kind of exit** (a return of an error value:
  a negative literal, NULL, a variable named like an error status; a return of anything else; the end of the function) and by the allocation callee, and by the **last
  event before the exit** (a failed call, a failed NULL check, a goto to a label). OpenSSH portable joins the development projects (its alerts will be read);
  libuv and Lua stay untouched.
- **Rule for acting:** a change is made only if one kind of exit or one cause holds at least 25% of the alerts of a project, and it must be a pattern of C that does not
  name a function. Kept only if the six development projects and OpenSSH do not get worse in total, Juliet 401 does not lose more than 1 point of recall or gain false
  positives, and Juliet 416 and 415 do not change.
- **Held-out:** three projects never used for the leak query and never measured: **zlib** (`madler/zlib`), **libpng** (`glennrp/libpng`) and **memcached**
  (`memcached/memcached`), blobless clones at their head, all `.c` files, headers read for `#define`s. Measured once with the query frozen, the coverage rule (at least 1
  allocation site per KLOC) and success at most 0.1 alerts/KLOC in all files.
- **Not in this change:** C++ `new`, Juliet flows through pointer copies, pointer-to-pointer, function pointers and static globals, allocation through a function pointer
  (Lua, which stays blind).

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

## Protocol: direct comparison on the benchmarks of the reference papers (written on 2026-10-13 **before** any measurement)

Purpose: put the graph arm on the same data that Li et al. (arXiv 2601.19239) used for RepoAudit, KNighter, CodeQL and Semgrep, so that the
comparison is on one benchmark and not on numbers of different kinds. Data: their replication package (`Feng-Jay/LLM4Security`, commit
`122e915`). The queries are the ones frozen at `6bc9e39`: **no change to the extractor or the queries during this experiment**; anything changed
afterwards is reported as a new version, not folded into this result.

**A. In-house benchmark (known vulnerabilities, recall).** `data/in_house/c/linux_check_table.csv`: 40 CWE-401, 10 CWE-416 and 14 CWE-476 Linux kernel
cases, the vulnerable version being the parent of the fix commit.
- Queries: CWE-401 `memory_leak`, CWE-416 `use_after_free`. CWE-476 has **no query** in the graph arm, so its 14 cases are reported as not covered (0 by
  construction), not tuned for.
- Unit: the case. Graph built from the `.c` files changed by the fix plus, for the learned names (allocators, release functions) that need project
  statistics, all `.c` and `.h` files of the directories of those files at the parent commit.
- Detected: at least one alert of the query in a changed file within 10 lines of a hunk (old line numbers), the criterion of `fixcommits.py`. Also reported:
  exact (the alert inside the hunk), file-level (any alert in a changed file) and noise (alerts of the query in changed files that are not near a hunk).
  For detected cases the query is also run on the fixed version: an alert near the hunk that disappears is "fix-sensitive".
- Their criterion is that the tool reports the labelled vulnerable program point; the 10-line window is looser, which favours us, and is said where the
  numbers are compared. Their reference: RepoAudit 22/40 (55.0%) on 401 and 1/10 on 416; KNighter, CodeQL and Semgrep 0.

**B. Real-world projects (reports and sampled false discovery rate).** Table III/V of the paper, C projects, at their commits: Linux `6093a68`
(`sound`, `mm` for CWE-401; `net`, `drivers/net` for CWE-416), ImageMagick `3bf1076` (CWE-401), vim `8feaa94` (CWE-416). The CWE-476 projects (`peci`,
`gpac`, `bitlbee`) are not covered for the same reason as above.
- Reports = alerts of the query over all files of the project (directory for the kernel). Sample: up to 10 alerts per project, every k-th in path and
  line order (no choice by hand), read by one reviewer with the surrounding code and, when needed, the called functions; true positive = a real memory
  leak or use after free in the code as it stands; sampled false discovery rate = false positives / sampled, the paper's definition.
- The reviewer is the author of the extractor and reads without running the code; same limits as the paper's two authors, one person fewer.
- If a project cannot be extracted (time or memory), that is reported as such.

**What would count as a result.** Recall on A against 55% / 10% (RepoAudit) and 0 (the others); reports and SFDR on B against their Table V (RepoAudit:
333, 356 and 348 reports for sound, mm and ImageMagick, all sampled alerts false; 3, 1 and 32 for the CWE-416 projects). A result worse than the reference
is reported as such.

### Result of the direct comparison (2026-10-13), protocol above

**A. In-house benchmark (Linux kernel).** `python -m src.graph.paper_benchmark cases`: all 50 CWE-401 and CWE-416 cases analysed (the files of the fix plus the `.c` and
`.h` of its directories at the parent commit, downloaded from the raw-content server because a sparse checkout of the kernel was too slow here), the 14
CWE-476 cases not covered (no query). **In all 50 cases the coverage diagnostic is zero: 0 `free` events and 0 allocation sites of the standard library.** The kernel
never calls `malloc` or `free` (it has `kmalloc` and `kfree`), and the arm learns release functions and allocators by calibrating against the project's own use
of the standard ones, so with none present it has nothing to learn from. The arm is **blind** on this benchmark, which is not a recall of 0% of a working
detector: no alert, near a hunk or anywhere (0 alerts in 50 cases), and no claim either way. A hand-written seed for the kernel API was not added (the arm
takes no lists of names). Reference: RepoAudit 55.0% (22/40) and 10% (1/10), KNighter, CodeQL and Semgrep 0.

**B. Real-world projects, frozen queries (`6bc9e39`).** One reviewer, 10 alerts per project chosen as every k-th in path and line order, no run of the code.
| Project (commit) | Query | Reports | Sampled true / false | Reference reports (sampled false discovery rate) |
|---|---|---|---|---|
| ImageMagick `3bf1076` (288 `.c`) | memory leak | **454** | 0 / 10 | RepoAudit 348 (10/10), CodeQL 141 (9/10), Semgrep 37 (10/10), KNighter 0 |
| vim `8feaa94` (205 `.c`) | use after free | **235** | 0 / 10 | RepoAudit 32 (10/10), Semgrep 2 (2/2), CodeQL 1 (1/1), KNighter 0 |
| Linux `sound`, `mm`, `net`, `drivers/net` (`6093a68`) | both | not measured | | blind as in A: the probe on `mm` (125 files) gives 0 `free` events |

In ImageMagick 8 of the 10 sampled alerts were a test written with a cast, `if (p == (float *) NULL)`: the extractor compared the text of the other side with `NULL` without
removing the cast, so the NULL branch was not recognised. The other two: `Resize*` wrappers that free the old block on failure, and a reference returned by a getter.
In vim 6 of the 10 are one `vim_free(buf); return NULL;` seen as a free followed by uses in code that is not reachable from it, and the others a free in a branch
that returns, a callee that reassigns a global, and a reassignment right after the free. **0 of 20 sampled alerts are real, a sampled false discovery rate of 100% for both,
the same as the reference tools**, with more reports than any of them on both projects.

**C. A new version, after reading the frozen result.** `p == (T *) NULL` is read as a null test (casts removed on the compared side; `_text(_strip(other))`),
one line and one test. Juliet unchanged (CWE-401 648/868 with 200 false positives, CWE-416 134/138, CWE-415 150/228 with the exclusion filter);
tmux, curl, Redis, OpenSSL, Git, OpenSSH, zlib, memcached, libuv and vim unchanged (the leak query), and use after free and double free on tmux, curl, Redis, OpenSSL and Git unchanged.
ImageMagick falls from **454 to 65 reports** (0.119 train / 0.158 test alerts per KLOC). A new sample of 10 of the 65, read the same way: **3 likely real, 7 false**
(sampled false discovery rate 70%, against 100% / 90% / 100% of the reference tools on the same project). The three are leaks on error paths:
`equalize_map` not released when the next allocation fails (`accelerate.c`), `density_xy` not released in the failure block of `GetImageFeatures` (`feature.c`), and
`profiles` not released when `ThrowMIFFException` leaves `ReadMIFFImage` (`miff.c`); not confirmed by running and not reported upstream. The seven: a registry
reference returned by a getter, a pointer handed to the image (`SetImageProfilePrivate`), a free guarded by `program_name != program_invocation_name`, a free in every
other case of a `switch`, a macro that frees `map` (`RelinquishNodesAndMap`), and two alerts with a hit before the allocation that look like an artifact of the
extractor. **ImageMagick is a development project for this version** (its alerts were read twice), so the 70% is a hint, not an independent measure.

## Protocol: CWE-476, null pointer dereference, in the graph arm (written on 2026-10-13 **before** the change)

Why now: it is the third CWE of the reference papers, the one where RepoAudit has its best real recall (4 of 14 kernel cases) and where **the arm is not blind
on the kernel**, because a NULL source needs no allocator or release function to be learned.

Query `null_dereference` (two patterns, both intraprocedural and over the same graph):
1. **Null source to dereference:** a `p = NULL` (also `T *p = NULL`) or a branch known NULL (`if (!p)`, `p == NULL`) from which a `use` of `p` (a dereference: `p->x`, `*p`, `p[i]`,
   or a callee that dereferences its parameter) is reachable with no new value, no allocation and no **non-NULL test** of `p` in between.
2. **Dereference before the test:** a `use` of `p` from which a NULL test of `p` is reachable with no new value in between (the dereference-then-check pattern).

Extractor changes, all general: a new event `nonnull` on the branch where `p` is known non-NULL (`if (p)`, `p != NULL`, the else of `if (!p)`), also inside `&&` and `||` after the
left operand (`p != NULL && p->x`); an explicit marker on assignments of NULL. The new event is a pass-through for the existing queries.

Development: Juliet CWE-476 (386 BAD, with `data = NULL`, `deref_after_check`, `null_check_after_deref`, `binary_if` with `&`; the 2 C++ `class` cases left out), scored like the
other CWEs (a hit in a `*bad*` function, a false positive in a `*good*` one); Git, curl, Redis and OpenSSL for the real-code side (alerts per KLOC, limit 0.1, train/test by file hash).
Frozen after that, measured once: tmux, PostgreSQL, SQLite, vim, libuv, OpenSSH, zlib, memcached (none of their NULL alerts has been read), then the reference benchmarks:
the 14 kernel cases of Li et al. (same detection criterion as for the other CWEs) and their CWE-476 projects (gpac, bitlbee; `drivers/peci` if it can be read), with 10 sampled alerts read per project.

Acceptance: Juliet 416, 415 and 401 unchanged (the new event must not move them); a change is kept only if the development projects do not get worse in total. Expectation written down:
real code is full of intentional patterns (a test after a macro that dereferences, `p ? p->x : 0`), so a count above 0.1 per KLOC on some project is likely; it is reported as it comes.

### Result of the CWE-476 work (2026-10-14), protocol above

**What was built.** Event `nonnull` (the branch where a pointer is known not NULL: `if (p)`, `p != NULL`, the else of `if (!p)`, the right side of `p && ..`, the right side of
`||` after a NULL test, the arms of `p ? a : b`, the body of a loop whose condition tests it); a marker on assignments of NULL; calls wrapped around a test (`unlikely(!p)`,
`BE (p == NULL, 0)`) read as the test; `return p` and arguments handed to calls that are not resolved are no longer dereferences; a callee summary `derefs` (the callee dereferences
the parameter on a path from its entry where it was not tested, reset or released first), so that `sink(p)` counts only if `sink` dereferences without a guard. **Queries:**
`null_dereference`, a pointer set or known NULL that is dereferenced on the one path that follows (no decision in between, so no path condition is needed), and `check_after_deref`,
a dereference followed on the one path that follows by a NULL test of the same pointer, kept apart because its count on real code is far above the limit.

**Three things tried and dropped, in order, on Git, curl and Redis (development).** The path walk of the first version (any path from a NULL to a dereference) gave **11.5 alerts per
KLOC in Git, 13.1 in curl, 8.4 in Redis**: `T *p = NULL` followed by conditional assignments, `goto error` with a NULL and a guard on another variable at the label. A filter that
required the NULL to be the only value that could reach the dereference lowered Git to 1.5 and curl to 3.6, still far above 0.1, and cost 36 Juliet cases whose flags live in support
files (variants 09 to 14). The rule kept is that **no decision may lie between the cause and the effect**: Git **0.035** per KLOC, curl **0.082**, Redis **0.028**, OpenSSL **0.010**.

**Juliet CWE-476 (the 2 C++ `class` cases left out): `null_dereference` 168 of 270 cases (62.2%), 0 false positives; `check_after_deref` 18 of 270 (6.7%), 0.** Found: variants 01 to 08, 15 to 18
(including the `binary_if` with `&` against `&&`), 21, 22, 41, 51 to 54, and the three of nine of 09 to 14 that need no flag. Not found: 09 to 14 in part (flags in support files),
31, 32, 34 (copies of the pointer), 44 (function pointer), 45 (static global), 63 to 68 (pointer passed by address across files), 81 and 82 (C++). Juliet 416, 415 and 401 unchanged.

**Real code, total alerts per KLOC, limit 0.1, `null_dereference`.** Development: Git 0.035, curl 0.082, Redis 0.028, OpenSSL 0.010. **Never seen by this query, measured once:** tmux 0.009, PostgreSQL 0.030,
SQLite 0.039, vim 0.038, libuv 0.010, zlib 0.000, memcached 0.024 (**all pass**) and **OpenSSH 0.907 (fails)**. Reading 12 of its 142 alerts: all one cause, `fatal_f(..)` after a NULL test.
It is `#define fatal_f(...) sshfatal(..)` with `sshfatal` declared `__attribute__((noreturn)) __attribute__((format(..)))`: the declaration reader did not accept another attribute after
the `noreturn`. **Fix (general, one regex, one test): the declaration may carry other attributes around `noreturn`.** OpenSSH falls from 142 to 7 alerts (0.045); it is a development project now.
Side effects, all measured: Juliet 416, 415, 401 and CWE-476 unchanged; use after free and double free unchanged on Git, curl, Redis, OpenSSL; the leak query on **Git 0.103 to 0.070, OpenSSL 0.069 to 0.050 and OpenSSH 0.153 to 0.140**
(the NULL tests inside `&&`, `||`, `?:` and loop conditions now reach it too), curl, Redis, tmux, libuv, vim, memcached unchanged. So 12 of 12 projects are under 0.1 for this query, 7 of them never seen by it before the measure.
`check_after_deref` is not under the limit: 1.7 to 3.3 per KLOC (Git 1338 alerts, curl 562, Redis 793, OpenSSL 1499, with the single-path rule), mostly defensive tests of pointers the contract says are not NULL.

**Direct comparison with the reference papers (their benchmark, the frozen query).**
| Benchmark | RepoAudit | KNighter | CodeQL | Semgrep | Graph, `null_dereference` (and `check_after_deref`) |
|---|---|---|---|---|---|
| Kernel, 14 known cases (recall) | 4/14 | 0 | 0 | 0 | **0/14** (16 alerts in all the contexts, none in a changed file); `check_after_deref` **1/14** (`tw5864`: `vb` dereferenced at line 1400 and tested after, inside the hunk, gone after the fix) with 54 other alerts in changed files |
| gpac `c6a72c3` (reports) | 77, 10/10 false | 0 | 6345 | 0 | **164** (3801 for `check_after_deref`) |
| bitlbee `8af06ca` | 374, 8/10 false | 0 | 284 | 1 (0/1 false) | **4** (376) |
| Linux `drivers/peci` (7 files read) | 3, 3/3 false | 0 | 3 | 0 | 0 (0) |
Read by one reviewer, no run of the code. **bitlbee: all 4 alerts read, 3 distinct sites, all with a NULL branch that falls through to the dereference**: `if (!(query = jabber_make_packet(..))) { log; xt_free_node(node); }` then
`jabber_cache_add(ic, query, ..)` twice (the error branch does not return), and `if ((ic = irc_channel_by_name(..)) || (ic = irc_channel_new(..))) {..}` then `ic->set` (counted twice). **gpac: 10 sampled, 7 are
`GF_SAFEALLOC(p, T)` followed by a dereference with no test** (the macro leaves NULL when the allocation fails: a real CWE-476 on allocation failure that I count as true, a maintainer may call it harmless), 1 is
`assert(att)` before the dereference (a contract), 1 a macro `NARG_STR(..)` read as a NULL, 1 `if (!ctx->mpd) dasher_setup_mpd(ctx);` where the callee sets the field; so 3 of 10 false by my count, 10 of 10 false if
allocation failures are not defects. The values for the other tools are those of Table V of the paper as printed (read from a text extraction with scrambled columns, the counts of reports are certain, the labels less so).

## Protocol: CWE-476 on the Linux kernel subsystems of the reference papers (written on 2026-10-14 **before** the run)

The queries are the ones at `2d79aeb` (no change allowed). Linux `6093a68`, subsystems `mm`, `sound`, `net`, `drivers/net` (the ones Li et al. and RepoAudit analysed), query `null_dereference`
(and `check_after_deref` counted apart). Reports = alerts over all files of the directory; a sample of up to 10 per subsystem, every k-th in path and line order, read by one reviewer without running the code,
true positive = a NULL that reaches a dereference on the path the alert names, in the code as it stands (a dereference after an allocation with no test counts as true and is marked as such, as for gpac).
Compared with RepoAudit (333 reports for `sound`, 356 for `mm`, 3 for `net`, 1 for `drivers/net`, all sampled alerts false except where the paper says otherwise) and KNighter (6, 3, 12, 79). CWE-401 and CWE-416
stay blind on the kernel and are not run. If a subsystem cannot be extracted (time or memory) that is reported.
