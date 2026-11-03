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

### Result of CWE-476 on the whole kernel subsystems (2026-10-14), protocol above

Run on the whole directories, Linux `6093a68`: `mm` (160 files), `sound` (1842), `net` (1528), `drivers/net` (3505), with the kernel's `include/` and `arch/x86/include/` read for `#define`s.
**Five runs, each changed only after reading the alerts of the one before** (so the first is the frozen one and the last is development for the kernel):
| Run | mm | sound | net | drivers/net | What was read and changed |
|---|---|---|---|---|---|
| 1, no kernel headers | 6 | 7 | 35 | 70 | 6 of 7 `sound` alerts were `cont ? cont->size : 0` followed by `cont->size`: a `null` event inside a conditional expression stayed on the path to the next statement (a bug of mine, the same for `a && b`); `panic()` and `for_each_*` unknown without the headers |
| 2, + `include/`, expression tests give non-NULL facts only | 14 | 0 | 31 | 48 | 12 of the 14 `mm` alerts were a macro's own temporary (`tl` in `local_trylock`) with source and dereference on one line; `typeof(*p)` counted as a dereference |
| 3, + `typeof`/`offsetof` unevaluated, one-line pairs dropped | 0 | 0 | 28 | 48 | 5 of the `net` alerts were `skb = NULL; ... dev_kfree_skb(skb)` (the callee tolerates NULL through an inline function in a header); `&rt->dst` taken for a dereference; two functions merged by a parse error |
| 4, `&p->f` tagged as an address, a call to an unknown function before the dereference counts as a possible guard, functions with parse errors skipped | 0 | 0 | 3 | 40 | 29 of the 40 `drivers/net` alerts were `u32 x = 0; SET_FIELD(x, ..)`: a plain `0` taken for NULL |
| 5, `0` is NULL only for a local declared with a `*` | 0 | 0 | **3** | **9** | all read |
All five general fixes, with tests (111 graph tests), left the Juliet numbers (416, 415, 401, 476) unchanged and the development projects not worse (Git 0.028 / 0.036, curl 0.016 / 0.000, Redis 0.013 / 0.000, OpenSSL 0.010 / 0.004,
tmux 0.000, OpenSSH 0.022 / 0.031 per KLOC for `null_dereference`; use after free and leak unchanged).

**The 12 alerts left, all read (one reviewer, no run):** **1 true: `sxgbe_rx` in `drivers/net/ethernet/samsung/sxgbe/sxgbe_main.c`**: `if (unlikely(!skb)) netdev_err(..); prefetch(skb->data - ..);`, the error branch does not leave. In the
current kernel master (`4056b3c9d3c9`) that branch has a `break;`, so it was a real defect that has since been fixed. The other 11 are false: three `struct_size(p, ..)` where `p` was NULL (a size macro that the extractor still evaluates),
a `for_each_pci_dev(tdev)` loop macro that assigns `tdev`, two correlated conditions (`hs_activate` is true exactly when `hscfg_param` is NULL; `fs_fw_usable`), a callee that sets the field (`sis900_default_phy`), a guard on a sibling pointer
(`htc_proc_trailer` tests `next_lk_ahds` before it uses `n_lk_ahds`), and in `net` one correlated condition, one `struct_size`, one loop macro. **So 1 of 12 true (sampled false discovery rate 92%) on 7035 files, 12 reports against the hundreds
that the reference tools give on the same subsystems for the memory-related CWEs**; the reference papers did not run CWE-476 on these four subsystems, only on `drivers/peci`, so there is nothing to compare these counts with directly.
Whether the arm "finds something new" on the kernel: at this commit it found one real defect that is already fixed, and nothing that is still there; to look for new ones the same run has to be repeated on the current master.

## Protocol: false positives on SV-COMP memory-safety tasks (written on 2026-10-14 **before** any measurement)

Why: so far the false positive rate of the arm was measured on real code assumed correct (alerts per KLOC) and on samples of ten alerts read by one person. SV-COMP (`sv-benchmarks`, `gitlab.com/sosy-lab/benchmarking/sv-benchmarks`,
head `c7d7c3e`) has C programs with an **expected verdict decided by verifiers**: a `true` program has no memory-safety violation on any execution, so any alert on it is a false alert, counted without anybody reading it.

Data: the 510 tasks with a `valid-*` property in the directories `memsafety*`, `ldv-memsafety`, `list*-properties`, `heap-manipulation`, `forester-heap`, `ddv-machzwd`, `list-simple`, `ldv-regression`, `ldv-sets`, `heap-data`, `memory-alloca`:
268 `valid-memsafety` true; false with sub-property `valid-deref` 115, `valid-free` 18, `valid-memtrack` 71; `valid-memcleanup` 36 false and 2 true. 442 of the files are preprocessed `.i`.

Queries, frozen at `abf3004` (no change during the experiment): `null_dereference`, `use_after_free`, `double_free`, `memory_leak`; `check_after_deref` is run and reported apart. Each task is built alone (its input files, no headers,
only the C standard library known), the extractor as it is.
- **False positive rate**: share of the 268 safe tasks with at least one alert of any of the four queries, and per query; the alerts of 20 flagged tasks (every k-th in path order) are read and the cause named.
- **Recall at task level** (no location is given, so an alert anywhere in the task counts, which is generous): `valid-deref` violations by `null_dereference` or `use_after_free` (an invalid dereference includes a use after free), `valid-free` by `double_free`,
  `valid-memtrack` by `memory_leak`; per query and as the union. `valid-memcleanup` (also reports what is still allocated at exit, a stricter property) is reported apart.
- Files that fail to parse are listed. An alert in a false task of another sub-property is not counted either way.
Expectation written down: the tasks are small and written to stress verifiers (nondeterministic branches, pointer arithmetic, aliasing through arrays and lists, `__VERIFIER_*` calls), so a path-insensitive arm should flag a
fair share of the safe tasks and miss many violations; the point is the number, not a target.

### Result on SV-COMP (2026-10-14), protocol above

`python -m src.graph.svcomp`: 507 tasks (the protocol said 510 property entries; three tasks carry two), no parse failure, no error, 12 seconds in all. Queries frozen at `abf3004`.

**False positives, on the 268 safe tasks (`valid-memsafety` true), counted with no reading:**
| Query | Safe tasks flagged | Alerts |
|---|---|---|
| `null_dereference` | **0** | 0 |
| `use_after_free` | **0** | 0 |
| `double_free` | **0** | 0 |
| `memory_leak` | 9 (3.4%) | 9 |
| any of the four | **9 of 268 (3.4%)** | |
| `check_after_deref` (secondary) | 80 (29.9%) | 227 |
The 9 tasks, all read: five `tree_*` programs of `memsafety-ext` (`main` allocates a node that other nodes keep, and the code releases the tree through another pointer by a traversal, which an ownership summary
cannot follow), `lockfree-3.0` (`push` allocates and returns on the branch of a failed compare-and-swap), and three `ddv-machzwd` programs (a model of `pci_get_class` allocates and returns NULL on one branch). None is a defect of
the program; they are the ownership limit of the leak query already found on real code (about 5% of allocation sites).

**A bug found by this run, in the secondary query only.** 80 safe tasks for `check_after_deref` came from `while (node) { node = node->next; }`: the second half of the query kept walking after the pointer got a new value and reached the
test of the next iteration. Fixed (the walk stops at a new value, with a test); Juliet unchanged (18 of 282, 0 false positives) and **the safe tasks flagged fall from 80 to 18 (6.7%, 28 alerts)**; the main four queries are not touched by it.
Real-code counts of `check_after_deref` were measured before the fix and are lower now.

**Recall at task level** (an alert anywhere in the task counts, so it is generous): `valid-deref` violations (115): `use_after_free` **4**, `null_dereference` **0**; `valid-free` (18): `double_free` **2**; `valid-memtrack` (71): `memory_leak`
**22 (31%)**; `valid-memcleanup` false (36): 0 (that property also counts what is still allocated at exit, which the leak query does not report).
Reading: on programs written to stress verifiers the arm is **quiet on safe programs (3.4%, none for the three pointer-validity queries)** and **finds a small part of the violations** (a `valid-deref` violation is mostly an out-of-bounds access, an uninitialized pointer or pointer
arithmetic, none of which is a NULL or freed pointer; the arm has no queries for those). The two numbers say it trades recall for silence, as on real code.

## Protocol: the model writes the rule from the graph's findings (written on 2026-10-14 **before** the run)

Question: if the generator is shown the real alerts of the event-graph analysis instead of the findings of a language model, does a local model write a Semgrep rule that passes the gate (Juliet on held-out variants,
no false positives, and at most 0.1 alerts per KLOC on the Git sources)? The graph writes no rule; it plays the role the detector played (`python -m src.graph.export_findings --cwe CWE-416`: 206 findings over the 300 CWE-416
files, written as `log_<file>.json` with the pointer, the two lines and a description of the path), and `synthesize --example-mode graph` shows three of them, as it showed three findings of the detector. Generator, corrector, gate, folds and
real-world files are unchanged.

Conditions, CWE-416, template format, 5-fold cross-validation by variant, seeds 1 and 2 (the same folds and the same Git files as the runs they are paired with):
- `graph4b`: combo C (Qwen3-4B), against the `qwen4b` run (detector findings; recall 30.0%, rules that match nothing in 7 of 10 folds, 0 accepted).
- `graph`: combo D (Qwen3-Coder-30B), against B0 (detector findings; 25-fold recall 75.8%, 2.92 alerts per KLOC, 0 accepted).
Paired comparison with `python -m src.pipeline.compare`, the criterion of `docs/ablation_plan.md` (bootstrap interval over folds, a difference of at least 0.10 for an effect); the number of accepted folds is reported whatever the interval says.

What would count as a result: the 4B writing rules that detect (recall well above 30%) with the same findings quality as the 30B; the 30B lowering the real-world alerts below its 2.5 per KLOC, or having accepted folds with more than the narrow recall of `pairs`.
Two things to read it with, written down now: (1) the findings are better than the detector's (0 false positives in the safe functions against 34% on the safe files for the 3B detector) and give exact lines, so any effect is the effect of the findings' quality, not a new kind of help;
(2) the description of a finding says "released at line a and used at line b on a path with no new value", which is the strategy of the template, so the arm is the template arm and is reported with it, apart from the free-form YAML arm. A free-form arm (`--format yaml`) with the graph findings
is the next step only if this one shows an effect.

### Result: the model writes the rule from the graph's findings (2026-10-14), protocol above

CWE-416, template format, 5-fold cross-validation by variant, seeds 1 and 2, the same folds and Git files as the runs they are paired with. Summaries: `logs/crossval/C/CWE-416/20261014-150439.json`, `…-152309.json` (4B) and
`logs/crossval/D/CWE-416/20261014-154341.json`, `…-163555.json` (30B); comparison with `python -m src.pipeline.compare`.
| Model | Findings shown | Folds | Accepted | Recall | Precision | Juliet false positives | Real-world alerts per KLOC |
|---|---|---|---|---|---|---|---|
| Qwen3-4B (C) | detector (`qwen4b`) | 10 | 0 | 30.0% | 26.2% (1 fold) | 33.1 | 0.008 |
| Qwen3-4B (C) | graph | 10 | **0** | 20.0% | 24.5% (1 fold) | 60.2 | 0.014 |
| Qwen3-Coder-30B (D) | detector (B0) | 10 | 0 | 71.6% | 89.4% | 9.0 | 2.53 |
| Qwen3-Coder-30B (D) | graph | 10 | **0** | **91.6%** | 69.8% | 29.4 | **4.76** |
Paired differences, graph minus detector: 4B recall -0.100 (interval -0.40 to +0.20), no effect; **30B recall +0.200 (interval -0.011 to +0.368, below the criterion because the interval includes 0), precision -0.197 (interval -0.343 to -0.047), Juliet
false positives +20.4 (+7.2 to +33.6), real-world alerts +2.22 per KLOC (+0.43 to +4.00)**: the rules got broader, not quieter. 0 folds accepted in 20.
Reading: the findings are better than the detector's (exact lines, no false positives in the safe functions) and the 30B got to a rule that detects at once (fold 1: recall 100% in attempt 0), but the rule it wrote is the generic taint rule whose sink is any use of the pointer, which also matches the
`free` statement that marks it; that is the structural defect of `findings.md` (about 80% of the alerts on the source line), and a finding that says "released at line a and used at line b" does not tell the model to leave line a out. The graph's information about *where*
the defect is does not carry the information about *what the rule must exclude*; that comes only from the real-world feedback, which was already in the loop. Two things the comparison does not say: the descriptions give away the strategy (the arm is the template arm), and the free-form YAML arm
was not run (the protocol made it conditional on an effect, and there was none on the quantity that decides acceptance).

## Protocol: the model writes the rule from the graph's findings for CWE-415 and CWE-476, accepted by validity (written on 2026-10-14 **before** the run)

Why: the run for CWE-416 gave the 30B a recall of 91.6% from the graph's findings but rules too broad for the real-world limit. The question for the other CWEs is the one the TCC1 asks (is the generated rule *valid*, grammatically and on cases it was not shown),
so the acceptance here is by validity and the real-world noise is measured beside it, not used to reject.

Setup: combo D (Qwen3-Coder-30B, local), `--format yaml` (free form: the model writes the whole rule, no strategy given; only the generic Semgrep documentation and the findings), `--example-mode graph` (CWE-415: 150 findings of `double_free`, CWE-476: 168 of `null_dereference`,
exported with `python -m src.graph.export_findings`; the exported findings of CWE-401 exist, 848 of `memory_leak`, and are not used in this run), 5-fold cross-validation by flow variant, seeds 1 and 2, up to 6 corrections.
**Accepted = train recall of at least 50% and no false positive on the Juliet files, and (the change from the other runs) no real-world limit**: `--max-negative-rate 1000`, so the Git sources still grade each attempt and their alerts per KLOC are in the feedback and in the summary,
but do not reject. Reported per CWE: folds accepted, held-out recall and precision, Juliet false positives, real-world alerts per KLOC, valid rules (grammatical validity: the share of attempts that reach the gate), and the number of folds that would pass the 0.1 limit.
Not run (cost, about 100 minutes per CWE and seed pair): the same runs with the detector's findings as the baseline. Without it, a result is a level, not an effect of the graph; the comparison with the detector findings of the same CWE is the next step if the level is worth it.
What would count as a result: accepted folds with a held-out recall well above what the template arm gave on CWE-415 (0%); a free-form rule for CWE-476 that detects held-out variants with no false positive. A result under that is reported as such.

### Result: the graph's findings on CWE-415 and CWE-476, accepted by validity (2026-10-15), protocol above

Combo D (30B local), free-form YAML, `--example-mode graph`, 5-fold cross-validation by variant, seeds 1 and 2, `--max-negative-rate 1000` (the Git sources grade and feed back, they do not reject). Summaries:
`logs/crossval/D/CWE-415/20261015-031019.json`, `…-034743.json` and `logs/crossval/D/CWE-476/` (the two summaries of 2026-10-15 with `example_mode: graph`).
| CWE | Folds | With a rule | Accepted | Mean held-out recall (median) | Folds with recall of 50% or more | Folds with 0 Juliet false positives and recall above 0 | Mean Juliet false positives | Real-world alerts per KLOC (mean; folds at or under 0.1) |
|---|---|---|---|---|---|---|---|---|
| 415 | 10 | 9 | **0** | 64.3% (69.9%) | 8 | 1 | 89.3 | 4.55 (2) |
| 476 | 10 | 10 | **0** | 23.9% (7.9%) | 3 | 0 | 40.3 | 52.8 (4) |
**CWE-415.** The template of the use after free gave 0% on this CWE; in free form with the graph's findings the 30B reaches a held-out recall of 64.3%, and 8 of 10 folds detect at least half of the unseen variants. One fold is clean (seed 1, variants 03, 06, 07, 09, 11, 13, 15, 31, 61:
recall 78%, precision 100%, 0 Juliet false positives, 0.43 alerts per KLOC); it was not accepted because its *train* recall was under 50%. Two folds have a rule that detects nothing. The others detect more and match more: 84 to 144 Juliet false positives and about 6.7 alerts per KLOC
(one has 120 false positives and 0.01 alerts per KLOC, a rule broad on the Juliet files and narrow on Git). So the free form with the graph findings makes a rule that is *valid* (it runs, it detects held-out variants) and not yet *quiet*: no fold passes the validity acceptance either.
**CWE-476.** Weak. Half of the folds (5) have a rule that matches nothing (recall 0%, 0 false positives); the folds whose rule detects (recall 51% to 80%) match nearly every dereference on real code, **110 to 145 alerts per KLOC** (the graph query gives 0.03). The idea the findings give
("NULL, then dereferenced") needs the notion of a path with no test in between, which a Semgrep pattern cannot state, and the model writes either a pattern that never matches or one that matches any dereference. This is the clearest case so far of the limit of the rule language, not of the model.
Honest limits: no baseline with the detector's findings was run for these two CWEs (so these are levels, not effects of the graph); two seeds; 30B local only; for CWE-415 the extra reading of the one clean rule was not done.

## Protocol: alternative rule generators tried in order (written on 2026-10-15 **before** any of them was run)

Question: is there a way to produce a *valid* rule (accepted by the gate: train recall of at least 50%, no Juliet false positive, at most 0.1 alerts per KLOC on the Git train files) where the model alone did not? Four generators are tried, in this order; a fifth (another target language: CodeQL, Joern, Semgrep Pro)
changes the scope of the thesis and a sixth (fine-tuning with the gate as reward) does not fit in a 6 GB card, so neither is tried.
All use the same folds, seeds (1 and 2), Juliet files and Git files as the runs they are compared with, CWE-416 first and CWE-415 second, and the same gate; the held-out side is graded exactly as `synthesize` does.
1. **Constrained generation**: the model answers the template with a JSON schema enforced by the decoder (`response_format` of llama.cpp), so every answer is syntactically a valid spec. Same loop, same prompts. 4B against `qwen4b`, 30B against B0.
2. **Assembler with repair operators**: the model's own best attempt of each fold (the template of B0) is taken as the start; a program applies, one at a time and keeping a change only if it lowers the alerts of the train files without losing train recall, three operators: exclude the statement of the event
   (`not_inside: free($X)`), add the resets `$P = ...`, `$P = NULL`, `$P = malloc(...)`, drop a use pattern. The gate is the judge; no model call.
3. **Synthesis from the graph's findings**: the source line and the use line of each train finding are abstracted (the pointer to `$P`, the callee kept) into candidate events and uses, and a greedy search picks the uses that cover the train cases without a Juliet false positive. The resets are the generic ones of operator 2.
4. **Compiling the graph query**: one fixed spec per CWE (event `free($P)`; uses: a dereference, an index, a call with the pointer; `not_inside` the event; resets), written by us from what the graph query does, graded in every fold. It is an upper bound for what the template language reaches, not a result of a model.
Whose rule it is, said before the numbers: 1 is the model's; 2 starts from the model's and is edited by a program; 3 and 4 are written by programs from our knowledge of the strategy (taint by side effect with resets), like the template arm, and are reported apart from 1 and 2.
Success = the number of accepted folds of 10, then the held-out alerts per KLOC under 0.1 with recall above 50%. A generator that is no better than the model's own run is reported as not better.

### Result: the alternative rule generators (2026-10-16), protocol above

CWE-416 and CWE-415, seeds 1 and 2, 5-fold cross-validation by variant, the same folds, Juliet files and Git files as the model runs; acceptance = train recall of at least 50%, no Juliet false positive, at most 0.1 alerts per KLOC on the Git train files.
Summaries in `logs/crossval/NONE/<CWE>/` (deterministic generators) and `logs/crossval/C/CWE-416/` (grammar, 4B); code in `src/pipeline/rulegen.py`.
| # | Generator | Who writes the rule | CWE | Accepted (of 10) | Held-out recall | Juliet false positives | Real-world alerts per KLOC |
|---|---|---|---|---|---|---|---|
| - | the model alone (B0, 30B, template) | model | 416 | 0 | 71.6% | 9.0 | 2.53 |
| - | the model with the graph's findings (30B) | model | 416 | 0 | 91.6% | 29.4 | 4.76 |
| 1 | decoder held to the template's JSON schema, 4B | model | 416 | **0** | 20.0% | - | ~0.01 (rules that match nothing) |
| 1 | the same, 30B | model | 416 | not run: the run waited 2 hours for 20 GB of free RAM and gave up | | | |
| 2 | repair operators on the model's best attempt (30B template of B0) | model, edited by a program | 416 | **5** | 71.6% | 1.8 | 0.26 (accepted folds under 0.1) |
| 3 | synthesis from the graph's findings (patterns abstracted from train findings, greedy cover) | program | 416 | **9** | 58.1% | 1.2 | 0.02 |
| 4 | fixed spec with the calls that take the pointer | program (us) | 416 | 0 | 87.0% | 12 on train | 0.31 to 0.40 |
| 4 | fixed spec, dereference only (`fixed_deref`) | program (us) | 416 | **10** | 52.0% | 0.0 | 0.06 |
| 4 | fixed spec | program (us) | 415 | 0 | 84.7% | 127 | 6.81 |
| 3 | synthesis | program | 415 | 0 | 0.0% | 0 | 0 (every candidate was excluded by `not_inside free($X)`, a flaw of this run) |
Notes. (a) `fixed_deref` was chosen *after* the first fixed spec gave 12 Juliet false positives and 0.19 alerts per KLOC on the train files of fold 0, so it is tuned on one fold; both specs are in the code. (b) The synthesis keeps `not_inside free($X)` on every use whatever the CWE;
for CWE-415 the use is itself a `free`, so nothing survives: the 0% is a flaw of the generator for that CWE, not a measure of the idea. (c) The graph's findings and the template strategy (taint by side effect, resets `$P = ...`) are our knowledge in 3 and 4; in 2 the strategy is the model's and the edits are ours.
**Ranking by accepted folds on CWE-416: 4 dereference-only 10 of 10, 3 synthesis 9 of 10, 2 repair 5 of 10, then 1 grammar and the model alone 0 of 10.** With a model in the loop, only the repair got there (5 of 10, from 0 of 10): the decoder changes nothing because syntax was not the problem.
**What "accepted" is worth: the 22 alerts of `fixed_deref` on the Git sources, all read, are all false** (0 real): loops that free one element and use the next (`free(d->messages[i])` then `d->messages[j]`), a reassignment by a macro (`FLEX_ALLOC_STR`) or by a function (`x = xmalloc(..)` after `free(x)`, where the pattern `*x` inside `sizeof(*x)`
is matched), a hashmap entry added after being freed on another path. The rule is quiet (0.06 per KLOC), valid and detects half of the held-out Juliet cases by dereference, and its alerts on real code are not bugs; the gate measures noise and recall on Juliet, not whether an alert is true. The two things the accepted rules also do
not do are to find the cases where the pointer is handed to a function (87% against 52% recall) and to cover CWE-415 or CWE-476, where the event and the use are the same pattern or the use needs a path with no test in between.

## Protocol: CWE-457 and the form format, where the model only fills blanks (written on 2026-10-17 **before** the run)

Question: if the model does not write the rule but fills the blanks of a Semgrep rule, with the decoder held to the skeleton by a grammar, does it write rules that pass the gate, and does that beat letting it write the YAML? CWE-457 (use of an uninitialized variable) is run because it was never tried
and because a form of this kind is what it needs.
Two facts found before the run, from hand-written probes on the Juliet files (not results of a model): (1) in taint mode a declaration without a value does not start a taint in Semgrep OSS for C, so a taint rule with the declaration as source has a recall of 0%; (2) in search mode a rule that matches a declaration, anything, and a use,
excluding the same shape with an assignment before the use, has a recall of 31% with no false positive on the first 120 pairs of files; the variant with `pattern-inside` / `pattern-not-inside` gets 33% and 64 false positives. So the Semgrep rule for this CWE is a search-mode rule, and a recall of about one third is
what a first idea reaches.
Arms, CWE-457, 4B local model (combo C), 5-fold cross-validation by variant, seeds 1 and 2, up to 6 corrections, the detector's findings as examples (698 findings of CWE-457 in the v1 logs, false positives on safe files included), the gate with the Git sources (acceptance: train recall of at least 50%, no Juliet false positive, at most 0.1 alerts per KLOC):
- `yaml`: the model writes the rule as YAML (the format of the first runs);
- `template`: the model fills the JSON of the template (taint strategy; expected to fail by fact 1);
- `form` with the grammar: the blanks of a taint rule (same strategy as the template, as YAML);
- `formsearch` with the grammar: the blanks of a search-mode rule: one to four alternatives, up to four `pattern-not`, up to two `pattern-not-inside`, `focus-metavariable: $X` fixed.
The 30B (combo D) is run for `formsearch` and `yaml` afterwards if the memory allows (20 GB free).
Whose rule it is: `yaml` is the model's; the three others fix the skeleton, which is our knowledge, and are reported apart from `yaml`, as the template arm is.
Success = accepted folds of 10, then held-out recall with alerts per KLOC under 0.1; a result no better than `yaml` is reported as not better.

### Result (2026-10-17, after the run)

0 of 10 folds accepted in every arm (`yaml`, `template`, `form`, `formsearch`), both seeds. `formsearch` is the only arm that ever
matches anything (train recall 18.75% on one fold, with 288 false positives; 0% on the other four), which is already below the
31% a hand-written search-mode rule reaches on the first 120 pairs. `yaml` and `template` are valid Semgrep (when they parse at
all) but inert: `report.valid=True`, recall 0%, 0 false positives, on almost every fold - the model writes a rule that Semgrep
runs without complaint and that matches nothing. `form` (the taint skeleton) fails the way fact (1) predicted: a declaration is
not a taint source in Semgrep OSS for C, so it is structurally capped at 0% recall regardless of what the model fills in. The
`yaml` seed also lost 4 of its 5 folds to an unrelated bug (a candidate rule hung Semgrep past the subprocess timeout scanning
the real-world negatives, which crashed the whole cross-validation process instead of being reported as an ordinary invalid-rule
error); fixed in `gate.run_semgrep` (catches `subprocess.TimeoutExpired` and a non-JSON crash, same as a rejected rule) before
the `template`/`form` arms ran, so this did not recur.

Read as: this is not evidence against the form/formsearch idea, or against `field_correct` (not used in this run - see
docs/graph_progress.md's note on it; none of these arms passed `--field-correct`). It is evidence that CWE-457 is a poor target
for this pipeline at all: the hand-written ceiling was already ~31-33%, well under the 50% acceptance bar, before any model was
involved, and the 4B model (combo C) does not even reach that ceiling. Effort moves to CWEs the gate has already shown
potential on instead of a second attempt at CWE-457: CWE-416 (the only one with any accepted crossval folds - 2/5 in one
combo D + template + example_mode seed - and the only one with a standing rules/accepted/ rule) and CWE-415 (0/5 accepted but
64-65% held-out recall with combo D + yaml + example_mode, never pushed further). CWE-476 (23-25% recall) and CWE-401 (one
noisy run, 79% recall but 36% precision) are weaker leads.

## Protocol: CWE-416 and CWE-415 with the taint form and `field_correct` (written on 2026-10-18 **before** the run)

Question: for the two CWEs where a taint rule's shape actually fits the bug (use-after-free: source `free($P)`, sink any later
use of `$P`; double-free: source `free($P)`, sink a second `free($P)`), does writing the rule as the `form` skeleton beat the
`yaml`/`template` formats already tried, and does `field_correct` (the corrector answers one field at a time instead of
rewriting the whole rule - see src/pipeline/form.py, added 2026-10-17) beat the full-rewrite corrector on the same format? Run
on CWE-416 and CWE-415 rather than a third try at CWE-457, since both already show real potential: CWE-416 is the only CWE
with any accepted crossval folds (2/5, combo D + template + example_mode) and the only one with a rules/accepted/ rule;
CWE-415 reached 64-65% held-out recall (combo D + yaml + example_mode, 0/5 accepted) but was never pushed past that one run.
CWE-476 and CWE-401 are weaker leads, deferred to a later round.

Arms, both CWEs, 4B local model (combo C - 13.4 GB free RAM at launch does not clear combo D's 20 GB bar), 5-fold
cross-validation by variant, seeds 1 and 2, up to 6 corrections, the detector's findings as examples, the gate with the Git
sources (acceptance: train recall of at least 50%, no Juliet false positive, at most 0.1 alerts per KLOC):
- `form` with the grammar: the taint skeleton, full-rule corrector (the format's existing baseline);
- `form` with the grammar and `--field-correct`: same skeleton, corrector answers one field at a time;
- `formsearch` with the grammar: the search-mode skeleton (a second way to state the same two CWEs: for UAF, the declaration
  and the free and the later use as one pattern with the free excluded by `pattern-not`; for double-free, two frees of the
  same pointer as one pattern), full-rule corrector;
- `formsearch` with the grammar and `--field-correct`.

8 seed-runs per CWE, 16 total. Protected by the `gate.run_semgrep` timeout/crash fix from the CWE-457 round (2026-10-17): a
rule that hangs or crashes Semgrep is now an ordinary invalid-rule error, not a process crash.
Success = accepted folds, then held-out recall with alerts per KLOC under 0.1, compared against each CWE's existing best
(CWE-416: combo D + template + example_mode's 2/5; CWE-415: the 64-65% recall baseline). `field_correct` is judged against the
full-rewrite corrector on the same format (`form` vs `form --field-correct`, `formsearch` vs `formsearch --field-correct`),
not against the historical yaml/template runs, which differ in more than one variable at once.

### Result (2026-10-18, after the run)

0 of 10 folds accepted in every one of the 16 seed-runs; neither CWE beats its existing best (CWE-416: 2/5 accepted,
combo D + template + example_mode; CWE-415: 64-65% held-out recall, combo D + yaml + example_mode).

`field_correct` made no measurable difference anywhere in this round: every `form`/`formsearch` pair (with and without
`--field-correct`) landed on the same recall, to the fourth decimal, on both CWEs and both seeds - identical except for one
real-world-rate number (CWE-415, `form`, seed 2: 3.44 alerts/KLOC without `--field-correct` vs 0.0235 with it, same 20%
recall). One data point is not enough to call that an effect, but it is consistent with the field-level corrector not
changing *what* the rule ends up detecting, only *how cheaply* it gets there (confirmed in the pre-run smoke test: ~5s per
field-level correction vs ~44s for a full rewrite) and, perhaps, how much noise a correction that touches one field at a
time leaves behind on the untouched fields.

CWE-416: both formats stay near 0% recall regardless of `field_correct` (`form` exactly 0.0 every time; `formsearch` 0.0-2.1%).
`formsearch` carries a real-world alert rate of 0.22-0.48/KLOC - over the 0.1 gate limit - on a rule that still detects
almost nothing in Juliet, the same "inert at best, noisy at worst" pattern as CWE-457's `yaml`/`template` arms. The taint
form's source/sink split does not help UAF here either: the smoke test before the run already showed the 4B model using
`malloc(...)` as the source (an allocation, not a free) instead of `free($X)`, so the generated rule tracks the wrong event
from the start regardless of which corrector mode follows it.

CWE-415: `form` (double-free is a clean taint shape: source `free($P)`, sink a second `free($P)`) is the best arm of this
round at 20% recall on every one of its four seed-runs, but still well under the 64-65% of the existing `yaml` +
`example_mode` baseline, and with real false-positive cost (84-144 total, one run spiking to 3.44 alerts/KLOC).
`formsearch` is markedly worse here (2.5-4.1% recall) - the search-mode encoding of "two frees of the same pointer" loses
to the taint encoding, the reverse of CWE-457 where search mode was the only one that worked at all (taint could not even
start, since a Semgrep taint source needs a value).

Read as: this round answers its own question - no, stating these two CWEs as a `form`/`formsearch` skeleton does not beat
the historical `yaml`/`template` + `example_mode` runs, and `field_correct` is neutral on outcome quality in every arm
where it was tried alongside a format change. The variable that has actually moved results so far across every CWE tried
is `example_mode` (`combo D + template/yaml + example_mode` is the best config for both CWE-416 and CWE-415), not the
output format or the corrector's granularity. A follow-up that isolates `example_mode` on top of `form`/`field_correct`,
or that just tries `example_mode` on CWE-415 at a bigger combo, is a better next step than more format variants.

### Combo D repeat (2026-10-18): same 16 arms, Qwen3-Coder-30B-A3B instead of Qwen3-4B

The combo C result above is confounded with model size: CWE-416's 2/5-accepted and CWE-415's 64-65%-recall baselines both
used combo D, not combo C, so the comparison was not apples to apples. Repeated the same 16 seed-runs with combo D (paused
once and resumed with `--resume-since` when a foreground game left too little free VRAM for the 10 offloaded GPU layers;
see the free-RAM/GPU-contention note already in memory - the same applies to GPU memory, not only system RAM).

Still 0 of 10 folds accepted everywhere - the ceiling from the combo C round holds at the bigger model too - but
`field_correct` is no longer reasonably called neutral:

- **CWE-416, `form`**: fc=False stays at exactly 0% recall both seeds (unchanged from combo C). fc=True jumps to
  **60%/40% recall** - the single largest effect seen in either round - but at the cost of 96-614 false positives and a
  real-world rate of 0.04-**7.25**/KLOC (seed 2), two orders of magnitude over the 0.1 gate limit. Isolating one field at a
  time let the bigger model actually find the right source/sink relationship it could not land on in one shot; it did not
  teach it when to stop widening the match.
- **CWE-416, `formsearch`**: fc has no effect at all, to three decimal places (1.43%/1.48% both ways) - same conclusion as
  combo C, the search-mode fields are not where this CWE's difficulty lives.
- **CWE-415, `form`**: high seed variance dominates. fc=False: 32%/0%. fc=True: 40%/0% - an improvement on seed 1, no
  change at all on seed 2 (still exactly 0%). Field-level correction cannot rescue a run whose generator picked a
  source/sink pair so wrong that no single-field edit reaches a working shape; it only helps when the starting point is
  already close.
- **CWE-415, `formsearch`**: fc=False: 12.7%/2.2% (24/6 false positives, 1.4-1.5/KLOC). fc=True: 4.6%/4.1% (0/0 false
  positives, 0.12-0.17/KLOC) - recall drops a little, but false positives disappear and the real-world rate falls by
  roughly 10x. The same direction as the one CWE-415/combo-C data point noted above, now confirmed across both seeds of a
  second arm: field-level correction's most reliable effect across this whole investigation is cutting real-world noise,
  not raising recall - raising recall only happened once (CWE-416/`form`), and when it did, it brought the noise back
  with it.

Net: `field_correct` is real, but it is not a general corrector upgrade - it helps a format/CWE pair that was already
structurally close to the answer (CWE-416's taint shape, once the bigger model engages with it) and mostly just quiets
down the ones that were not (CWE-415's `formsearch`). Neither CWE beats its own `combo D + example_mode` baseline with any
of these 16 runs. `example_mode` remains the only lever that has moved an accepted-folds count in this project's history;
that, combined with `field_correct` for noise control rather than detection, is the more promising combination to try
next, not `field_correct` alone.

## Protocol: `field_correct` combined with `example_mode=pairs` (written on 2026-10-18 **before** the run)

Question: the only configuration that has ever gotten crossval folds accepted in this project is CWE-416, combo D,
`template`, `example_mode=pairs` (vulnerable/safe file pairs shown to the generator instead of the detector's findings) -
2/5 accepted, seed 1. `field_correct`'s own best result (CWE-416, `form`, combo D) reached 40-60% recall but with
false-positive rates 20-70x the gate's limit. Does stacking the two - `pairs` for what the generator is shown,
`field_correct` for how the corrector fixes it - do better than either alone on the `form`/`formsearch` skeletons, which
have never been tried with `pairs` before (the historical `pairs` run was on `template`)?

Arms, both CWE-416 and CWE-415, combo D, `--example-mode pairs` added to every one, 5-fold cross-validation, seeds 1 and 2,
up to 6 corrections, the gate with the Git sources (same acceptance bar as every prior round: train recall >= 50%, no
Juliet false positive, <= 0.1 alerts/KLOC):
- `form` with the grammar (baseline: pairs alone, no field_correct, not tried on this skeleton before);
- `form` with the grammar and `--field-correct`;
- `formsearch` with the grammar (baseline: pairs alone);
- `formsearch` with the grammar and `--field-correct`.

16 seed-runs, same structure as the two earlier `form`/`formsearch` sweeps so the three are directly comparable:
combo C (no `example_mode`) -> combo D (no `example_mode`) -> this round (combo D + `pairs`). `example_mode=graph` reached
higher raw recall than `pairs` in isolated historical runs (97%/86% on CWE-416, 64%/65% on CWE-415) but never got anything
accepted, consistent with it finding real bugs but also many false positives; `pairs` is tried first here specifically
because it is the one data point that ever cleared the gate's false-positive bar, not just the one with the highest
recall.

### Result (2026-10-19, after the run)

0 of 10 folds accepted in every one of the 16 seed-runs, again. Stacking `pairs` on `field_correct` does not beat either
lever alone, and comes with one clear negative result:

- **CWE-415, `form`**: `pairs` zeroes recall outright - 0% on both seeds, with or without `field_correct` (the no-`pairs`
  baseline was 32%/0% and 40%/0%). Showing the generator vulnerable/safe file pairs instead of detector findings is
  actively harmful to this CWE's taint encoding, not just unhelpful.
- **CWE-416, `formsearch`**: completely flat at ~0-1.5% recall across all four combinations of `pairs` x `field_correct` -
  the same conclusion as every earlier round. Nothing tried on this skeleton has ever moved CWE-416's `formsearch` result;
  the CWE's difficulty is not reachable from the search-mode encoding at all, independent of corrector or examples.
- **CWE-416, `form`**: the only arm with real movement, and the four combinations scatter across 0%, 31%, 54%, 60%
  recall with no consistent ranking by `pairs` or `field_correct` - e.g. `pairs` alone reached 54% on seed 1 but 0% on
  seed 2; `pairs` + `field_correct` reached 31% on seed 1 (down from `pairs` alone) but 60% on seed 2 (up from 0%). Every
  high-recall result pairs with heavy false positives (308-1154) and a real-world rate up to 0.11/KLOC.
- **CWE-415, `formsearch`**: recall stays low (0-6.8%) and noisy under every combination; `pairs` does not clearly help
  or hurt once `field_correct` is in the mix either way.

The pattern across all three `form`/CWE-416 sweeps (combo C, combo D, combo D + `pairs`) is that **seed-to-seed variance
is often larger than the effect of any lever tested**: the same exact config (`form` + `field_correct`, combo D) swung
from 0% to 60% recall between its own two seeds in the first sweep, and `pairs` alone swung from 0% to 54% in this one.
Two seeds is not enough to tell a real effect from this noise floor - a claim like "`pairs` helped" or "`field_correct`
hurt" drawn from one seed's number in this round would likely reverse on a third seed. Any future round that wants to
trust a direction (not just note that something moved) needs more than 2 seeds per arm, which trades off against the
breadth these sweeps have favored so far (16 one-variable-at-a-time arms instead of fewer arms run deeper).

Net for this whole CWE-416/CWE-415 investigation (2026-10-18 to 2026-10-19, 48 seed-runs total across three rounds):
no format/corrector/example combination tried on `form` or `formsearch` has matched either CWE's `template`/`yaml` +
`example_mode` baseline, and the clearest lesson is methodological rather than substantive - this project's crossval
protocol needs more seeds before another round chases a single-seed effect size.

## Protocol: stacking the two proven levers, and more seeds on the existing bests (written on 2026-10-19 **before** the run)

Three follow-ups to the dashboard review of all 120 crossval runs so far, in the order decided with the user:

1. **`example_mode=pairs` + `guard` + `project_apis` together**, `template`, combo D, CWE-416. Never tried: `pairs` alone is
   the only configuration ever accepted (2/5, seed 1); `guard`+`project_apis` alone reached the highest recall of any run
   (100%/94.9%, two seeds) but was never accepted (398/616 false positives). Stacking them tests whether `guard`'s
   never-regress corrector plus `project_apis`'s project-specific functions can keep `pairs`' precision while pushing its
   recall further.
2. **`field_correct` extended to the `yaml` format**, then tried with `example_mode=graph` on CWE-415. `field_correct`
   (src/pipeline/form.py) was form/formsearch-only because that was its original use; its field walk only looks for
   `pattern`/`pattern-not`/`pattern-not-inside` keys, with no assumption about the surrounding shape, so it applies to any
   parsed Semgrep rule - confirmed against the hand-written CWE-416 fixture's nested `pattern-either`/
   `metavariable-pattern` shape, which the form/formsearch grammars never produce (test_field_correct_works_on_the_yaml_format_too).
   `describe_field` had a latent bug this generalization exposed: a bare `pattern-not` directly under `pattern-sinks` (not
   reachable from the form/formsearch skeletons, which only ever put `pattern-not-inside` there) was mislabeled as
   `pattern-not-inside` in the corrector prompt; fixed alongside this change. `yaml` + `example_mode=graph` already reaches
   64-65% recall (never accepted, combo D, no `field_correct`); this tests whether field-level correction's noise-reduction
   effect (seen on `formsearch` in the CWE-415 round) can push that recall over the gate instead of just ignoring it the
   way the `form`/`formsearch` rounds' noise reduction did.
3. **More seeds (3, 4, 5) on each CWE's existing best** (`template` + `pairs` for CWE-416, `yaml` + `graph` for CWE-415,
   both combo D, no new roles) - a direct response to the seed-variance finding from the `form`/`formsearch` rounds: with
   only 2 seeds, "this helped" and "this didn't" are not reliably distinguishable from noise. Five seeds per config is
   still not a lot, but it is what compute allows next.

Arms (combo D throughout, 5-fold cross-validation, up to 6 corrections, the gate with the Git sources, the same
acceptance bar as every round so far):
- CWE-416, `template`, `--example-mode pairs --guard --project-apis`, seeds 1-2 (new combination);
- CWE-415, `yaml`, `--example-mode graph --field-correct`, seeds 1-2 (new combination, needs the code change above);
- CWE-416, `template`, `--example-mode pairs`, seeds 3-5 (extends the only-ever-accepted config past its original 2 seeds);
- CWE-415, `yaml`, `--example-mode graph`, seeds 3-5 (extends the 64-65%-recall baseline past its original 2 seeds).

10 seed-runs total. Success for (1) and (2) is beating `pairs` alone (2/5 accepted) or `graph` alone (65% recall)
respectively; success for (3) is the already-reported numbers holding up across 3 more seeds rather than regressing to
something nearer the field-correct rounds' 0%-60% swings.

### Result (2026-10-19, after the run)

Neither new combination beat its base config, and the extra seeds answer the question they were run for.

- **CWE-416, `pairs` + `guard` + `project_apis`** (2 seeds): 97.1%/80.3% held-out recall, but 799/619 false positives and
  25.6-47.3 real-world alerts/KLOC - both far noisier than `pairs` alone's own worst seed (320 FP, 5.5/KLOC). Stacking
  `guard`+`project_apis` on top of `pairs` keeps the ceiling `guard`+`project_apis` already had alone (close to 100%
  recall) and brings its false-positive problem with it; it does not inherit `pairs`' quiet real-world behavior. 0/5
  accepted both seeds, same as every arm this round.
- **CWE-416, `pairs` alone, extended to 5 seeds**: 77.6% (accepted, 2/5), 97.1%, 97.8%, 91.4%, 88.6%. This is the opposite
  of what the `form`/`formsearch` rounds' seed swings predicted: recall is consistently high (78-98%) across every seed -
  the config is not unstable on recall. What is fragile is the false-positive count sitting close to the train-side gate
  (84-320 across seeds, only seed 1's 138 happened to land on the accepted side of the cutoff). The one accepted result
  from 2026-10-09 was not a fluke of recall; it was a fluke of exactly where that seed's false-positive count fell
  relative to a hard threshold - a real distinction the first two seeds alone could not show.
- **CWE-415, `graph` + `field_correct`** (2 seeds): 20.6%/78.2% recall, 12/498 false positives. Compare to `graph` alone's
  same two seeds (63.8%/64.8%, 348/456 false positives, already on record from 2026-10-15): `field_correct` made seed 1
  markedly worse (63.8% to 20.6%) and left seed 2 about the same (64.8% to 78.2%, with the same order of false
  positives). No sign of the noise-reduction effect seen on CWE-415's `formsearch` in the previous round; on free-form
  `yaml`, a structurally broken attempt (confirmed in the pre-run smoke test, where the generator put
  `metavariable-pattern` at the top level) still consumes a correction cycle even with the new structural-fallback fix,
  since the fallback only changes *which* corrector runs on the bad attempt, not how many of the limited attempts are
  available afterward for content-level fixes.
- **CWE-415, `graph` alone, extended to 5 seeds**: 63.8%, 64.8%, 47.3%, 43.3%, 76.3% - a real spread (43-76%), narrower
  than the extreme 0-60% swings `form`/`formsearch` showed, but still a 33-point range across 5 seeds of the identical
  config. The original 2-seed estimate (63.8%/64.8%, both close together) understated how much this number moves; five
  seeds puts the honest range at roughly 45-75%, not 64% the first two happened to agree on.

Net: the dashboard's two leads do not combine or extend into anything better. `pairs`+`guard`+`project_apis` is worse than
`pairs` alone on the only axis that matters (false positives). `field_correct` on `yaml` repeats CWE-415's established
pattern of high seed variance rather than controlling it. The most load-bearing result of this round is methodological,
again: the 2026-10-09 "2/5 accepted" number for CWE-416 holds up at 5 seeds (every seed reaches comparable recall; only
the false-positive count decides acceptance), while the 2026-10-15 "64-65%" number for CWE-415 does not (45-75% is the
honest range at 5 seeds). Two seeds were enough to trust CWE-416's recall but not CWE-415's - there was no way to know
that in advance, which is itself the argument for defaulting to more seeds before reporting a number as a CWE's
"result" rather than deciding case by case after the fact.

## Protocol: `pairs` + `guard` without `project_apis` (written on 2026-10-19 **before** the run)

The 5-seed extension of `pairs` alone showed recall is stable (78-98%) across every seed; what decides acceptance is the
train-side false-positive count sitting close to the gate's cutoff (84-320 across seeds, only seed 1's 138 landed on the
accepted side). `pairs` + `guard` + `project_apis` made this worse (619-799 false positives) rather than better.
`project_apis` is the more likely source of that noise (it adds project-specific function names to the prompt, which on
a different real-world codebase than train could easily fire on hero-named functions); `guard` by itself (never let a
correction score worse than the best rule so far) is the one piece of that combination aimed directly at the identified
problem - stopping the corrector from drifting to a noisier rule - without `project_apis`'s extra surface.

Arm: CWE-416, combo D, `template`, `--example-mode pairs --guard` (no `--project-apis`), seeds 1-5, 5-fold
cross-validation, up to 6 corrections, the gate with the Git sources, same acceptance bar as every round so far.
5 seeds from the start, matching the now-5-seed `pairs`-alone baseline for a fair comparison instead of needing a
second extension pass later.
Success: more of the 5 seeds land under the false-positive/negative-rate limit than `pairs` alone's 1 of 5, without
giving up `pairs`' recall.

### Result (2026-10-20, after the run)

seed1: 1/5 accepted, 91.4% recall, 102 FP, 3.09/KLOC. seed2: 0/5, 89.2%, 12 FP, 0.75/KLOC. seed3: 0/5, 100%, 216 FP,
6.79/KLOC. seed4: 1/5 accepted, 89.2%, 90 FP, 2.36/KLOC. seed5: 0/5, 91.4%, 168 FP, 5.67/KLOC.

This is the first configuration in three rounds to beat its predecessor, on the metric that matters: `pairs` alone got
an accepted fold in 1 of 5 seeds (seed 1, 2/5 folds there); `pairs` + `guard` (no `project_apis`) gets one in 2 of 5
seeds (seed 1 and seed 4, 1/5 folds each) - the total count of accepted folds across all 25 is the same either way (2),
but it is no longer concentrated in a single lucky seed. Recall is also tighter: 89.2-100% across every seed, against
`pairs` alone's 77.6-97.8%. `guard`'s mechanism (never let a correction score worse than the best rule so far) does what
it was meant to here without `project_apis`'s extra noise: it holds the line on recall while giving the false-positive
count more chances across a run to land under the gate, rather than fixing the count outright (it still ranges 12-216
test-side FP across seeds - still fragile, just less rarely lucky).

This answers the open question from the dashboard review in the most useful way available: `guard` alone is a real,
if modest, improvement on `pairs` for CWE-416/`template`, worth keeping as this project's best-known configuration;
`project_apis` is confirmed as the piece that was hurting rather than helping. Given three rounds of combination search
(form/formsearch + field_correct, pairs + field_correct, pairs + guard + project_apis, graph + field_correct) produced
one real improvement and otherwise reproduced or worsened what was already known, this is a reasonable point to stop
searching combinations for CWE-416/CWE-415 and treat `template` + `pairs` + `guard` (CWE-416) and `yaml` + `graph`
(CWE-415, unresolved, 45-75% recall) as this investigation's standing results.

## Why free/use graph tracking does not translate into a quiet Semgrep rule (written 2026-11-02, answering a question about the unsolved CWEs)

The question: for the CWEs the rule synthesis never solved, could the model be helped by explicit memory nodes - tracking
when something is freed, then following where it is used afterward? That tracking already exists and is not the missing
piece; the results already in this log explain what it does and does not fix.

**The free-to-use walk is built and works as a standalone detector.** `src/graph/paths.py`'s `use_after_free` builds a
graph of events (free, use, alloc, reset...) per function with control-flow edges, and walks forward from each `free` to
the `use`s of the same variable (and its `->field`, `[i]`, derived paths) reachable with no intervening reassignment.
On Juliet: 134/138 CWE-416 cases, 0 false positives. On real code never used to develop the extractor: tmux, PostgreSQL,
SQLite pass the 0.1-alerts/KLOC bar; vim fails because one wrong "frees its parameter on some path" call summary
produces 179 of 234 alerts in a single function. `double_free` (CWE-415) and `memory_leak` (CWE-401) are the same idea
applied to other event pairs, weaker on Juliet (150/272 and 648/868) because some cases need information the walk does
not have (a double free gated by a global flag; a leak whose flag lives in a support file not in the data).

**Handing the model these findings as examples (`--example-mode graph`, "the model writes the rule from the graph's
findings" above) raises recall and lowers precision together, for a specific, diagnosed reason.** CWE-416, combo D:
recall 71.6% to 91.6% going from detector to graph findings, but precision 89.4% to 69.8%, Juliet false positives 9.0 to
29.4, real-world alerts/KLOC 2.53 to 4.76 - broader, not quieter. Read at the time: "the rule it wrote is the generic
taint rule whose sink is any use of the pointer, which also matches the `free` statement that marks it; a finding that
says 'released at line a and used at line b' does not tell the model to leave line a out." The graph's information about
*where* the defect is does not carry the information about *what the rule must exclude* - that line is itself a "use" by
the sink pattern's own definition, and nothing in the finding's description says to subtract it.

**CWE-476 is the clearest case of a limit in the rule language itself, not in the model or the information given to it.**
The graph's null-dereference query needs "no decision between the NULL and the dereference" to stay quiet (see the three
things tried and dropped in the CWE-476 protocol above: a plain reachability walk gave 8-13 alerts/KLOC on development
projects before that restriction brought it to 0.01-0.08). A Semgrep pattern has no way to state "no decision in
between"; given the graph's findings as examples, the 30B model's rules either matched nothing (5 of 10 folds) or
matched every dereference (51-80% recall with 110-145 alerts/KLOC) - there is no pattern in between for it to write.

**A program compiling the same free/use logic directly into a Semgrep rule (no model) does reach the gate - and that
is also informative.** "Compiling the graph query" (CWE-416, `fixed_deref`, the alternative-generators round) gets
10 of 10 folds accepted: 52.0% recall, 0 Juliet false positives, 0.06 alerts/KLOC. But its 22 real-world alerts, all
read by hand, were all false: a loop freeing one element and using the next, a reassignment through a macro or a
function the extractor could not see, a hashmap entry re-added on another path - exactly the ownership and call-summary
limits the graph arm's own project log already names as open problems. Passing the gate (quiet, detects half of Juliet)
is a property of the rule's behavior on this benchmark and this real-code sample, not evidence that its alerts are real
bugs.

Net: tracking a freed variable forward to its uses, the idea behind the question, is not a missing capability - it is
already the graph arm's core query, already measured on eight to twelve real-world projects, and already shown to carry
real signal (it is what let the 30B model's recall jump on CWE-416 and CWE-415 when used as examples). What breaks the
pipeline is downstream of that: a Semgrep rule general enough to run on code the walk has not seen needs to state
*exclusions* (the defining line is not a use; a path has no intervening test) that the graph's own representation
carries naturally (walk one way, stop at a condition) and Semgrep's pattern language cannot always say. Where a program
writes the Semgrep rule directly from the graph's logic instead of asking a model to infer it from examples, the
acceptance gate can be satisfied (CWE-416, 10 of 10) without the rule's alerts being any more true than before.
