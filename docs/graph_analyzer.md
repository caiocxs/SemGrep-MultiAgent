# Event-graph analyzer (design sketch)

Status: on branch `feat/graph-analyzer`. The schema, the path queries, the tree-sitter extractor, the scoring against Juliet and real
projects, and the fix-commit evaluation exist and are tested (`tests/test_graph_paths.py`, `tests/test_graph_extract.py`, `tests/test_graph_leaks.py`, 92 tests); the LLM
judge was decided against. The tables above the section "No hand-written names" were measured at earlier versions of the extractor (with
hand-written lists); that section has the current numbers.

## Why a second arm

The cross-validated rule synthesis (`findings.md`) reaches high recall on Juliet but no rule passes the real-world gate. The
alerts that remain are structural: loops that move to another element, reassignment through macros, a different object,
out-parameters. A Semgrep rule matches syntax inside one function; those cases need the order of events along control flow and
facts about callees. This arm keeps the events of a whole repository in a database and answers "is there a path from a free of
`p` to a later event on `p` with no new value in between" as a query.

It is a different product from the thesis' main line (local models writing Semgrep rules) and must be reported apart from it.

## Data model

`src/graph/schema.sql`: files, functions, **events** (alloc, free, use, reset, call; each with the variable's access path,
line and statement text), **flow** (control-flow successor edges, back edges for loops), **aliases** (provable `q = p` in one
function), **call_args** and **summaries** (what a function does to each parameter) for interprocedural queries.
SQLite is enough for the size involved (Git: 644 `.c` files, 447 KLOC); a graph database adds operations and no capability
the recursive query below lacks.

## Query

`src/graph/paths.py`: a recursive query walks `flow` from each `free` event and stops at a `reset` or `alloc` of the same
variable. A reachable `use` of that variable is a use-after-free candidate; a reachable `free` is a double-free candidate
(including a `free` that reaches itself through a loop with no reset). Intraprocedural for now; `summaries` and `call_args`
are the hook for following a pointer through a call.

## Roles

1. **Extractor (deterministic, to write).** tree-sitter C (or Joern, to be compared) producing events and flow edges.
   Hardest part: macros, `goto cleanup`, wrappers of allocation, field paths, aliases.
2. **Query (deterministic, written).** Candidates with the statement text and the path between the two events.
3. **Judge (LLM, optional).** Sees one candidate with its path and decides whether the path is feasible. It is a triage step:
   it may only drop candidates, never add them, and the final numbers are reported with and without it.

Principle 2 of the project (no LLM decides whether something works) holds for the query; the judge is declared as a filter and
measured separately.

## Evaluation (same data as the rule synthesis)

- Juliet CWE-416 (and 415), the same 5 folds by flow variant: recall and precision per fold; there is nothing to train for the
  query alone, so every variant is a test variant.
- Real-world gate: alerts per KLOC on the Git sources (limit 0.1), identical to the synthesis gate.
- The 16 Git fix commits: alert near the fixed lines before the fix and none after (the rules were at chance level, 31% against 36%).
- Arms: query alone; query + judge with a 4B local model; query + judge with the 30B local model; query + judge through an API
  (reported apart). Each judge arm is paired with the query alone on the same candidates.

## Extractor (`src/graph/extract.py`) and first measurements

tree-sitter C, one pass per file (events and flow edges per function) and one pass over the whole code base that binds call
arguments to the callee's parameters and turns each call into a free, a use or nothing from a summary of the callee, iterated
to a fixed point (a wrapper of `free` two calls deep counts). Generic conventions, each with a test: `exit`/`die`/`abort`
end the flow; `&p` passed to a call is a reset of `p`; a name declared in a block is another variable when the block is left
(also by `break`/`continue`) or entered again; a macro whose name contains ALLOC assigns its first argument; `*foreach*` macros
and calls with a block argument are loops that assign their plain-identifier arguments; `FREE_AND_NULL`-style macros free and reset.

Scored by `python -m src.graph.evaluate` with the gate's rules (hit in a `*bad*` function of a BAD file, false positive in a
`*good*` function, a case split over files found if any file is), and on the Git sources (`../git`, 644 files, 400 KLOC) split
by file hash exactly as the synthesis splits them (seed 0, 446 train / 198 test files).

| Query | Juliet | Git train (alerts/KLOC) | Git test (alerts/KLOC) |
|---|---|---|---|
| use after free, first version | 126/138 cases, 0 false positives | 0.320 | 0.232 |
| + the conventions above | 126/138 cases, 0 false positives | 0.014 | 0.063 |
| double free (CWE-415), no tuning | 150/272 cases, 6 false positives | 0.059 | 0.295 |
| + loops that run once, `&p` passed to a function (use after free) | **134/138 cases, 0 false positives** (variants 63 and 64: 4/6 each) | 0.014 | 0.063 |
| + the same (double free) | **162/272 cases, 0 false positives** (variants 63 and 64 are the new ones) | 0.059 | **0.295** (held-out) |

How the numbers were obtained: the conventions were chosen by reading **train** alerts only (the test alerts were counted at each
step, since the evaluator prints both counts, but read only once at the end). The limit of the synthesis gate is 0.1 per KLOC on
the train side, which the use-after-free query meets (0.014) with Juliet recall equal to the hand-checked reference fixture of the
gate (126/138, 0 false positives). The rule synthesis reaches 2.9 alerts/KLOC at best (`findings.md`).

What the alerts still are: all 11 use-after-free alerts left (4 train, 7 test) were read; none is a use after free. They come from
the call summary ("the callee frees its parameter on some path", used after a call on another path), which is the limit documented
in the extractor. CWE-415: variants 01-22 (the data-flow and control-flow variants) are found 6/6 each, the later variants (31+,
across functions and files, pointer-to-pointer) are not; the 6 false positives are one Juliet pattern, a loop `for (j = 0; j < 1; j++)`
that runs once, which a graph that does not evaluate conditions sees as a repeated free. Nothing was tuned on CWE-415: it is the
generalization check, and 0% was the result of the rule synthesis on it for both models.

The second step (the last two rows) added two general conventions with a test each: a `for` with constant bounds and step 1 has no back
edge (it removed the 6 CWE-415 false positives), and a function that is passed `&p` and frees or reads what it loads from `*param`
(`data = *dataPtr`, also through a cast of the parameter) frees or reads `p` at the call site, unless the callee assigns `*param`
(a list `pop`), which is a reset. Without the reset rule, 25 new alerts appeared on the train side (0.101 per KLOC), all from
`pop_commit(&stack)`; with it the numbers went back to 0.014 and 0.063. Variants 63 and 64 are found in 4 of 6 cases each; the rest
pass the pointer through a struct or a global, which is not modelled. **The CWE-415 test number (0.295) is the held-out one: I read
the list of alerts after measuring (the pattern, not every function): none looked like a double free, and 41 of the 50 alerts (train and
test together) are a `ref_transaction_*` call followed by `ref_transaction_free(t)`, where the summary says "the callee frees its
parameter on some path". I did not change the code afterwards.** The fix that this
points to (a summary that requires the free on every path to the exit) is the next step, and its result will not be a clean test
for the seed-0 split.

## Other projects, and what the Git numbers did not show (2026-10-12)

The first table above is Git only, and Git is where the conventions were found. The check on other C projects (protocols and dates in
[graph_progress.md](graph_progress.md)) gave:

| Project (KLOC) | Extractor version | Free events per KLOC | Use after free, train / test | Double free, train / test | Role |
|---|---|---|---|---|---|
| curl (267) | before release macros | 0.5 | 0.005 / 0.000 | 0.005 / 0.000 | held-out, **blind** (curl frees through `curlx_free`) |
| Redis (320) | before the "every path" summaries | 8.5 | **4.131 / 2.561** | 0.866 / 1.039 | held-out, **failed** |
| OpenSSL (862) | before the "every path" summaries | 13.2 | **0.290 / 0.628** | 0.133 / 0.223 | held-out, **failed** |
| Git (400), curl, Redis, OpenSSL | after release macros and "every path" summaries | 6.7 to 13.2 | 0.000 to 0.040 / 0.000 to 0.031 | 0.009 to 0.026 / 0.000 to 0.031 | **development sets** (changed after seeing each) |
| nginx (242), libxml2 (190) | final | **0.5** | 0 / 0 | 0 / 0 | held-out, **blind**: the empty result means nothing |

- **What failed and why.** On Redis and OpenSSL, 98-99% of the alerts had as their "free" a *call* classified by the callee's summary
  ("frees its parameter on some path"): `addReplyArrayLen(c, 2)` seen as freeing the Redis client `c`, `ossl_ssl_init(ssl, ctx, ..)` as freeing `ctx`. One
  wrong summary produced dozens of alerts in a function (222 in one). The same mechanism accounted for 89-100% of the alerts of Git and curl; those
  projects simply have few badly summarized calls. So the 0.014 / 0.063 of the first table was partly luck of the project.
- **The fix** (a summary counts as a free only if the free is on every path from the entry to a return, with explicit entry and return markers, and
  `#if`/`#else` as alternatives) brought the four development projects under 0.1 on both sides. It costs recall on Juliet CWE-415: 162 to 150 of 272
  cases (variants 21 and 22, where the callee frees only if a global flag is set, a true double free). Use after free on CWE-416 is unchanged
  (134/138).
- **Coverage is part of the result.** A project where the extractor sees fewer than 3 `free` events per KLOC is reported as blind, whatever the alert rate:
  it recognizes deallocators by name (`free`, the macros and aliases found in the sources and headers, and functions that free their parameter on
  every path). nginx (pools: `ngx_pfree`, slab) and libxml2 (`xmlFree`, a function-pointer variable) are outside that, so the arm **has not been shown
  to work on a project it was not adapted to**.
- What this says about the first claim: under 0.1 alerts per KLOC holds on four projects after the extractor was adapted to each; the honest
  statement is "on projects whose deallocators it recognizes, after the fixes", not "on real C code".

## No hand-written names: what the analyzer learns by itself (2026-10-12)

The extractor first carried lists written by hand (`kfree`, `g_free`, `OPENSSL_free`, `FREE_AND_NULL`, `die`, `BUG`, macros with `ALLOC` in the
name, `foreach` macros). Those lists were removed: only the C standard library is given (`free`; `malloc`, `calloc`, `realloc`, `strdup`,
`strndup`; `exit`, `_exit`, `_Exit`, `abort`, `quick_exit`, `longjmp`, `thrd_exit`). Everything else comes from the code analyzed:

| What | How it is found |
|---|---|
| Wrappers that free (`curlx_free`, `FREE_AND_NULL`, `xfree`) | `#define`s read as text from the sources and headers (the parser fails on headers such as curl's `curl_setup.h`); an alias of a name that frees is renamed, a function-like macro whose body calls something with a parameter, assigns a parameter or frees one is expanded at its calls |
| Functions that free their parameter | summaries from their bodies: the free must lie on every path from the entry to a return (explicit entry and return markers) |
| Allocators that assign their first argument (`CALLOC_ARRAY`) | the same macro expansion: the body assigns the parameter |
| Loop macros (`kh_foreach`, `hashmap_for_each_entry`) | a `for`/`while` in the body, or a call with no `;` followed by a block, which the parser marks as missing |
| Functions that never return (`die`, `BUG`, `usage`) | `_Noreturn`, `__attribute__((noreturn))` or a macro whose body is that attribute in the declarations; macros that call such a function; functions whose paths all end in one (their bodies) |
| Release functions with no usable body (`g_free`, `OPENSSL_free`, `xmlFree`, a hook) | a three-signal model, calibrated on the project's own `free` and on what its bodies prove (`infer_releases`): the after-use rate of the argument at most twice that of `free`; the argument acquired (assigned from a call) at least half as often as `free`'s; the words of the name resemble those of the functions proven to free (a naive-Bayes model of the words, project prefixes ignored, a word seen in at least two proven releases) |

Usage statistics alone (the first learned version) failed badly (hundreds of alerts per KLOC on double free, Juliet use after free at 98/138):
a function whose argument is just never used afterwards is not necessarily a deallocator (`printLine(data)`, `parse_options(argc, argv)`, `sha1_f1(b, c, d)`
are all last uses). The proven functions of the project give the missing signal: their names say what a deallocator looks like in that
project. No language model is involved: it is the analyzer's own statistics, deterministic and reproducible.

**What became of the old hand-written names** (the project's own code decides; counts are call sites):

| Project | Recognized by the code | Not recognized |
|---|---|---|
| Git | `g_free` (learned); `FREE_AND_NULL` 363 (expanded macro); `die` 2968, `die_errno` 332, `BUG` 803, `usage` 103, `pthread_exit` 2 (declared noreturn) | - |
| curl | - | `g_free` 7, `OPENSSL_free` 8 (libraries with no definition in the code, few uses) |
| Redis | `xfree` 62 (alias of `free`); `die` 8, `usage` 17 (from their bodies) | `panic` 6, `OPENSSL_free` 2 |
| OpenSSL | `OPENSSL_free` 3595 (learned); `usage` 20 | `CRYPTO_free` 15 (goes through a hook) |
| PostgreSQL | `die` 28 (macro, declared noreturn) | `usage` 70, `OPENSSL_free` 2; **`pfree` (2616 uses), the project's own release: the name is one word and the model of words cannot see `free` in it** |

**Alerts per KLOC without any list** (train / test of the split by file hash; the limit of the synthesis gate is 0.1):

| Project (KLOC) | Free events per KLOC | Use after free | Double free | Role |
|---|---|---|---|---|
| Git (400) | 10.8 | 0.000 / 0.000 | 0.017 / 0.009 | development |
| curl (267) | 10.5 | 0.016 / 0.093 | 0.021 / 0.080 | development |
| Redis (320) | 7.3 | 0.071 / **0.231** | 0.004 / 0.042 | development |
| OpenSSL (862) | 17.4 | 0.016 / 0.021 | 0.018 / 0.025 | development |
| **tmux (109)** | **15.2** | **0.000 / 0.000** | 0.058 / 0.000 | **never seen** |
| **PostgreSQL (1597)** | **3.9** | **0.006 / 0.005** | 0.002 / 0.005 | **never seen** |
| nginx (242) | 0.5 | 0 / 0 | 0 / 0 | seen, **blind**: not a result |
| libxml2 (190) | 0.1 | 0 / 0 | 0 / 0 | seen, **blind**: not a result |

Juliet (training side, same data as the rule synthesis): CWE-416 134/138 cases with 0 false positives; CWE-415 150/272 with 0 false positives.

Reading: the two projects the extractor had never seen pass the criterion written beforehand (coverage at least 3 events per KLOC and use after free at
most 0.1 alerts/KLOC), with no list of names inside it. It is **not** a claim about all C code: nginx (pool allocators) and libxml2 (`xmlFree`, a function
pointer) are outside what the analyzer can see and are reported as blind, PostgreSQL passes with a coverage just above the minimum because the model of
names misses `pfree`, and Redis stays above 0.1 on one side. The CWE-415 recall on Juliet is lower than with the old lists (150 against 162 of 272) because
the summaries that count a free only on every path cannot see the variants where a callee frees only if a global flag is set.

## Final extractor: sub-word names and the projects it has not seen (2026-10-12)

The name model now reads a concatenated name through the word it learned (`pfree` through `free`, `zfree`, `hi_sdsfree`), and a function that only
hands its parameter on to a call (as `pfree` does to a hook) no longer counts as a negative example. Effect: the project's own releases are seen. It
came with a price: more of the code's releases are seen, so more false alerts appear.

| Project (KLOC) | Free events per KLOC | Use after free, train / test (all files) | Double free, train / test (all files) | Status |
|---|---|---|---|---|
| Git (400) | 11.2 | 0.000 / 0.000 (0.000) | 0.017 / 0.009 (0.015) | development, pass |
| curl (267) | 10.5 | 0.016 / 0.093 (0.037) | 0.021 / 0.080 (0.037) | development, pass |
| OpenSSL (862) | 17.4 | 0.016 / 0.021 (0.017) | 0.018 / 0.025 (0.020) | development, pass |
| Redis (320) | 13.8 | 0.084 / 0.283 (0.144) | 0.027 / 0.136 (0.059) | development, **fail** on use after free |
| PostgreSQL (1597) | 11.0 (was 3.9) | 0.135 / 0.101 (0.126) | 0.039 / 0.018 (0.033) | seen, **fail** since `pfree` is learned (0.006 / 0.005 before) |
| tmux (109) | 16.0 | 0.000 / 0.000 (0.000) | 0.058 / 0.000 (0.046) | never seen when measured, pass |
| **SQLite (440)** | 7.1 | **0.100 / 0.023 (0.077)** | 0.042 / 0.000 (0.030) | **never seen, pass** |
| **vim (572)** | 5.2 | **0.515 / 0.146 (0.409)** | 0.120 / 0.085 (0.110) | **never seen, fail** |
| nginx (242), libxml2 (190) | 0.5, 0.1 | 0 / 0 | 0 / 0 | blind: not a result |

Juliet: CWE-416 134/138 (0 false positives), CWE-415 150/272 (0 false positives), unchanged.

- **Honest reading.** Of the projects never seen when they were measured, tmux and SQLite pass and vim fails (PostgreSQL passed before the sub-word fix
  and fails after it). The method generalizes in part, not in full: about half of the real projects measured pass the limit of 0.1 with no list of names in
  the analyzer, and the failures concentrate in a few wrongly classified calls (vim: 234 use-after-free alerts from 20 free sites, 179 in one function).
- **The count per KLOC overstates independent mistakes.** One call taken for a release makes every later use of the variable an alert, in every path; a
  per-site count would show the same failures as tens of mistakes, not hundreds of alerts.
- **Seeing more is not free.** The PostgreSQL pass at 0.006 alerts per KLOC came from not recognizing its most used release; once recognized, the rate
  is 0.126. The same happened to Redis with `zfree` and `sdsfree`.

## CWE-401, memory leak (2026-10-13)

The same event graph, with `escape` (a pointer copied into something else), `null` (the branch where a pointer is known to be NULL) and the callee of each
allocation. A leak is an allocation of a local variable that can reach a return on some path along which the variable is not freed, not handed to someone who
keeps it, not stored, not returned and not overwritten; `p = realloc(p, n)` leaks the old block on the path where the call fails. Which calls keep a pointer, and
which functions allocate, are found from the code like the releases: bodies (to a fixed point), readers and allocators learned from how often the caller frees
afterwards, and constants folded so that a branch behind `if (1)` is the only one that runs.

| | Result |
|---|---|
| Juliet CWE-401, C cases (868 BAD, 868 GOOD; the C++ `new` cases and flows 81 to 84 left out) | **648 of 868 cases (74.7%)**; **200 false positives**, all in variants 09, 10, 11, 13 and 14, whose flags are defined in support files that are not in the data. Variants 31, 32, 34, 44, 45 and 63 to 68 (pointer copies, pointer-to-pointer, function pointers, static globals) are not found |
| Development (Git, curl, Redis, OpenSSL), alerts per KLOC in all files | 0.175, 0.097, 0.091, 0.092; allocation sites followed per KLOC 3.2, 2.2, 1.8, 1.0 |
| **Not used to design it, measured once** | tmux 0.321 (fails), PostgreSQL 0.244 (fails), vim 0.044 (passes), SQLite blind (0.8 allocation sites per KLOC, below the minimum of 1) |

Reading: the leak query finds what it was built to find on Juliet and is close to the limit on the four projects it was developed on, but of the three held-out
projects it can be measured on, one passes. It generalizes less well than use after free, because the question "who owns this pointer now" depends on conventions the
analyzer learns less reliably: wrappers that hand the pointer to helpers, registries, ownership passed through fields. How it got there is in
[graph_progress.md](graph_progress.md): a regression caught by the benchmark (derived paths taken for hand-offs), two blind projects fixed with learned allocators, and
a reordering that traded coverage for precision.

### CWE-401, second round: ownership (2026-10-13)

The first held-out measure failed on tmux and PostgreSQL, so their alerts were read and the way ownership is decided was changed for causes that are patterns of C
(macros that store or paste, `&p->f` and `return &p->f` giving a block away, chained assignments, a function returning memory it does not own, types that cannot hold
a pointer, arena allocators). The details are in [graph_progress.md](graph_progress.md). Final numbers, total alerts per KLOC in all files, the same extractor for all:

| Project (KLOC) | Allocation sites per KLOC | Alerts per KLOC (train / test) | Total | Role |
|---|---|---|---|---|
| tmux (109) | 6.2 | 0.035 / 0.045 | **0.037** | development (alerts read), passes |
| curl (267) | 1.7 | 0.073 / 0.040 | **0.064** | development, passes |
| OpenSSL (862) | 1.0 | 0.074 / 0.089 | **0.078** | development, passes |
| Redis (320) | 1.8 | 0.084 / 0.073 | **0.081** | development, passes |
| Git (400) | 2.9 | 0.115 / 0.072 | **0.103** | development, on the line |
| PostgreSQL (1597) | 3.2 | 0.157 / 0.119 | **0.147** | development (alerts read), fails |
| vim (572) | 1.1 | 0.029 / 0.024 | **0.028** | independent, passes |
| **libuv (102)** | 1.7 | 0.055 / 0.138 | **0.078** | **never seen, frozen query, passes** |
| **OpenSSH portable (157)** | 6.9 | 0.249 / 0.154 | **0.210** | **never seen, frozen query, fails** |
| SQLite (440) | 0.8 | 0.074 / 0.031 | 0.061 | blind by the rule (below 1 site per KLOC) |
| Lua (28) | 0.0 | 0 / 0 | 0 | blind: it allocates through a function pointer |

Juliet CWE-401 stayed at 648 of 868 (74.7%) with 200 false positives (the flags defined in files that are not in the data). Reading: ownership is the hard part, and
it moved a lot (tmux 0.321 to 0.037) but not everywhere. Two of three projects the query had never seen pass; six of the nine it can be measured on pass. About 5% of
the allocation sites of real code are flagged even for `malloc` itself in PostgreSQL: that is the noise floor of a path-insensitive query that cannot tell an arena from an
owner, an error path from a normal one, or a registration it cannot see.

## Does it find real bugs? The 16 fix commits of Git (`src/graph/fixcommits.py`)

Protocol of `experiments.md` (16 commits since 2018 whose subject matches `use-after-free|double free|freed|memory after`, fixed
before the script was written; it reproduces exactly 16), the query run on each changed `.c` file before and after the fix, an alert
"near the fix" if it is within 10 lines of a changed line.

| Result | Value |
|---|---|
| Files with an alert near the fix before the fix | **2/16**, and in both the alert is gone after the fix |
| All alerts in those 16 files | 2 before the fix, 0 after |
| Share of the alerts that are at the fix | 2/2; a predictor flagging every `free()` would put 9% (35/375) of its lines within the window |
| The earlier rules (`experiments.md`) | 5/16 near a fix, at the level of chance (36% of `free()` lines near an alert) |

The two alerts are the bugs the commits fixed, read against the diffs: `read-cache.c` (`free(base_path)` before
`trace_performance_leave(.., base_path)`) and `notes.c` (`l->key_oid` used after `note_tree_insert()` freed the leaf, found through the
call summary). Recall is low (2 of 16) and precision in these files is 2 of 2 (n is tiny, a binomial test of 2 of 2 against 9% gives
p of about 0.008).

Why the other 14 are missed (my reading of each diff, one reviewer): 4 use a pointer derived from the freed object (`cp` into
`new_path`, a list inside a freed `config_set`, `dst_name` from `buf.buf`, a tree buffer), 4 free through a project function whose
effect is on a structure (`signature_check_clear(&sigc)`, `free_commit_list`, a callee that frees shared state), 4 are lifetimes of
objects stored in structures and arrays (`q->queue[i]` freed and read in another function, `diff.c` struct lifetimes), and 2 are not a
use after free of the program as written (the semantics of a zero-length `realloc`, `argv` strings kept by other structures). None of
the 14 needs a better judgement of a candidate: the graph does not have the candidate, which is a limit of tracking one variable's
path (aliasing and data-structure lifetimes), not of the filter after it.

## Decision on the LLM judge: not implemented

The plan was a judge that sees a candidate and its path and may only drop it. With the numbers above I do not expect it to help, so
it is not built:

- A filter that only removes candidates can gain on precision only; the query's alerts are 2 in the fix files (both real) and 4
  train / 7 test alerts on the whole of Git (none real). The false positives are already below the real-world limit (0.014 and 0.063),
  so there is no gate the judge would help to pass, and in the fix files it can only lose one of the 2 true alerts.
- What limits the graph is recall, for causes that a judge cannot add (derived pointers, data-structure lifetimes, unmodelled release
  functions). A model that proposed candidates (a second role, not the one in the plan) could address that, but it would be a different
  experiment, with the risk the detector already showed (34% false positives on GOOD code).
- The remaining false positives all have one cause that a deterministic change handles (a summary that requires the free on every
  path), which is cheaper and checkable.

Revisit if the query is widened until its alerts grow to the order of hundreds per KLOC; at the current alert counts a judge has
nothing to filter.
The real-world gate treats the code as correct, so a query that reports little passes it; Juliet recall and the fix commits have
to be read together with it.

## Risks

- The extractor decides everything: a wrong flow edge gives wrong candidates, and the judge cannot add what the query missed.
- The real-world gate treats the code as correct, so an analyzer that reports almost nothing passes it; recall on Juliet and the
  fix commits must be read together with it.
- Juliet variants 63/64 (free and use in different files) need the interprocedural step; until then they are expected misses.
- "Pointer never freed" is CWE-401 (leak), a different query (an alloc event with no path to a free or an escape); it is not in this sketch.

## Decision point (written before the second step)

After the extractor exists for CWE-416: if the query alone is under the real-world limit with Juliet recall below the best rule
synthesis, the judge has nothing to rescue and the arm is only a comparison; if it is over the limit, measure what the judge removes.
Confirm with the advisor before spending time beyond that point, since it changes the scope of the thesis.
