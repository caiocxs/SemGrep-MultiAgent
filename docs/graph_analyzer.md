# Event-graph analyzer (design sketch)

Status: on branch `feat/graph-analyzer`. The schema, the path queries, the tree-sitter extractor and the scoring against Juliet
and the Git sources exist and are tested (`tests/test_graph_paths.py`, `tests/test_graph_extract.py`); the LLM judge is not written.

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

What this does not show: that the query finds real bugs (the 16 Git fix commits are not run yet), and nothing about the judge.
The real-world gate treats the code as correct, so a query that reports little passes it; Juliet recall and the fix commits have
to be read together with it.

## Risks

- The extractor decides everything: a wrong flow edge gives wrong candidates, and the judge cannot add what the query missed.
- The real-world gate treats the code as correct, so an analyzer that reports almost nothing passes it; recall on Juliet and the
  fix commits must be read together with it.
- Juliet variants 63/64 (free and use in different files) need the interprocedural step; until then they are expected misses.
- "Pointer never freed" is CWE-401 (leak), a different query (an alloc event with no path to a free or an escape); it is not in this sketch.

## Decision point

After the extractor exists for CWE-416: if the query alone is under the real-world limit with Juliet recall below the best rule
synthesis, the judge has nothing to rescue and the arm is only a comparison; if it is over the limit, measure what the judge removes.
Confirm with the advisor before spending time beyond that point, since it changes the scope of the thesis.
