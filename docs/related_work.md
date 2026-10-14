# Our results against the reference papers

Four papers are kept in `tcc/fontes` as the reference for this work. This page places our numbers next to theirs and says
what can and cannot be compared. Every figure quoted from a paper was read from the paper itself; every figure of ours comes
from `docs/graph_progress.md`, `docs/graph_analyzer.md`, `docs/findings.md` and `docs/ablation.md`.

## The papers

| Paper | What it does | Model and cost | Evaluation |
|---|---|---|---|
| **KNighter** (Yang et al., SOSP 2025) | Synthesizes Clang Static Analyzer checkers from historical Linux kernel patches, with a refinement loop and a triage agent | o3-mini; 15.9 h and about $0.24 per commit | 61 commits; 39 valid checkers, 37 plausible; 90 reports labelled "bug", 61 confirmed (false positive rate 32.2%); 92 new kernel bugs, 77 confirmed, 30 CVEs |
| **Hou et al.** (QRS 2025), generation, migration and optimization of Semgrep rules | Generates Semgrep rules from a description and a few examples, migrates them across languages, repairs official rules | LLMs; the paper stresses that no large GPU cluster is needed | Official Semgrep ruleset: 81.98% grammatically valid, 74.73% functionally valid (the rule reports the bug in the buggy snippet); on the 61 KNighter commits 41 effective rules against 37; 9 new kernel bugs |
| **RepoAudit** (Guo et al., ICML 2025) | LLM agent that follows data-flow facts along feasible paths, with a validator for path conditions | Claude 3.5 Sonnet; 0.44 h and $2.54 per project on average | NPD, memory leak and use after free; 40 true bugs in 15 projects, precision 78.43%; 185 new bugs, 174 confirmed or fixed |
| **Li et al.** (arXiv 2601.19239, 2026), project-scale empirical study | Compares five LLM-based detectors and two traditional tools (CodeQL, Semgrep) | up to 38 million output tokens and multi-day runs per project | known C/C++ vulnerabilities of CWE-401 (40), 416 (10) and 476 (14); 385 warnings labelled by hand on 24 projects (more than 150 human hours) |

## Same question, different question

The papers answer "does the tool find known or new bugs, and how many of its reports are wrong". Our experiments answer
"does a rule or a graph query stay quiet on code that is assumed correct, and does it detect on the Juliet suite". The two
are related but not the same, so the table below puts figures side by side only where the measurement is of the same kind.

## What lines up

**1. Rules written by a model: the snippet is not the test.** Hou et al. and KNighter validate a generated rule on the
buggy snippet of the commit that motivated it. By that criterion our results look like theirs: syntax converges within a few
corrections, and the local 30B model detects in 71.6% of the held-out CWE-416 variants (Hou et al. 74.73%, a different
dataset and a different criterion). Li et al. tested the same kind of tool on code it had not been built for and found that
KNighter, CodeQL and Semgrep detected none of the vulnerabilities of the three CWEs (Table IV of that paper). Our own gate points the same way from another
side: **0 of 60 cross-validation folds passed** once the rule also had to stay quiet on real C code (2.5 alerts per KLOC for
the 30B model against a limit of 0.1). A rule that detects in the snippet says little about its behaviour on a project.

**2. Why rules fail.** Li et al. attribute most misses to source and sink definitions that do not match the APIs of the project
(the KNighter checkers and the CodeQL and Semgrep rules). The same thing shows up here in two places. The model writes the right idea
and cannot express it (`docs/findings.md`), and the graph query is blind where allocation is not a plain call: SQLite, Lua
(function pointer) and libpng (`png_malloc`) fall under 1 allocation site per KLOC and are reported as blind instead of passing.

**3. What cannot be done inside one function.** Li et al. list concurrency, nested control flow and shallow interprocedural
reasoning as the remaining causes. Our fix-commit study of Git (`docs/graph_analyzer.md`) found the same set: 14 of 16 misses
come from pointers derived from the freed object, frees through project functions that act on a structure, and lifetimes of
objects stored in structures, and none of them is a filtering problem, the path simply is not in the graph.

**4. Cost.** Li et al. report hundreds of thousands to hundreds of millions of tokens and hours to days per project for the
LLM-based tools. The graph arm uses no tokens: extraction of OpenSSH (157 KLOC) takes about 19 s and a query under a second on
a CPU; PostgreSQL (1.6 MLOC) about 4 min. The model-written rule arm runs on a GTX 1060 or the free tier of a hosted model.

## Where we are behind

- **No bug of ours has been confirmed by a maintainer.** KNighter has 77 confirmed, RepoAudit 174, Hou et al. 9 new. We have
  two real bugs found in the Git fix-commit study, both already fixed upstream.
- **Recall on real vulnerabilities is low.** 2 of 16 Git fix commits for use after free. Li et al. measure RepoAudit at 10%
  (1 of 10) for CWE-416, 55% (22 of 40) for CWE-401 and 28.6% (4 of 14) for CWE-476 on their own set, which we did not run, so
  the figures are not comparable, only the order of magnitude: all of us are weak on use after free in real projects.
- **Precision on real code is not measured by labelling.** Li et al. labelled 385 reports by hand. We treat real code as
  correct and count alerts per KLOC, which counts a real bug as a false positive and a repeated error as many alerts. For the
  leak query the alerts we read in tmux and PostgreSQL were mostly ownership errors, so the real precision is probably low even
  where the count is under 0.1 per KLOC.
- **The Juliet numbers are synthetic.** 97.1% on CWE-416 is not a claim about real software; neither paper reports Juliet.

## Where the numbers are at least not worse

| | Reference | This work |
|---|---|---|
| Volume of reports on real C code, memory leak | RepoAudit averages 346 reports per project for CWE-401, KNighter 3, CodeQL 47, Semgrep 13 (Li et al.), with a sampled false discovery rate of 100% for RepoAudit, KNighter and Semgrep (sample of up to 10 reports per project) | graph query, 11 projects measured: 0.028 to 0.153 alerts per KLOC; 8 of 11 projects at or under 0.1, none of the four independent ones over |
| Sampled false discovery rate on C/C++ (all CWEs) | RepoAudit 97.0%, KNighter 100%, Semgrep 92.3% | not measured, see above |
| Tokens per project | 225 million input tokens at the high end (Li et al.) | 0 |
| Valid rule rate of a generated rule | KNighter 39 of 61 commits (64%); Hou et al. 74.73% | local models: syntax converges with the feedback loop; accepted by the real-code gate in 0 of 60 folds |

The comparison on volume is a comparison of different projects and different CWE sets (for CWE-401 the paper uses the Linux kernel,
ImageMagick and others). It says that a deterministic query on the path of one allocation can be an order of
magnitude quieter than an LLM agent, not that it is more accurate: quiet and correct are different properties.

## What this work adds to the literature

1. **A gate with real negatives for generated rules** (alerts per KLOC on assumed-correct code, split by file hash). None of the
   papers above uses one; KNighter and Hou et al. check the buggy and fixed snippet only, and the cost shows: rules that pass
   the snippet fail the project test in every case we measured.
2. **A fair account of small local models** with a pre-registered ablation, paired by seed and fold: the 4B reaches 30% recall and
   Phi-4-mini 0%, the 30B reaches the right idea and not the right expression, and a 120B hosted model raises recall by 0.27
   (interval +0.12 to +0.41, two seeds) without passing the gate.
3. **A graph arm without hand-written lists**: only the C standard library is given; macros, allocators, deallocators,
   `noreturn` functions, constants and ownership are learned from the code of each project, with a record of which projects were
   used to design the query and which were never seen. The independent record for the leak query is vim, libuv, zlib and
   memcached passing, SQLite, Lua and libpng blind, none failing.

## Limits of this comparison

The datasets differ (Linux kernel and Java in the papers; Juliet and general C projects here), as do the metrics (labelled
reports against alerts per KLOC), the models (hosted frontier models against local 4B to 30B and one 120B), and the CWEs
(CWE-401, 416 and 476 overlap with Li et al.; CWE-415 does not). No number of ours should be read as beating a number of theirs.
The point of the table is which claims survive across the two ways of measuring.

## Direct comparison on the benchmark of Li et al. (2026-10-13)

The graph arm was run on their data (replication package `Feng-Jay/LLM4Security`), with the protocol written before the measurement
(`docs/graph_progress.md`). Details, causes and the version after the cast fix are in that file.

| Benchmark | RepoAudit | KNighter | CodeQL | Semgrep | Graph arm (no LLM) |
|---|---|---|---|---|---|
| In-house, CWE-401, 40 kernel cases (recall) | 22/40 (55.0%) | 0 | 0 | 0 | **blind**: 0 `free` events and 0 allocation sites in all 40 |
| In-house, CWE-416, 10 kernel cases | 1/10 | 0 | 0 | 0 | **blind** in all 10 |
| In-house, CWE-476, 14 kernel cases | 4/14 | 0 | 0 | 0 | no query |
| ImageMagick, CWE-401 (reports; sampled false discovery) | 348 (10/10) | 0 | 141 (9/10) | 37 (10/10) | 454 (10/10); **65 (7/10) after the cast fix**, development |
| vim, CWE-416 | 32 (10/10) | 0 | 1 (1/1) | 2 (2/2) | 235 (10/10) |
| Linux `sound`, `mm`, `net`, `drivers/net` | 333, 356, 3, 1 reports | 6, 3, 12, 79 | 0 | 0 | blind (no `free`) |

Reading: on the kernel, where all 50 of the in-house cases and four of the six real-world projects are, the graph arm has nothing to learn from because the
kernel does not call `malloc` or `free`; on the two C projects it can read, it raises more reports than any reference tool and its sampled alerts are as
wrong as theirs (0 of 20 real before the fix). After one general fix found by reading that sample, ImageMagick drops to 65 reports and 3 of 10 sampled look real
(error-path leaks); that number is not independent. The earlier "under 0.1 alerts per KLOC" results do not predict the sampled precision, as stated before.
