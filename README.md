# Generative Static Analysis with LLMs: Optimizing Vulnerability Detection in Semgrep via a Multi-Agent Approach

> **Bachelor's Thesis (Computer Science — SENAC Santo Amaro)**  
> **Author:** Caio Xavier da Silva

---

## Overview

Traditional Static Application Security Testing (SAST) tools rely heavily on rigid, handcrafted logic, limiting scalability and the detection of corner cases. Conversely, direct whole-codebase scanning using Large Language Models (LLMs) incurs quadratic computational complexity ($O(n^2)$) and carries risks of hallucination.

This project proposes an **LLM-based multi-agent framework** designed to **automatically synthesize, validate, and optimize static analysis rules for Semgrep**, specifically targeting critical memory-safety vulnerabilities (CWEs) in the **C programming language**.

---

## Target CWEs (C Language)

The framework focuses on five critical memory-management weaknesses

| CWE         | Description                                                        |
| ----------- | ------------------------------------------------------------------ |
| **CWE-401** | _Missing Release of Memory after Effective Lifetime_ (Memory Leak) |
| **CWE-415** | _Double Free_                                                      |
| **CWE-416** | _Use After Free (UAF)_                                             |
| **CWE-457** | _Use of Uninitialized Variable_                                    |
| **CWE-476** | _NULL Pointer Dereference_                                         |

---

## Setup

Requirements: Python 3.11+ (3.13 recommended on Windows), and
[Semgrep](https://semgrep.dev/docs/getting-started/) installed as a CLI
(`pipx install semgrep`). The setup scripts create `.venv`, install the Python
dependencies and `llama-cpp-python`, create `.env` from `.env.example` and check
that Semgrep is on the PATH. Both are safe to re-run.

**Windows (PowerShell):**

```powershell
.\scripts\setup_windows.ps1                     # CPU-only
.\scripts\setup_windows.ps1 -Gpu                # CUDA, GTX 10xx (sm_61, default)
.\scripts\setup_windows.ps1 -Gpu -CudaArch 86   # CUDA, RTX 30xx / A2000
```

GPU prerequisites on Windows (install once, before running with `-Gpu`):

```powershell
winget install --id Kitware.CMake --source winget
winget install --id Microsoft.VisualStudio.2022.BuildTools --source winget `
  --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Nvidia.CUDA --version 12.4 --source winget
```

**Linux:**

```bash
scripts/setup_linux.sh                     # CPU-only
scripts/setup_linux.sh --gpu               # CUDA, GTX 10xx (sm_61, default)
scripts/setup_linux.sh --gpu --cuda-arch 86
```

GPU prerequisites on Linux: an NVIDIA driver that supports the card and CUDA
12.x. On Arch, GTX 10xx cards need `nvidia-580xx-dkms` (AUR) — the current
`nvidia-open` driver no longer supports Pascal.

**Models:** download the GGUF files of a combo (see [Model Combos](#model-combos-6-gb-gpu)):

```bash
.venv/bin/python -m src.config --combo B --download          # Linux
.\.venv\Scripts\python.exe -m src.config --combo B --download  # Windows
```

Notes:
- CUDA 13 dropped Pascal (GTX 10xx) support — use CUDA 12.x for those cards.
- `GGML_AVX512=off` is required on 12th/13th/14th-gen Intel consumer CPUs
  (Alder/Raptor Lake), which advertise no AVX-512 support — the community's
  prebuilt CUDA wheels are compiled with AVX-512 and crash with an "illegal
  instruction" error on these chips even before touching the GPU.
- `CMAKE_CUDA_ARCHITECTURES` should match your GPU's compute capability
  (61 = Pascal, e.g. GTX 1060; 86 = Ampere, e.g. RTX A2000/RTX 30xx).
- On Windows, the `Ninja` generator avoids needing the CUDA/MSBuild Visual
  Studio integration (which requires admin rights to install); the default
  Visual Studio generator fails with "No CUDA toolset found" without it.
- `N_GPU_LAYERS` in `.env` controls how many layers are offloaded to the GPU
  (`-1` = all, `0` = CPU-only). `.env.example` defaults to `0` — set it to `-1`
  after a GPU build.
- If PowerShell blocks the script, run once:
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- With `-Gpu`, run the script from a Visual Studio developer environment (e.g. after
  `vcvars64.bat`), otherwise Ninja can't find `cl.exe`.
- On the default Windows console, set `PYTHONUTF8=1` before `--download`; otherwise the
  final "✓" message raises `UnicodeEncodeError` (the file is already saved by then).

## Models

Model files live in `.models/` (gitignored) and are referenced by env key in
`.env`. All three are **instruction-tuned** variants — base/completion
checkpoints (tried first for DeepSeek and StarCoder2) don't reliably follow
the "respond only with JSON" instruction and mostly produce unparseable
prose or code echoes instead of a verdict:

| Env key           | Model file                                     | Source                                              |
| ----------------- | ----------------------------------------------- | ---------------------------------------------------- |
| `QWEN_CODE`        | `Qwen2.5-Coder-3B-Q4_K_M.gguf`                  | Qwen2.5-Coder-3B-Instruct                             |
| `DEEP_SEEK_CODER`  | `deepseek-coder-1.3b-instruct.Q4_K_M.gguf`      | TheBloke/deepseek-coder-1.3b-instruct-GGUF            |
| `STARCODER2`       | `starcoder2-3b-instruct-techxgenus.Q4_K_M.gguf` | RichardErkhov/TechxGenus_-_starcoder2-3b-instruct-gguf |

Generation is constrained to the JSON schema in `prompts/code_analyser.md`
via a GBNF grammar (`code_agent.get_grammar()`, built from
`RESPONSE_SCHEMA`), so parsing failures should be rare regardless of model.

## Usage

```powershell
# Everything: all models (QWEN_CODE, STARCODER2, DEEP_SEEK_CODER order) x all datasets
.\.venv\Scripts\python.exe -m src

# One model/dataset, capped to a few files (good for a quick check)
.\.venv\Scripts\python.exe -m src --models QWEN_CODE --datasets CWES_BAD --limit 5

# Multiple models/datasets (comma-separated)
.\.venv\Scripts\python.exe -m src --models STARCODER2,DEEP_SEEK_CODER --datasets CWES_GOOD,CWES_BAD

# Reprocess files that already have a log
.\.venv\Scripts\python.exe -m src --no-skip
```

Runs are resumable: files that already have a `log_<name>.json` under
`LOGS_LOCATION`/`<model>/<dataset>/` are skipped on the next run unless
`--no-skip` is passed.

## Log Utilities

- **`src/reformat_logs.py`** — re-parses logs saved as
  `{"error": ..., "raw_response": ...}` (JSON extraction failed on the first
  pass) and rewrites the original log file in place when a valid JSON object
  can be recovered from the raw response.
  ```powershell
  .\.venv\Scripts\python.exe src\reformat_logs.py [--root logs/dataset/] [--dry-run]
  ```
- **`src/analyze_logs.py`** — reports, per model/dataset, average processing
  time and bad/good detection accuracy (ground truth from the dataset
  folder name: `*BAD*` expects `vulnerable=true`, `*GOOD*` expects `false`).
  ```powershell
  .\.venv\Scripts\python.exe src\analyze_logs.py [--root logs/dataset/] [--output summary.json]
  ```

## Model Combos (6 GB GPU)

The rule-generation pipeline has five LLM roles — **detector**, **generator**,
**corrector**, **critic** and **merger** — plus a deterministic Semgrep gate
(no LLM) between generation and acceptance. Each *combo* assigns a model to
every role and is sized for a **GTX 1060 6 GB** (≈5 GB usable for weights +
KV cache). Only one model is loaded at a time; stages run in batches so a
full run swaps models at most ~3 times.

| Combo | Detector | Generator / Corrector / Merger | Critic | Question it answers |
| ----- | -------- | ------------------------------ | ------ | ------------------- |
| **A** (baseline) | Qwen2.5-Coder-3B Q6_K | Qwen2.5-Coder-3B Q6_K | Qwen2.5-Coder-3B Q6_K | How far does one small model go alone? |
| **B** (main bet) | Qwen2.5-Coder-3B Q6_K | Qwen2.5-Coder-7B IQ4_XS | Phi-4-mini Q6_K | Is a bigger rule writer worth it? |
| **C** | Qwen2.5-Coder-3B Q6_K | Qwen3-4B-Instruct-2507 Q6_K | Phi-4-mini Q6_K | Newer 4B at Q6 vs. older 7B at IQ4? |

Config files:

- `configs/models.toml` — model catalog (Hugging Face repo, GGUF file, quant, size).
- `configs/combos/combo_<a|b|c>.toml` — per-role model, `n_ctx`, `max_tokens`,
  temperature and the corrector loop limit (`max_fix_attempts`).

Check a combo and get the download links of the missing GGUF files:

```powershell
.\.venv\Scripts\python.exe -m src.config --combo B
```

### Models used

GGUF files go into `.models/`. The download link for each file is
`https://huggingface.co/<GGUF repo>/resolve/main/<file>`.

| Model | GGUF repo (file) | Size | Original model |
| ----- | ---------------- | ---- | -------------- |
| Qwen2.5-Coder-3B-Instruct | [bartowski/Qwen2.5-Coder-3B-Instruct-GGUF](https://huggingface.co/bartowski/Qwen2.5-Coder-3B-Instruct-GGUF) (`Qwen2.5-Coder-3B-Instruct-Q6_K.gguf`) | 2.54 GB | [Qwen/Qwen2.5-Coder-3B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-3B-Instruct) |
| Qwen2.5-Coder-7B-Instruct | [bartowski/Qwen2.5-Coder-7B-Instruct-GGUF](https://huggingface.co/bartowski/Qwen2.5-Coder-7B-Instruct-GGUF) (`Qwen2.5-Coder-7B-Instruct-IQ4_XS.gguf`) | 4.22 GB | [Qwen/Qwen2.5-Coder-7B-Instruct](https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct) |
| Qwen3-4B-Instruct-2507 | [bartowski/Qwen_Qwen3-4B-Instruct-2507-GGUF](https://huggingface.co/bartowski/Qwen_Qwen3-4B-Instruct-2507-GGUF) (`Qwen_Qwen3-4B-Instruct-2507-Q6_K.gguf`) | 3.31 GB | [Qwen/Qwen3-4B-Instruct-2507](https://huggingface.co/Qwen/Qwen3-4B-Instruct-2507) |
| Phi-4-mini-instruct | [bartowski/microsoft_Phi-4-mini-instruct-GGUF](https://huggingface.co/bartowski/microsoft_Phi-4-mini-instruct-GGUF) (`microsoft_Phi-4-mini-instruct-Q6_K.gguf`) | 3.16 GB | [microsoft/Phi-4-mini-instruct](https://huggingface.co/microsoft/Phi-4-mini-instruct) |
| Qwen3-Coder-30B-A3B-Instruct *(optional)* | [unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF](https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF) (`Qwen3-Coder-30B-A3B-Instruct-IQ4_XS.gguf`) | 16.38 GB | [Qwen/Qwen3-Coder-30B-A3B-Instruct](https://huggingface.co/Qwen/Qwen3-Coder-30B-A3B-Instruct) |

Notes for 6 GB / Pascal cards:

- Build `llama-cpp-python` with `CMAKE_CUDA_ARCHITECTURES=61` and **CUDA 12.x** —
  CUDA 13 dropped Pascal (GTX 10xx) support.
- The 7B's Q4_K_M (4.68 GB) barely fits; IQ4_XS is the default. Keep its
  `n_ctx` at 8192.
- If a model runs out of VRAM, lower `n_gpu_layers` in the combo (partial
  offload is still much faster than CPU-only) before switching to a smaller model.
- Avoid Q4 for the 3–4B models: rigid output (JSON/YAML) degrades noticeably.
- The optional MoE model keeps its experts on the CPU (`--n-cpu-moe`) and
  needs ~20 GB of free system RAM.

## Semgrep Gate

`src/pipeline/gate.py` is the deterministic (no LLM) check every candidate
rule goes through. It runs the rule on BAD and GOOD Juliet files and grades
each match by its enclosing function — `*good*` functions count as false
positives, `*bad*` ones as hits — since Juliet files mix both (a GOOD file
still contains the never-called `helperBad`). Recall is counted per test case,
so a case split across files (`_63a` + `_63b`) counts once. Its feedback text
is what the corrector agent receives.

```bash
python -m src.pipeline.gate --rule <rule>.yaml \
    --bad datasets/cwes_mixed/bad --good datasets/cwes_mixed/good --filter "CWE416*"
```

Rules are generated by the local models (generator/corrector agents); the
gate itself uses no LLM. `tests/fixtures/rules/cwe416_uaf.yaml` is a
known-good rule used **only** to test the gate (written with an AI assistant
while building it) — it is not part of the pipeline, not a prompt example and
not a thesis baseline. For reference, it detects 126/138 CWE-416 cases on
`datasets/cwes_mixed` with 0 false positives; the misses are the 63/64
variants, where the free and the use are in different files.

Tests (`tests/fixtures/` holds a few Juliet files, so they run without `datasets/`):

```bash
python -m pytest
```

## Rule Synthesis (generator → gate → corrector)

`src/pipeline/synthesize.py` generates a Semgrep rule for one CWE with the
local models of a combo:

1. The CWE's Juliet files are split into train/test **by flow variant**
   (`src/pipeline/split.py`) — files of one variant only differ in data type,
   so they always land on the same side.
2. Up to 3 findings of the detector on the train files are picked as examples,
   each from a different flow variant and family (`src/pipeline/findings.py`).
   Findings on GOOD files (detector false positives) can be picked too — the
   system doesn't know which findings are right.
3. The **generator** (`prompts/rule_generator.md`) writes a rule. Its prompt
   includes excerpts of the official Semgrep docs (`prompts/semgrep_docs.md`,
   generic syntax only — no CWE-specific hints).
4. The rule is extracted, normalized (id, `languages: [c]`, severity, metadata)
   and linted for names copied from the examples (`src/pipeline/rules.py`),
   then graded by the gate on the train files.
5. While it fails, the **corrector** (`prompts/rule_corrector.md`) gets the
   rule, the gate feedback and the code it missed, up to `max_fix_attempts`.
6. The best attempt is accepted if it passes (no false positives, train recall
   ≥ `--min-recall`) and is always evaluated on the held-out test files.

```bash
python -m src.pipeline.synthesize --combo A --cwe CWE-416
```

Outputs: every attempt in `rules/candidates/<combo>/<cwe>/<run>/`, the
accepted rule in `rules/accepted/<combo>/<cwe>.yaml`, and the full run log
(prompts sizes, raw responses, gate reports, timings, test result) in
`logs/synthesis/<combo>/<cwe>/<run>.json`.

`--format spec` changes what the model writes: instead of the rule's YAML it writes a
JSON of patterns (`src/pipeline/spec.py`) and the program builds the rule, so the model
never handles YAML quoting or operator nesting. Default is `--format yaml`.

`--format template` is an experimental arm where a strategy written by us (a state change
of a variable, run as Semgrep taint mode) is predefined and the model only fills in the
patterns (`event`, `uses`, `resets`); see [docs/changes.md](docs/changes.md) phase 8.

`--samples N [--temperature T] [--stop-on-pass]` runs N independent generator/corrector
loops (best-of-N); the gate picks the best attempt on the train files and only that one is
evaluated on the held-out test files. The fraction of samples that pass is a measure of
how often a model can write a valid rule.

The ablation table (what each change did, per factor) is in [docs/ablation.md](docs/ablation.md).

Results of the runs so far are in [docs/experiments.md](docs/experiments.md); the errors
found and every change made in response are in [docs/changes.md](docs/changes.md).

## Multi-Agent Architecture & Pipeline

The rule generation pipeline operates through an iterative feedback loop powered by four specialized LLM agents
