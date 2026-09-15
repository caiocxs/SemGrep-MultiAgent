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

## Setup (Windows)

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

By default this installs the CPU-only `llama-cpp-python` wheel. To run on an
NVIDIA GPU instead:

```powershell
winget install --id Kitware.CMake --source winget
winget install --id Microsoft.VisualStudio.2022.BuildTools --source winget `
  --override "--wait --quiet --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
winget install --id Nvidia.CUDA --version 12.4 --source winget

.\.venv\Scripts\python.exe -m pip install ninja
$env:CMAKE_ARGS  = "-DGGML_CUDA=on -DGGML_AVX512=off -DCMAKE_CUDA_ARCHITECTURES=86"
$env:CMAKE_GENERATOR = "Ninja"
$env:FORCE_CMAKE = "1"
.\.venv\Scripts\python.exe -m pip install --no-binary llama-cpp-python --force-reinstall --no-cache-dir llama-cpp-python
```

Notes:
- `GGML_AVX512=off` is required on 12th/13th/14th-gen Intel consumer CPUs
  (Alder/Raptor Lake), which advertise no AVX-512 support — the community's
  prebuilt CUDA wheels are compiled with AVX-512 and crash with an "illegal
  instruction" error on these chips even before touching the GPU.
- `CMAKE_CUDA_ARCHITECTURES` should match your GPU's compute capability
  (86 = Ampere, e.g. RTX A2000/RTX 30xx).
- The `Ninja` generator avoids needing the CUDA/MSBuild Visual Studio
  integration (which requires admin rights to install); the default Visual
  Studio generator fails with "No CUDA toolset found" without it.
- `N_GPU_LAYERS` in `.env` controls how many layers are offloaded to the GPU
  (`-1` = all, `0` = CPU-only). It currently defaults to `0` (CPU-only) in
  this repo's `.env` — set it to `-1` to use the GPU build above.

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

## Multi-Agent Architecture & Pipeline

The rule generation pipeline operates through an iterative feedback loop powered by four specialized LLM agents
