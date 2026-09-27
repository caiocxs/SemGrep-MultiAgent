<#
.SYNOPSIS
    Sets up the project on Windows: venv, Python deps, llama-cpp-python (CPU or
    CUDA), .env and a Semgrep check. Safe to re-run.

.EXAMPLE
    .\scripts\setup_windows.ps1                       # CPU-only
    .\scripts\setup_windows.ps1 -Gpu                  # CUDA, GTX 10xx (Pascal, sm_61)
    .\scripts\setup_windows.ps1 -Gpu -CudaArch 86     # CUDA, RTX 30xx / A2000 (Ampere)

.NOTES
    GPU prerequisites (see README): CMake, VS 2022 Build Tools (C++ workload)
    and CUDA 12.x. CUDA 13 dropped Pascal (GTX 10xx) support.
    If script execution is blocked, run once:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#>
param(
    [switch]$Gpu,
    [string]$CudaArch = "61",
    [string]$Python = "3.13"
)

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

if (-not (Test-Path ".venv")) {
    Write-Host "Creating .venv with Python $Python..."
    py "-$Python" -m venv .venv
}
$py = ".\.venv\Scripts\python.exe"

Write-Host "Installing Python dependencies..."
& $py -m pip install --upgrade pip
& $py -m pip install -r requirements.txt

if ($Gpu) {
    Write-Host "Building llama-cpp-python with CUDA (sm_$CudaArch)..."
    & $py -m pip install ninja
    # GGML_AVX512=off: 12th-14th gen Intel consumer CPUs have no AVX-512.
    # Ninja avoids needing the CUDA/MSBuild Visual Studio integration.
    $env:CMAKE_ARGS = "-DGGML_CUDA=on -DGGML_AVX512=off -DCMAKE_CUDA_ARCHITECTURES=$CudaArch"
    $env:CMAKE_GENERATOR = "Ninja"
    $env:FORCE_CMAKE = "1"
    & $py -m pip install --no-binary llama-cpp-python --force-reinstall --no-cache-dir llama-cpp-python
} else {
    Write-Host "Installing llama-cpp-python (CPU)..."
    & $py -m pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
}
if ($LASTEXITCODE -ne 0) { throw "llama-cpp-python installation failed." }

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "Created .env from .env.example."
}
if ($Gpu) {
    Write-Host "[i] Set N_GPU_LAYERS=-1 in .env to use the GPU for the detector benchmark."
}

if (Get-Command semgrep -ErrorAction SilentlyContinue) {
    Write-Host "Semgrep found: $(semgrep --version)"
} else {
    Write-Warning "Semgrep not found. Install it with: pipx install semgrep  (or run the pipeline from WSL)."
}

Write-Host "`nModel status for combo A:"
& $py -m src.config --combo A
Write-Host "`nDone. Download a combo's models with: $py -m src.config --combo B --download"
