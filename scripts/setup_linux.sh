#!/usr/bin/env bash
# Sets up the project on Linux: venv, Python deps, llama-cpp-python (CPU or
# CUDA), .env and a Semgrep check. Safe to re-run. Mirrors setup_windows.ps1.
#
#   scripts/setup_linux.sh                     # CPU-only
#   scripts/setup_linux.sh --gpu               # CUDA, GTX 10xx (Pascal, sm_61)
#   scripts/setup_linux.sh --gpu --cuda-arch 86
#
# GPU prerequisites: NVIDIA driver with support for the card (GTX 10xx on Arch:
# nvidia-580xx-dkms from the AUR) and CUDA 12.x - CUDA 13 dropped Pascal.
set -euo pipefail

GPU=0
CUDA_ARCH=61
PYTHON="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --gpu) GPU=1 ;;
        --cuda-arch) CUDA_ARCH="$2"; shift ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
    shift
done

cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
    echo "Creating .venv with $PYTHON..."
    "$PYTHON" -m venv .venv
fi
PY=.venv/bin/python

echo "Installing Python dependencies..."
"$PY" -m pip install --upgrade pip
"$PY" -m pip install -r requirements.txt

if [[ $GPU -eq 1 ]]; then
    echo "Building llama-cpp-python with CUDA (sm_$CUDA_ARCH)..."
    CMAKE_ARGS="-DGGML_CUDA=on -DGGML_AVX512=off -DCMAKE_CUDA_ARCHITECTURES=$CUDA_ARCH" FORCE_CMAKE=1 \
        "$PY" -m pip install --no-binary llama-cpp-python --force-reinstall --no-cache-dir llama-cpp-python
else
    echo "Installing llama-cpp-python (CPU)..."
    "$PY" -m pip install llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
fi

if [[ ! -f .env ]]; then
    cp .env.example .env
    echo "Created .env from .env.example."
fi
if [[ $GPU -eq 1 ]]; then
    echo "[i] Set N_GPU_LAYERS=-1 in .env to use the GPU for the detector benchmark."
fi

if command -v semgrep >/dev/null; then
    echo "Semgrep found: $(semgrep --version)"
else
    echo "[!] Semgrep not found. Install it with: pipx install semgrep" >&2
fi

echo
echo "Model status for combo A:"
"$PY" -m src.config --combo A
echo
echo "Done. Download a combo's models with: $PY -m src.config --combo B --download"
