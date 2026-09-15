import gc
import time
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()


def _register_cuda_dll_path():
    """
    On Windows, llama-cpp-python's own DLL loader only honors CUDA_PATH\\bin
    through the legacy (PATH-based) search order, not os.add_dll_directory.
    Must run before `import llama_cpp` so cudart/cublas resolve at load time.
    """
    if os.name != "nt":
        return
    cuda_path = os.environ.get("CUDA_PATH")
    if not cuda_path:
        root = r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA"
        versions = sorted(os.listdir(root)) if os.path.isdir(root) else []
        cuda_path = os.path.join(root, versions[-1]) if versions else None
    if cuda_path:
        cuda_bin = os.path.join(cuda_path, "bin")
        if os.path.isdir(cuda_bin):
            os.environ["PATH"] = cuda_bin + os.pathsep + os.environ.get("PATH", "")


_register_cuda_dll_path()

from llama_cpp import Llama

llm = None
current_model = None
prompt = None
files = None

def init_model(model="QWEN_CODE"):
    global llm, current_model
    if llm is not None and current_model == model:
        return
    if llm is not None:
        print(f"Unloading model '{current_model}' to load '{model}'...")
        del llm
        llm = None
        gc.collect()
    print(f"Loading model ({model})...")
    model_name = os.environ.get(model, model)
    n_gpu_layers = int(os.environ.get("N_GPU_LAYERS", "-1"))
    n_ctx = int(os.environ.get("N_CTX", "16384"))
    llm = Llama(
        model_path=f".models/{model_name}",
        n_ctx=n_ctx,
        n_gpu_layers=n_gpu_layers,
        verbose=False
    )
    current_model = model

def load_prompt(agent="code_analyser"):
    global prompt
    print("Loading prompt...")
    current_agent = Path(f"prompts/{agent}.md")
    if not current_agent.exists():
        print("Prompt not found!")
    prompt = current_agent.read_text(encoding="utf-8")

def load_dataset(dataset="CWES_BAD"):
    global files
    print(f"Loading dataset ({dataset})...")
    dataset_path = os.environ.get(dataset, dataset)
    code = Path(dataset_path)
    if not code.exists():
        print(f"Dataset not found: {dataset_path}")

    files = sorted(list(code.rglob("*.c")))
    if not files:
        print("Occurred an error when grabbing the code.")



