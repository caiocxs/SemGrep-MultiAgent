from llama_cpp import Llama
import time
from pathlib import Path

llm = None
files = None

def init_model(model="qwen2.5-coder-3b-instruct-q4_k_m.gguf")
    print("Carregando modelo...")
    llm = Llama(
        model_path=f".models/{model}", 
        n_ctx=4096,
        n_gpu_layers=0,
        verbose=False
    )

    print("Carregando prompt...")
    agent_c = Path("prompts/agent_c.md");
    if (not agent_c):
        print("Prompt not found!")
    prompt_1 = agent_c.read_text(encoding="utf-8")

    print("Carregando datasets...")
    code_401 = Path("dataset_cwe401/")
    if (not code_401):
        print("Dataset not found")

    files = code_401.rglob("*.c")
    if(not files):
       print("Ocurred an error when grabbing the code.")



