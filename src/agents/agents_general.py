from llama_cpp import Llama
import time
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

llm = None
prompt = None
files = None

def init_model(model="QWEN_CODE"):
    global llm    
    if llm is not None:
        return
    print("Loading model...")
    model_name = os.environ.get(model, model)
    llm = Llama(
        model_path=f".models/{model_name}", 
        n_ctx=4096,
        n_gpu_layers=0,
        verbose=False
    )

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



