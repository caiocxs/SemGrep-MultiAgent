from llama_cpp import Llama
import time
from pathlib import Path

# 1. Carregar o modelo
llm = Llama(
    model_path=".models/qwen2.5-coder-3b-instruct-q4_k_m.gguf", 
    n_ctx=2048,      # Tamanho do contexto (quantas palavras ele "lembra" por vez)
    n_gpu_layers=0,   # Mude para -1 se tiver instalado com suporte a GPU
    verbose=False
)

agent_c = Path("prompts/agent_c.md");
