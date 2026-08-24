from llama_cpp import Llama
import time
from pathlib import Path

# 1. Carregar o modelo
print("Carregando modelo...\n")
llm = Llama(
    model_path=".models/qwen2.5-coder-3b-instruct-q4_k_m.gguf", 
    n_ctx=2048,      # Tamanho do contexto (quantas palavras ele "lembra" por vez)
    n_gpu_layers=0,   # Mude para -1 se tiver instalado com suporte a GPU
    verbose=False
)

agent_c = Path("prompts/agent_c.md");
prompt_1 = agent_c.read_text(encoding="utf-8")

code_401 = Path("dataset_cwe401/")

for i in range(1):
    file_c = next(code_401.rglob("*.c"), None)
    if(not file_c):
       print("Ocurred an error when grabbing the next file.")

    code = file_c.read_text(encoding="utf-8")
    final_prompt = prompt_1.replace("{{CODE}}", code)

    messages = [
        {"role": "user", "content": final_prompt}
    ]

    print("Gerando resposta...\n")
    init = time.time()

    response = llm.create_chat_completion(
        messages=messages,
        max_tokens=4096,  # Limite de tamanho da resposta
        temperature=0.1  # Criatividade (0 = objetivo, 1 = muito criativo)
    )

    end = time.time()
    total_time = end - init

    data_token = response["usage"]
    token_prompt = data_token["prompt_tokens"]       # O que você enviou
    token_response = data_token["completion_tokens"] # O que o modelo gerou
    token_total = data_token["total_tokens"]

    speed = token_prompt / total_time

    # 3. Exibir a resposta
    print(response["choices"][0]["message"]["content"])
    print(f"\nTime spent: {total_time:.2f} seconds")

    print(f"\nPrompt tokens: {token_prompt}")
    print(f"Answer tokens: {token_response}")
    print(f"Total de tokens: {token_total}")
    print(f"Velocidade: {speed:.2f} tokens/s")

