try:
    from . import agents_general
except ImportError:
    import agents_general

import time
from pathlib import Path
import os
import json
import re
from dotenv import load_dotenv

load_dotenv()

llm = None
prompt = None
files = None


def extract_json(text: str):
    if not text or not isinstance(text, str):
        return None

    cleaned = text.strip()

    try:
        return json.loads(cleaned, strict=False)
    except json.JSONDecodeError:
        pass

    code_block_matches = re.findall(r"```(?:json)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
    for block in code_block_matches:
        block_clean = block.strip()
        try:
            return json.loads(block_clean, strict=False)
        except json.JSONDecodeError:
            repaired = re.sub(r",\s*([\]}])", r"\1", block_clean)
            try:
                return json.loads(repaired, strict=False)
            except json.JSONDecodeError:
                pass

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    first_bracket = text.find("[")
    last_bracket = text.rfind("]")

    candidates = []
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        candidates.append(text[first_brace:last_brace + 1])
    if first_bracket != -1 and last_bracket != -1 and last_bracket > first_bracket:
        candidates.append(text[first_bracket:last_bracket + 1])

    for candidate in candidates:
        try:
            return json.loads(candidate, strict=False)
        except json.JSONDecodeError:
            repaired = re.sub(r",\s*([\]}])", r"\1", candidate)
            try:
                return json.loads(repaired, strict=False)
            except json.JSONDecodeError:
                pass

    return None


def init_agent(model="QWEN_CODE", prompt_name="code_analyser", dataset="CWES_BAD"):
    global llm, prompt, files
    print(f"Initializing code agent (dataset={dataset})...\n")
    agents_general.init_model(model)
    agents_general.load_prompt(prompt_name)
    agents_general.load_dataset(dataset)

    llm = agents_general.llm
    prompt = agents_general.prompt 
    files = agents_general.files


def start_code_analysis(logs_dir=None, skip_existing=True):
    print('Starting code analysis...')
    if not files:
        print("[!] No files found to analyze.")
        return

    logs_folder_path = logs_dir or os.environ.get("LOGS_LOCATION", "logs/dataset/")
    logs_folder = Path(logs_folder_path)
    logs_folder.mkdir(parents=True, exist_ok=True)

    total_files = len(files)
    for idx, file in enumerate(files, start=1):
        log_path = logs_folder / f"log_{file.stem}.json"
        if skip_existing and log_path.exists():
            print(f"[{idx}/{total_files}] Skipping {file.name} (log already exists).")
            continue

        code = file.read_text(encoding='utf-8')
        final_prompt = prompt.replace("{{CODE}}", code)
        
        messages = [
            {"role": "user", "content": final_prompt}
        ]
        
        print(f"[{idx}/{total_files}] Generating response for {file.name}...")

        init = time.time()

        response = llm.create_chat_completion(
            messages=messages,
            max_tokens=4096,  # Limite de tamanho da resposta
            temperature=0.1  # Criatividade (0 = objetivo, 1 = muito criativo)
        )

        total_time = time.time() - init

        result = response["choices"][0]["message"]["content"]

        json_res = extract_json(result)
        if json_res is not None:
            if isinstance(json_res, dict):
                json_res["execution_time_in_seconds"] = round(total_time, 2)
            output_content = json.dumps(json_res, indent=4, ensure_ascii=False)
        else:
            print(f"[!] Warning: Model response for {file.name} was not a valid JSON.")
            output_content = json.dumps({
                "error": "Failed to parse JSON response from model",
                "raw_response": result,
                "execution_time_in_seconds": round(total_time, 2)
            }, indent=4, ensure_ascii=False)

        log_path.write_text(output_content, encoding='utf-8')

        print(f"[✓] [{idx}/{total_files}] File {file.name} done in {total_time:.2f}s.\n")

