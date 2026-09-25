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
from llama_cpp import LlamaGrammar

load_dotenv()

llm = None
prompt = None
files = None

TARGET_CWES = ["CWE-401", "CWE-415", "CWE-416", "CWE-457", "CWE-476"]

# Mirrors the "Output" section in prompts/code_analyser_v2.md. Passed to
# create_chat_completion as a grammar so generation is constrained to valid
# JSON matching this shape. Field order matters: the grammar makes the model
# write "analysis" and the evidence first and only then the "vulnerable"
# verdict, so the verdict can't be committed to before any reasoning happens.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "analysis": {"type": "string"},
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cwe": {"enum": TARGET_CWES},
                    "pointer": {"type": "string"},
                    "source_line": {"type": "integer"},
                    "source_code": {"type": "string"},
                    "violation_line": {"type": "integer"},
                    "violation_code": {"type": "string"},
                    "path": {"type": "array", "items": {"type": "string"}},
                    "refutation_attempt": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": [
                    "cwe", "pointer", "source_line", "source_code",
                    "violation_line", "violation_code", "path",
                    "refutation_attempt", "description",
                ],
            },
        },
        "vulnerable": {"type": "boolean"},
    },
    "required": ["analysis", "findings", "vulnerable"],
}

# Juliet test cases name their functions/types/globals after the CWE and the
# expected verdict (e.g. "CWE401_Memory_Leak__char_calloc_01_bad", "goodG2B",
# "badSink"), which hands the answer to the model. Every such identifier is
# renamed to a neutral one, consistently within a file so distinct symbols
# stay distinct.
_LEAKY_IDENT_RE = re.compile(
    r"\b_*(?:CWE\d+_\w+|(?:good|bad)(?:[A-Z0-9]\w*)?|helper(?:Good|Bad)\w*)\b"
)
# String literals that also give the verdict away: "GoodSink"/"BadSink" and
# "Good", which Juliet uses almost only in the good variants.
_LEAKY_STRING_RE = re.compile(r'"(?:Good|Bad)(Sink|Source)"')
_GOOD_LITERAL_RE = re.compile(r'"Good"')


def sanitize_code(code: str) -> str:
    mapping = {}

    def neutral_name(match):
        ident = match.group(0)
        if ident not in mapping:
            if ident.endswith("Type"):
                kind = "type"
            elif ident.endswith(("Global", "Data")):
                kind = "var"
            else:
                kind = "func"
            mapping[ident] = f"{kind}_{len(mapping) + 1}"
        return mapping[ident]

    code = _LEAKY_IDENT_RE.sub(neutral_name, code)
    code = _LEAKY_STRING_RE.sub(r'"\1"', code)
    return _GOOD_LITERAL_RE.sub('"Text"', code)


def number_lines(code: str) -> str:
    return "\n".join(f"L{i}| {line}" for i, line in enumerate(code.splitlines(), start=1))


def _squash(text) -> str:
    return re.sub(r"\s+", "", text) if isinstance(text, str) else ""


def validate_finding(finding, lines):
    """
    Returns None if the finding's evidence really exists in the analyzed code,
    otherwise the reason it was rejected. Checks that both cited lines exist,
    that the quoted code matches them and that the pointer appears in the
    violation line - the cheapest way to drop hallucinated findings.
    """
    if not isinstance(finding, dict):
        return "not an object"
    if finding.get("cwe") not in TARGET_CWES:
        return "cwe out of scope"
    for kind in ("source", "violation"):
        line_no = finding.get(f"{kind}_line")
        if not isinstance(line_no, int) or not 1 <= line_no <= len(lines):
            return f"{kind}_line out of range"
        quoted = _squash(finding.get(f"{kind}_code"))
        if not quoted or quoted not in _squash(lines[line_no - 1]):
            return f"{kind}_code does not match line {line_no}"
    pointer = finding.get("pointer")
    if not isinstance(pointer, str) or not pointer.strip():
        return "missing pointer"
    # Accept "data", "*data" or "s->field" as long as the base identifier is on the line.
    base = re.findall(r"[A-Za-z_]\w*", pointer)
    if not base or not re.search(rf"\b{re.escape(base[0])}\b", lines[finding["violation_line"] - 1]):
        return "pointer not in violation line"
    return None


def apply_validation(json_res, lines):
    """
    Keeps only findings with verifiable evidence and derives the verdict from
    them, instead of trusting the model's own "vulnerable" field. The model's
    raw verdict and the rejected findings are kept in the log for analysis.
    """
    findings = json_res.get("findings")
    findings = findings if isinstance(findings, list) else []
    kept, rejected = [], []
    for finding in findings:
        reason = validate_finding(finding, lines)
        if reason is None:
            kept.append(finding)
        else:
            rejected.append({"reason": reason, "finding": finding})
    json_res["model_vulnerable"] = json_res.get("vulnerable")
    json_res["findings"] = kept
    json_res["rejected_findings"] = rejected
    json_res["vulnerable"] = bool(kept)
    return json_res


_grammar = None


def get_grammar():
    global _grammar
    if _grammar is None:
        _grammar = LlamaGrammar.from_json_schema(json.dumps(RESPONSE_SCHEMA), verbose=False)
    return _grammar


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


def init_agent(model="QWEN_CODE", prompt_name="code_analyser_v2", dataset="CWES_BAD"):
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

        code = sanitize_code(file.read_text(encoding='utf-8'))
        code_lines = code.splitlines()
        final_prompt = prompt.replace("{{CODE}}", number_lines(code))
        
        messages = [
            {"role": "user", "content": final_prompt}
        ]
        
        print(f"[{idx}/{total_files}] Generating response for {file.name}...")

        init = time.time()

        response = llm.create_chat_completion(
            messages=messages,
            max_tokens=4096,  # Limite de tamanho da resposta
            temperature=0.0,  # 0 = determinístico, reprodutível entre execuções
            grammar=get_grammar(),
        )

        total_time = time.time() - init

        result = response["choices"][0]["message"]["content"]

        json_res = extract_json(result)
        if json_res is not None:
            if isinstance(json_res, dict):
                json_res = apply_validation(json_res, code_lines)
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

