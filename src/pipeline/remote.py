"""
Remote chat-completion backend (OpenAI-compatible endpoints: Groq, Gemini, OpenRouter) for the roles of a combo that set
`provider`. Keys, models and base URLs come from .env (never printed or logged). Free tiers are rate limited, so every call
waits for `min_interval` seconds since the last one of its provider, retries on 429/5xx honouring Retry-After, and is counted
in `logs/remote_usage.jsonl` (one line per call: provider, role, tokens, seconds waited, retries) to measure how the limits
shape the run. Standard library only.
"""

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

USAGE_LOG = Path("logs/remote_usage.jsonl")
MAX_RETRIES = 8
MAX_WAIT = 120  # seconds; a longer Retry-After usually means the daily quota is gone

# provider -> (env var(s) with the API key(s), model var, base URL var). More than one key rotates on 429.
PROVIDERS = {
    "groq": (["GROQ_API_KEY"], "GROQ_MODEL", "GROQ_BASE_URL"),
    "gemini": (["api_key_gemini_free", "api_key_gemini_alter"], "GOOGLE_MODEL", "GOOGLE_BASE_URL"),
    "openrouter": (["OPENROUTER_API_KEY"], "OPENROUTER_MODEL", "OPENROUTER_BASE_URL"),
}


class QuotaExhausted(RuntimeError):
    pass


class RemoteLLM:
    def __init__(self):
        self._last_call = {}
        self._key_index = {}

    def _config(self, provider):
        if provider not in PROVIDERS:
            raise KeyError(f"Unknown provider '{provider}' (known: {', '.join(PROVIDERS)})")
        key_vars, model_var, url_var = PROVIDERS[provider]
        keys = [os.environ[v] for v in key_vars if os.environ.get(v)]
        if not keys or not os.environ.get(model_var) or not os.environ.get(url_var):
            raise RuntimeError(f"Provider {provider}: set {key_vars[0]}, {model_var} and {url_var} in .env")
        return keys, os.environ[model_var], os.environ[url_var].rstrip("/")

    def complete(self, role, settings, prompt, temperature=None, max_seconds=None):
        provider = settings["provider"]
        keys, model, base = self._config(provider)
        body = {
            "model": settings.get("remote_model", model),
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": settings["max_tokens"],
            "temperature": settings.get("temperature", 0.0) if temperature is None else temperature,
        }
        if settings.get("reasoning_effort"):
            body["reasoning_effort"] = settings["reasoning_effort"]
        limit = max_seconds or settings.get("max_seconds", 600)
        start = time.time()
        waited = 0.0
        retries = 0
        status = "ok"
        usage = {}
        text = ""
        while True:
            gap = settings.get("min_interval", 0) - (time.time() - self._last_call.get(provider, 0))
            if gap > 0:
                time.sleep(gap)
                waited += gap
            idx = self._key_index.get(provider, 0) % len(keys)
            request = urllib.request.Request(
                f"{base}/chat/completions", data=json.dumps(body).encode(),
                headers={"Authorization": f"Bearer {keys[idx]}", "Content-Type": "application/json",
                         "User-Agent": "semgrep-multiagent/1.0"})
            self._last_call[provider] = time.time()
            try:
                with urllib.request.urlopen(request, timeout=limit) as response:
                    data = json.loads(response.read())
                text = data["choices"][0]["message"].get("content") or ""
                usage = data.get("usage") or {}
                break
            except urllib.error.HTTPError as error:
                retry_after = error.headers.get("Retry-After")
                error.read()
                if error.code not in (429, 500, 502, 503, 504) or retries >= MAX_RETRIES:
                    status = f"http {error.code}"
                    break
                retries += 1
                if error.code == 429 and len(keys) > 1:
                    self._key_index[provider] = idx + 1  # try the other key first
                if retry_after and retry_after.replace(".", "").isdigit():
                    pause = float(retry_after)
                else:
                    pause = min(2 ** retries * 2, MAX_WAIT)
                if pause > MAX_WAIT:
                    status = f"quota (retry-after {pause:.0f}s)"
                    break
                print(f"  {role}: {provider} http {error.code}, waiting {pause:.0f}s (retry {retries})")
                time.sleep(pause)
                waited += pause
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError) as error:
                if retries >= MAX_RETRIES:
                    status = f"error {type(error).__name__}"
                    break
                retries += 1
                pause = min(2 ** retries, MAX_WAIT)
                time.sleep(pause)
                waited += pause
        seconds = time.time() - start
        self._log(provider, role, body["model"], usage, seconds, waited, retries, status)
        if status.startswith("quota"):
            raise QuotaExhausted(f"{provider}: {status}")
        return text, seconds

    @staticmethod
    def _log(provider, role, model, usage, seconds, waited, retries, status):
        USAGE_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "provider": provider, "model": model, "role": role,
                "prompt_tokens": usage.get("prompt_tokens"), "completion_tokens": usage.get("completion_tokens"),
                "seconds": round(seconds, 1), "waited": round(waited, 1), "retries": retries, "status": status}
        with USAGE_LOG.open("a", encoding="utf-8") as out:
            out.write(json.dumps(line) + "\n")
