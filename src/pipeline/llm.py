"""
Local GGUF models for the pipeline roles, configured by a combo
(configs/combos/). Keeps a single model in memory: consecutive roles that use
the same model (generator -> corrector in every combo) share it, and a role
with a different model unloads the previous one first.
"""

import gc
import time

# A call that has not finished after this many seconds is cut and its partial text returned: in one run a
# 4B model took 2729 s for an answer that normally takes 25 s (cause unknown) and blocked the whole loop.
DEFAULT_MAX_SECONDS = 600


class LocalLLM:
    def __init__(self, combo):
        self.combo = combo
        self._llm = None
        self._loaded = None

    def _load(self, settings):
        key = (str(settings["path"]), settings["n_ctx"], settings["n_gpu_layers"])
        if key == self._loaded:
            return
        self.unload()
        if not settings["path"].exists():
            raise FileNotFoundError(
                f"Model not found: {settings['path']} "
                f"(download it with: python -m src.config --combo {self.combo['name']} --download)"
            )
        # agents_general registers the CUDA DLL path on Windows before importing llama_cpp.
        from src.agents.agents_general import Llama

        print(f"Loading {settings['model']['name']} ({settings['model']['quant']})...")
        self._llm = Llama(
            model_path=str(settings["path"]),
            n_ctx=settings["n_ctx"],
            n_gpu_layers=settings["n_gpu_layers"],
            verbose=False,
        )
        self._loaded = key

    def unload(self):
        if self._llm is not None:
            del self._llm
            self._llm = None
            self._loaded = None
            gc.collect()

    def complete(self, role, prompt, temperature=None, max_seconds=None):
        """
        Returns (response_text, seconds) for a single-turn prompt with the role's settings;
        `temperature` overrides the combo's value for this call. The answer is streamed and
        cut after `max_seconds` (default: the role's `max_seconds` setting, else
        DEFAULT_MAX_SECONDS); the partial text is returned, which the rule parser then
        rejects like any other malformed answer.
        """
        settings = self.combo["roles"][role]
        self._load(settings)
        limit = max_seconds or settings.get("max_seconds", DEFAULT_MAX_SECONDS)
        start = time.time()
        stream = self._llm.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=settings["max_tokens"],
            temperature=settings.get("temperature", 0.0) if temperature is None else temperature,
            stream=True,
        )
        parts = []
        for chunk in stream:
            parts.append(chunk["choices"][0]["delta"].get("content") or "")
            if time.time() - start > limit:
                print(f"  {role} cut after {limit}s")
                break
        return "".join(parts), time.time() - start
