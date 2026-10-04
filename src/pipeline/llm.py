"""
Local GGUF models for the pipeline roles, configured by a combo
(configs/combos/). Keeps a single model in memory: consecutive roles that use
the same model (generator -> corrector in every combo) share it, and a role
with a different model unloads the previous one first.
"""

import gc
import time


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

    def complete(self, role, prompt, temperature=None):
        """
        Returns (response_text, seconds) for a single-turn prompt with the role's settings;
        `temperature` overrides the combo's value for this call.
        """
        settings = self.combo["roles"][role]
        self._load(settings)
        start = time.time()
        response = self._llm.create_chat_completion(
            messages=[{"role": "user", "content": prompt}],
            max_tokens=settings["max_tokens"],
            temperature=settings.get("temperature", 0.0) if temperature is None else temperature,
        )
        return response["choices"][0]["message"]["content"], time.time() - start
