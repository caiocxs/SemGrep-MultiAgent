import time

from src.pipeline.llm import DEFAULT_MAX_SECONDS, LocalLLM


class FakeModel:
    """Stands in for llama_cpp.Llama: streams `pieces`, sleeping `delay` seconds before each one."""

    def __init__(self, pieces, delay=0.0):
        self.pieces, self.delay, self.calls = pieces, delay, []

    def create_chat_completion(self, **kwargs):
        self.calls.append(kwargs)

        def stream():
            yield {"choices": [{"delta": {"role": "assistant"}}]}  # llama.cpp opens with a role-only chunk
            for piece in self.pieces:
                time.sleep(self.delay)
                yield {"choices": [{"delta": {"content": piece}}]}
            yield {"choices": [{"delta": {}, "finish_reason": "stop"}]}

        return stream()


def make_llm(model, **role_settings):
    llm = LocalLLM({"name": "T", "roles": {"generator": {"max_tokens": 64, **role_settings}}})
    llm._load = lambda settings: None
    llm._llm = model
    return llm


def test_complete_joins_the_streamed_text_and_passes_the_role_settings():
    model = FakeModel(["Hel", "lo", "!"])
    text, seconds = make_llm(model, temperature=0.2).complete("generator", "hi")

    assert text == "Hello!"
    assert seconds >= 0
    assert model.calls[0]["messages"] == [{"role": "user", "content": "hi"}]
    assert model.calls[0]["max_tokens"] == 64 and model.calls[0]["temperature"] == 0.2
    assert model.calls[0]["stream"] is True


def test_temperature_argument_overrides_the_role_setting():
    model = FakeModel(["x"])
    make_llm(model, temperature=0.2).complete("generator", "hi", temperature=0.7)

    assert model.calls[0]["temperature"] == 0.7


def test_a_slow_answer_is_cut_and_the_partial_text_returned(capsys):
    model = FakeModel(["a"] * 100, delay=0.02)
    text, seconds = make_llm(model).complete("generator", "hi", max_seconds=0.1)

    assert 0 < len(text) < 100  # cut, not complete
    assert seconds < 1.5
    assert "cut after 0.1s" in capsys.readouterr().out


def test_the_limit_comes_from_the_role_setting_then_the_default():
    slow = FakeModel(["a"] * 100, delay=0.02)
    text, _ = make_llm(slow, max_seconds=0.1).complete("generator", "hi")
    assert len(text) < 100

    fast = FakeModel(["a"] * 5)
    text, _ = make_llm(fast).complete("generator", "hi")
    assert text == "aaaaa" and DEFAULT_MAX_SECONDS >= 60
