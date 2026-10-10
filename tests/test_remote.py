import io
import json
import urllib.error

import pytest

from src.pipeline import remote


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


def _ok(text):
    body = {"choices": [{"message": {"content": text}}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}}
    return _Response(json.dumps(body).encode())


def _settings(**extra):
    return {"provider": "groq", "max_tokens": 16, "min_interval": 0, **extra}


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.setenv("GROQ_MODEL", "m")
    monkeypatch.setenv("GROQ_BASE_URL", "http://x/v1")
    monkeypatch.setattr(remote, "USAGE_LOG", tmp_path / "usage.jsonl")
    monkeypatch.setattr(remote.time, "sleep", lambda s: None)


def test_retries_on_429_then_logs(monkeypatch):
    calls = []

    def fake(request, timeout=None):
        calls.append(request)
        if len(calls) == 1:
            raise urllib.error.HTTPError("u", 429, "rate", {"Retry-After": "3"}, io.BytesIO(b""))
        return _ok("hi")

    monkeypatch.setattr(remote.urllib.request, "urlopen", fake)
    text, _ = remote.RemoteLLM().complete("generator", _settings(), "p")
    assert text == "hi" and len(calls) == 2
    line = json.loads(remote.USAGE_LOG.read_text().splitlines()[0])
    assert line["retries"] == 1 and line["waited"] == 3 and line["status"] == "ok" and "k" not in line.values()


def test_long_retry_after_means_quota(monkeypatch):
    def fake(request, timeout=None):
        raise urllib.error.HTTPError("u", 429, "rate", {"Retry-After": "3600"}, io.BytesIO(b""))

    monkeypatch.setattr(remote.urllib.request, "urlopen", fake)
    with pytest.raises(remote.QuotaExhausted):
        remote.RemoteLLM().complete("generator", _settings(), "p")


def test_retries_exhausted_on_429_is_not_an_empty_answer(monkeypatch):
    def fake(request, timeout=None):
        raise urllib.error.HTTPError("u", 429, "rate", {"Retry-After": "1"}, io.BytesIO(b"{}"))

    monkeypatch.setattr(remote.urllib.request, "urlopen", fake)
    with pytest.raises(remote.QuotaExhausted):
        remote.RemoteLLM().complete("generator", _settings(), "p")
