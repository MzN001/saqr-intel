"""Claude (Anthropic) as the AI judge: chain order, Gemini fallback, second opinion, request shape.

Run: pytest -q tests/test_llm_anthropic.py   (offline: the SDK client is replaced by a fake)
"""
import asyncio
import dataclasses
import json
import sys
import types

import pytest

from saqr.config import Settings
from saqr.intel import ai_inspector

CLAUDE = "claude-opus-5-5"
GEMINI = "gemini-3.8-flash"


def test_auto_prefers_claude_then_gemini_then_openai():
    base = dataclasses.replace(Settings(), llm_provider="auto", anthropic_api_key="", gemini_api_key="",
                               openai_api_key="")
    assert base.active_llm == "rules"
    assert dataclasses.replace(base, openai_api_key="k").active_llm == "openai"
    assert dataclasses.replace(base, openai_api_key="k", gemini_api_key="k").active_llm == "gemini"
    assert dataclasses.replace(base, gemini_api_key="k", anthropic_api_key="k").active_llm == "anthropic"
    # an explicit provider without its key falls back to the rules engine, as for Gemini / OpenAI
    assert dataclasses.replace(base, llm_provider="claude", gemini_api_key="k").active_llm == "rules"
    assert dataclasses.replace(base, llm_provider="claude", anthropic_api_key="k").active_llm == "anthropic"
    assert dataclasses.replace(base, llm_provider="gemini", gemini_api_key="k",
                               anthropic_api_key="k").active_llm == "gemini"


@pytest.fixture
def chain(monkeypatch):
    cfg = dataclasses.replace(ai_inspector.settings, llm_provider="auto", anthropic_api_key="test-not-a-key",
                              gemini_api_key="test-not-a-key", openai_api_key="", offline_mode=False,
                              llm_timeout_s=20.0, llm_second_opinion=True, anthropic_models=[CLAUDE],
                              gemini_models=[GEMINI], gemini_second_opinion_models=[])
    monkeypatch.setattr(ai_inspector, "settings", cfg)
    monkeypatch.setattr(ai_inspector, "_skip_until", {})
    monkeypatch.setattr(ai_inspector, "_retired", set())
    monkeypatch.setattr(ai_inspector, "llm_status", {
        "last_ok": None, "last_model": None, "last_error": None,
        "second_opinion": {"runs": 0, "last_ok": None, "last_model": None, "last_error": None}})
    calls: list[str] = []
    answers: dict[str, object] = {}

    def provider(prefix):
        async def fake(system, user, model):
            calls.append(f"{prefix}:{model}")
            item = answers.get(prefix, RuntimeError("503 UNAVAILABLE"))
            if isinstance(item, Exception):
                raise item
            return json.dumps(item)
        return fake

    monkeypatch.setattr(ai_inspector, "_anthropic", provider("anthropic"))
    monkeypatch.setattr(ai_inspector, "_gemini", provider("gemini"))
    return types.SimpleNamespace(calls=calls, answers=answers)


def test_claude_answers_first(chain):
    chain.answers["anthropic"] = {"risk_score": 90}
    data, engine = asyncio.run(ai_inspector.llm_json("sys", "user"))
    assert data == {"risk_score": 90} and engine == f"anthropic:{CLAUDE}"
    assert chain.calls == [f"anthropic:{CLAUDE}"]
    assert ai_inspector.llm_status["last_model"] == f"anthropic:{CLAUDE}"


def test_gemini_is_the_fallback_when_claude_fails(chain):
    chain.answers["anthropic"] = RuntimeError("Error code: 529 - overloaded_error")
    chain.answers["gemini"] = {"risk_score": 10}
    data, engine = asyncio.run(ai_inspector.llm_json("sys", "user"))
    assert data == {"risk_score": 10} and engine == f"gemini:{GEMINI}"
    assert chain.calls == [f"anthropic:{CLAUDE}", f"gemini:{GEMINI}"]


def test_wrong_key_rests_claude_for_an_hour(chain):
    chain.answers["anthropic"] = RuntimeError("Error code: 401 - authentication_error: invalid x-api-key")
    chain.answers["gemini"] = {"risk_score": 10}
    asyncio.run(ai_inspector.llm_json("sys", "user"))
    asyncio.run(ai_inspector.llm_json("sys", "user"))
    # second scan goes straight to Gemini; the resting Claude model is only a last resort
    assert chain.calls == [f"anthropic:{CLAUDE}", f"gemini:{GEMINI}", f"gemini:{GEMINI}"]


def test_second_opinion_comes_from_gemini_when_claude_is_first(chain):
    name, _fn, model = ai_inspector.second_opinion_candidate(f"anthropic:{CLAUDE}")
    assert name == f"gemini:{GEMINI}" and model == GEMINI


def test_no_second_opinion_without_a_gemini_key(chain, monkeypatch):
    monkeypatch.setattr(ai_inspector, "settings", dataclasses.replace(ai_inspector.settings, gemini_api_key=""))
    assert ai_inspector.second_opinion_candidate(f"anthropic:{CLAUDE}") is None


# ---- the request itself (fake SDK module: no network, no key) ----
class _Block:
    def __init__(self, type_, text=""):
        self.type, self.text = type_, text


def _fake_sdk(monkeypatch, response, seen):
    class _Messages:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return response

    class AsyncAnthropic:
        def __init__(self, **kwargs):
            seen["client"] = kwargs
            self.beta = types.SimpleNamespace(messages=_Messages())

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=AsyncAnthropic))


def test_request_shape_and_text_blocks_only(monkeypatch):
    monkeypatch.setattr(ai_inspector, "settings", dataclasses.replace(
        ai_inspector.settings, anthropic_api_key="test-not-a-key", anthropic_effort="low", llm_timeout_s=20.0))
    seen: dict = {}
    resp = types.SimpleNamespace(stop_reason="end_turn",
                                 content=[_Block("thinking"), _Block("text", '{"risk_score": 80}')])
    _fake_sdk(monkeypatch, resp, seen)
    out = asyncio.run(ai_inspector._anthropic("SYSTEM", "USER", CLAUDE))  # noqa: SLF001
    assert json.loads(out) == {"risk_score": 80}
    assert seen["model"] == CLAUDE and seen["system"] == "SYSTEM"
    assert seen["messages"] == [{"role": "user", "content": "USER"}]  # no assistant prefill
    assert seen["output_config"] == {"effort": "low"}
    # current Claude models reject sampling parameters and explicit thinking budgets
    assert not {"temperature", "top_p", "top_k", "thinking"} & set(seen)
    assert seen["client"]["max_retries"] == 0 and seen["client"]["api_key"] == "test-not-a-key"


def test_unknown_effort_falls_back_to_low(monkeypatch):
    monkeypatch.setattr(ai_inspector, "settings", dataclasses.replace(
        ai_inspector.settings, anthropic_api_key="test-not-a-key", anthropic_effort="turbo"))
    seen: dict = {}
    _fake_sdk(monkeypatch, types.SimpleNamespace(stop_reason="end_turn", content=[_Block("text", "{}")]), seen)
    asyncio.run(ai_inspector._anthropic("s", "u", CLAUDE))  # noqa: SLF001
    assert seen["output_config"] == {"effort": "low"}


def test_refusal_is_a_failure_so_the_chain_moves_on(monkeypatch):
    monkeypatch.setattr(ai_inspector, "settings", dataclasses.replace(
        ai_inspector.settings, anthropic_api_key="test-not-a-key"))
    _fake_sdk(monkeypatch, types.SimpleNamespace(stop_reason="refusal", content=[]), {})
    with pytest.raises(RuntimeError, match="refusal"):
        asyncio.run(ai_inspector._anthropic("s", "u", CLAUDE))  # noqa: SLF001
