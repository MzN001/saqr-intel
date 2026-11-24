"""Gemini calibration: few-shot prompt, optional output fields, second-opinion pass, circuit breaker.

The provider call (ai_inspector._gemini) is always stubbed: no test talks to a real LLM.
Run: pytest -q tests/test_llm_second_opinion.py
"""
import asyncio
import dataclasses
import json
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402

from saqr.intel import ai_inspector, user_llm  # noqa: E402
from saqr.intel.ai_inspector import LLMVerdict, combine_opinions, run_rules, wants_second_opinion  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402

PRIMARY = "gemini-3.8-flash"
SECOND = "gemini-4-argon"


def answer(score, verdict=None, conf=0.9, **extra):
    return {"risk_score": score, "verdict": verdict or ai_inspector.verdict_for(score),
            "citizen_explanation_en": "x", "citizen_explanation_ar": "س", "key_red_flags": ["f"],
            "confidence": conf, **extra}


@pytest.fixture
def llm(monkeypatch):
    """Gemini 'configured' for ai_inspector only, with a scripted fake provider.
    Script: dict model -> list of answers (dict, or an Exception instance to raise)."""
    cfg = dataclasses.replace(ai_inspector.settings, llm_provider="gemini", gemini_api_key="test-not-a-key",
                              offline_mode=False, llm_timeout_s=20.0, llm_second_opinion=True,
                              gemini_models=[PRIMARY, "gemini-3.6-flash"], gemini_second_opinion_models=[SECOND])
    monkeypatch.setattr(ai_inspector, "settings", cfg)
    monkeypatch.setattr(ai_inspector, "_skip_until", {})
    monkeypatch.setattr(ai_inspector, "_retired", set())
    status = {"last_ok": None, "last_model": None, "last_error": None,
              "second_opinion": {"runs": 0, "last_ok": None, "last_model": None, "last_error": None}}
    monkeypatch.setattr(ai_inspector, "llm_status", status)
    calls: list[tuple[str, str]] = []
    script: dict[str, list] = {}

    async def fake(system, user, model):
        calls.append((model, user))
        queue = script.get(model) or []
        item = queue.pop(0) if queue else RuntimeError("503 UNAVAILABLE")
        if isinstance(item, Exception):
            raise item
        return json.dumps(item)

    monkeypatch.setattr(ai_inspector, "_gemini", fake)

    class Ctl:
        pass

    ctl = Ctl()
    ctl.calls, ctl.script, ctl.status = calls, script, status
    ctl.set = lambda **kw: monkeypatch.setattr(ai_inspector, "settings", dataclasses.replace(ai_inspector.settings, **kw))
    return ctl


def scan(host):
    return asyncio.run(ai_inspector.inspect(analyze_lexical(host), {}, None, None))


SUSPECT = "adorable-dodol-caf89a.netlify.app"  # URL-model-only SUSPICIOUS, no hard evidence


# --- trigger conditions -----------------------------------------------------------
@pytest.mark.parametrize("score,conf,want", [(40, 0.95, True), (55, 0.95, True), (69, 0.95, True),
                                             (20, 0.79, True), (90, 0.5, True),
                                             (20, 0.95, False), (90, 0.95, False), (39, 0.8, False), (70, 0.8, False)])
def test_trigger(score, conf, want):
    assert wants_second_opinion(LLMVerdict(**answer(score, conf=conf))) is want


@pytest.mark.parametrize("first", [answer(20, conf=0.95), answer(90, conf=0.95)])
def test_sure_first_answer_makes_one_call(llm, first):
    llm.script[PRIMARY] = [first]
    fv = scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY]
    assert fv.llm_extra["second_opinion"] is False and fv.llm_extra["models"] == [f"gemini:{PRIMARY}"]


def test_unsure_answer_gets_exactly_one_extra_call(llm):
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script[SECOND] = [answer(60, conf=0.9), answer(60, conf=0.9)]
    fv = scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY, SECOND]
    first_user, second_user = llm.calls[0][1], llm.calls[1][1]
    assert second_user.startswith(ai_inspector.SECOND_OPINION_NOTE) and second_user.endswith(first_user)
    assert "55" not in ai_inspector.SECOND_OPINION_NOTE  # the first verdict is not leaked
    assert fv.llm_extra == {"second_opinion": True, "models": [f"gemini:{PRIMARY}", f"gemini:{SECOND}"]}
    assert llm.status["second_opinion"]["runs"] == 1 and llm.status["second_opinion"]["last_model"] == f"gemini:{SECOND}"


def test_low_confidence_triggers_second_opinion(llm):
    llm.script[PRIMARY] = [answer(10, conf=0.5)]
    llm.script[SECOND] = [answer(12, conf=0.9)]
    fv = scan(SUSPECT)
    assert len(llm.calls) == 2 and fv.llm_extra["second_opinion"] is True


def test_failed_second_call_keeps_first_answer_and_no_retry(llm):
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script[SECOND] = [RuntimeError("503 UNAVAILABLE")]
    fv = scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY, SECOND]  # no third call to another model
    assert fv.llm_extra == {"second_opinion": False, "models": [f"gemini:{PRIMARY}"]}
    assert fv.confidence == 0.9 and fv.engine == f"gemini:{PRIMARY}"
    assert llm.status["second_opinion"]["last_error"] and llm.status["last_error"] is None


def test_invalid_second_answer_keeps_first(llm):
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script[SECOND] = [{"risk_score": "abc", "verdict": "MAYBE"}]
    fv = scan(SUSPECT)
    assert fv.llm_extra["second_opinion"] is False


def test_setting_off_disables_second_pass(llm):
    llm.set(llm_second_opinion=False)
    llm.script[PRIMARY] = [answer(55, conf=0.5)]
    scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY]


def test_offline_mode_and_use_llm_false_make_no_calls(llm):
    asyncio.run(ai_inspector.inspect(analyze_lexical(SUSPECT), {}, None, None, use_llm=False))
    llm.set(offline_mode=True)
    scan(SUSPECT)
    assert llm.calls == []


@pytest.mark.parametrize("host", ["tamm.abudhabi", "www.emiratespost.ae"])
def test_official_domain_never_calls_the_llm(llm, host):
    llm.script[PRIMARY] = [answer(55, conf=0.3)]
    fv = scan(host)
    assert llm.calls == [] and fv.verdict == "SAFE" and fv.engine == "rules"


def test_second_budget_respects_timeout(llm):
    llm.set(llm_timeout_s=1.0)  # less than the 2 s minimum: not even the first pass runs
    scan(SUSPECT)
    assert llm.calls == []


def test_empty_second_model_setting_uses_next_healthy_chain_model(llm):
    llm.set(gemini_second_opinion_models=[])
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script["gemini-3.6-flash"] = [answer(50, conf=0.9)]
    fv = scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY, "gemini-3.6-flash"] and fv.llm_extra["second_opinion"]


# --- circuit breaker ----------------------------------------------------------------
def test_breaker_benches_a_404_second_opinion_model(llm):
    llm.script[PRIMARY] = [answer(55, conf=0.9), answer(55, conf=0.9)]
    llm.script[SECOND] = [RuntimeError("404 NOT_FOUND models/gemini-4-argon is not found")]
    llm.script["gemini-3.6-flash"] = [answer(58, conf=0.9)]
    scan(SUSPECT)
    assert f"gemini:{SECOND}" in ai_inspector._retired
    fv = scan(SUSPECT)  # next scan: argon is resting, the next healthy chain model answers instead
    assert [m for m, _ in llm.calls] == [PRIMARY, SECOND, PRIMARY, "gemini-3.6-flash"]
    assert fv.llm_extra["models"] == [f"gemini:{PRIMARY}", "gemini:gemini-3.6-flash"]


def test_breaker_rests_a_model_not_on_this_tier_for_a_day(llm):
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script[SECOND] = [RuntimeError("429 RESOURCE_EXHAUSTED quota exceeded, limit: 0, model: gemini-4-argon")]
    scan(SUSPECT)
    import time
    assert ai_inspector._skip_until[f"gemini:{SECOND}"] - time.monotonic() > 3600


def test_no_healthy_second_model_means_no_extra_call(llm):
    llm.set(gemini_models=[PRIMARY])
    import time
    ai_inspector._skip_until[f"gemini:{SECOND}"] = time.monotonic() + 999
    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    fv = scan(SUSPECT)
    assert [m for m, _ in llm.calls] == [PRIMARY] and fv.llm_extra["second_opinion"] is False


# --- combining two answers ----------------------------------------------------------
def V(score, conf, verdict=None):
    return LLMVerdict(**answer(score, verdict, conf))


def test_same_band_is_averaged():
    c = combine_opinions(V(50, 0.6), V(60, 0.8))
    assert c.risk_score == 55 and c.verdict == "SUSPICIOUS" and c.confidence == pytest.approx(0.7)


def test_disagreement_prefers_higher_confidence():
    c = combine_opinions(V(55, 0.6), V(90, 0.9))
    assert c.risk_score == 90 and c.verdict == "HIGH-RISK SCAM" and c.confidence == 0.9


def test_disagreement_tie_prefers_riskier():
    assert combine_opinions(V(10, 0.7), V(50, 0.7)).risk_score == 50


def test_less_risky_winner_cannot_trigger_confident_safe_discount():
    c = combine_opinions(V(60, 0.6), V(5, 0.95))
    assert c.verdict == "SAFE" and c.confidence < 0.8


def test_rules_floor_and_hard_evidence_survive_two_safe_answers(llm):
    host = "secure.paypa1.com"  # homoglyph spoof: hard evidence
    rr = run_rules(analyze_lexical(host), {}, None, None)
    llm.script[PRIMARY] = [answer(0, "SAFE", conf=0.5)]
    llm.script[SECOND] = [answer(0, "SAFE", conf=1.0)]
    fv = scan(host)
    assert len(llm.calls) == 2 and fv.risk_score == rr.score and fv.verdict == rr.verdict


def test_disagreement_end_to_end_uses_blend(llm):
    llm.script[PRIMARY] = [answer(50, conf=0.6)]
    llm.script[SECOND] = [answer(92, conf=0.9)]
    rr = run_rules(analyze_lexical(SUSPECT), {}, None, None)
    fv = scan(SUSPECT)
    assert fv.risk_score == ai_inspector.blend(rr, V(92, 0.9)) and fv.risk_score >= rr.score


# --- optional output fields -----------------------------------------------------------
def test_optional_fields_absent_still_validate():
    lv = LLMVerdict.model_validate({"risk_score": 10, "verdict": "SAFE"})
    assert lv.red_flags_ar == [] and lv.citizen_advice_en == "" and lv.citizen_advice_ar == ""


def test_optional_fields_present_and_odd_shapes_validate():
    lv = LLMVerdict.model_validate(answer(80, red_flags_ar=["نطاق جديد", 3, {"x": 1}],
                                          citizen_advice_en="Do not pay.", citizen_advice_ar="لا تدفع."))
    assert lv.red_flags_ar == ["نطاق جديد", "3"] and lv.citizen_advice_en == "Do not pay."
    lv = LLMVerdict.model_validate(answer(80, red_flags_ar="not a list", citizen_advice_en=None))
    assert lv.red_flags_ar == [] and lv.citizen_advice_en == ""


def test_optional_fields_reach_llm_extra(llm):
    llm.script[PRIMARY] = [answer(92, conf=0.95, red_flags_ar=["رابط مزيف"],
                                  citizen_advice_en="Do not pay.", citizen_advice_ar="لا تدفع.")]
    fv = scan(SUSPECT)
    assert fv.llm_extra["red_flags_ar"] == ["رابط مزيف"]
    assert fv.llm_extra["citizen_advice_en"] == "Do not pay." and fv.llm_extra["citizen_advice_ar"] == "لا تدفع."


def test_api_analyzer_block_carries_metadata(llm):
    from fastapi.testclient import TestClient
    from main import app

    llm.script[PRIMARY] = [answer(55, conf=0.9)]
    llm.script[SECOND] = [answer(60, conf=0.95, red_flags_ar=["علامة"])]  # the more confident answer leads
    with TestClient(app) as c:
        body = c.post("/api/analyze-url", json={"url": f"https://{SUSPECT}/", "run_sandbox": False}).json()
        health = c.get("/health").json()
    an = body["analyzer"]
    assert an["second_opinion"] is True and an["models"] == [f"gemini:{PRIMARY}", f"gemini:{SECOND}"]
    assert an["red_flags_ar"] == ["علامة"] and "confidence" in an and "engine" in an
    assert body["verdict"] in {"SAFE", "SUSPICIOUS", "HIGH-RISK SCAM"} and "llm_red_flags" in body
    assert "second_opinion" in health["llm"] and "last_ok" in health["llm"]
    assert "key" not in json.dumps(an).lower()


# --- prompt ----------------------------------------------------------------------------
def test_prompt_has_six_calibration_examples_and_stays_compact():
    p = ai_inspector.SYSTEM_PROMPT
    for marker in ("tamm-fines-pay.example", "epost-redelivery.example", "freemail.example",
                   "tamm.abudhabi", "Never share this code", "emiratespost.ae"):
        assert marker in p, marker
    for n in range(1, 7):
        assert f"\n{n}. " in p.split("CALIBRATION EXAMPLES")[1]
    assert "the <evidence> block decides" in p and "below 20" in p
    assert "red_flags_ar" in p and "citizen_advice_en" in p
    assert len(p) < 4500
    e = user_llm.EMAIL_SYSTEM_PROMPT
    assert "Calibration" in e and "freemail.example" in e and len(e) < 4200


def test_calibration_scam_domains_are_reserved_names():
    import re
    p = ai_inspector.SYSTEM_PROMPT.split("CALIBRATION EXAMPLES")[1].split("Return ONLY")[0]
    hosts = set(re.findall(r"[a-z0-9.-]+\.[a-z]{2,}", re.sub(r"\S+@", "", p)))  # drop e-mail local parts
    assert hosts <= {"tamm-fines-pay.example", "epost-redelivery.example", "freemail.example",
                     "tamm.abudhabi", "emiratespost.ae"}, hosts
