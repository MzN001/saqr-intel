"""Shared runner for the UAE benchmark suite (tests/test_uae_suite.py and tools/eval_uae.py).

cases.json holds 50 hand-written cases (25 malicious, 25 legitimate) across the five input types SAQR accepts.
Every scam domain in it is invented. The cases were written by the team, so this is a regression set, not a
measure of accuracy on real-world scams.

ONE definition of "detected" (used everywhere):
  * url / email / maps / message: the response verdict is not SAFE (SUSPICIOUS or HIGH-RISK SCAM);
  * phone (/api/check-phone): `level` is a warning level ("caution" or "danger"); "official" and "none" are benign.
A malicious case that is detected is a true positive; a legitimate case that is detected is a false positive.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CASES_PATH = Path(__file__).with_name("cases.json")
MODALITIES = ("url", "email", "maps", "phone", "message")
ENDPOINTS = {
    "url": "/api/analyze-url",
    "email": "/api/analyze-email",
    "maps": "/api/scan-maps",
    "phone": "/api/check-phone",
    "message": "/api/analyze-message",
}
WARNING_PHONE_LEVELS = frozenset({"caution", "danger"})
BENIGN_PHONE_LEVELS = frozenset({"official", "none"})


def load_cases(path: Path = CASES_PATH) -> list[dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))["cases"]


def is_detected(modality: str, response: dict[str, Any]) -> bool:
    """True when SAQR warns the citizen about this input (see the module docstring)."""
    if modality == "phone":
        return response.get("level") in WARNING_PHONE_LEVELS
    return response.get("verdict") != "SAFE"


def request_body(case: dict[str, Any], live: bool = False) -> dict[str, Any]:
    """The case's endpoint body plus the run-mode switches. Offline (default) = rules only: no LLM, no page
    fetch. --live allows the LLM judge and the page sandbox (the endpoints' own defaults)."""
    body = dict(case["input"])
    m = case["modality"]
    if m in ("url", "email", "message"):
        body["use_llm"] = live
    if m == "url":
        body["run_sandbox"] = live
        body["include_screenshot"] = False
    return body


@dataclass
class Result:
    case: dict[str, Any]
    status_code: int
    response: dict[str, Any]
    detected: bool
    error: str | None = None

    @property
    def id(self) -> str:
        return self.case["id"]

    @property
    def malicious(self) -> bool:
        return self.case["label"] == "malicious"

    @property
    def correct(self) -> bool:
        return self.error is None and self.detected == self.malicious

    @property
    def outcome(self) -> str:
        if self.malicious:
            return "TP" if self.detected else "FN"
        return "FP" if self.detected else "TN"

    def summary(self) -> str:
        r = self.response
        if self.error:
            return f"{self.id}: request failed ({self.status_code}) {self.error[:200]}"
        shown = (f"level={r.get('level')} status={r.get('status')}" if self.case["modality"] == "phone"
                 else f"verdict={r.get('verdict')} score={r.get('risk_score')}")
        flags = [f"{f.get('code')}+{f.get('points')}" for f in r.get("red_flags") or [] if f.get("points")]
        if self.case["modality"] == "phone":
            flags = [x.get("code") for x in r.get("reasons") or []]
        return f"{self.id} [{self.case['label']}] {self.outcome}: {shown} flags={flags[:6]}"


def run_case(client: Any, case: dict[str, Any], live: bool = False) -> Result:
    resp = client.post(ENDPOINTS[case["modality"]], json=request_body(case, live))
    try:
        data = resp.json()
    except ValueError:
        data = {}
    if resp.status_code != 200:
        return Result(case, resp.status_code, data if isinstance(data, dict) else {}, False, resp.text)
    return Result(case, resp.status_code, data, is_detected(case["modality"], data))


def run_all(client: Any, cases: list[dict[str, Any]] | None = None, live: bool = False) -> list[Result]:
    return [run_case(client, c, live) for c in (cases if cases is not None else load_cases())]


@dataclass
class Metrics:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def fpr(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p and r else None

    def to_dict(self) -> dict[str, Any]:
        r4 = lambda v: None if v is None else round(v, 4)  # noqa: E731
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn, "precision": r4(self.precision),
                "recall": r4(self.recall), "fpr": r4(self.fpr), "f1": r4(self.f1), "errors": self.errors}


def metrics(results: list[Result]) -> Metrics:
    m = Metrics()
    for r in results:
        if r.error:
            m.errors.append(r.id)
        setattr(m, r.outcome.lower(), getattr(m, r.outcome.lower()) + 1)
    return m


def verified_official_misses(results: list[Result]) -> list[str]:
    """Legitimate cases marked expect.verified_official whose response does not say verified_official=true."""
    out = []
    for r in results:
        if (r.case.get("expect") or {}).get("verified_official") and r.response.get("verified_official") is not True:
            out.append(f"{r.id}: verified_official={r.response.get('verified_official')!r}")
    return out
