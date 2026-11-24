"""Model transparency API: how SAQR's phishing URL model was trained and how accurate it measured.

GET /api/model/metrics   the stored evaluation (saqr/intel/data/model_metrics.json, written by
                         tools/train_url_model.py and tools/evaluate.py --suite): model, datasets,
                         source-disjoint holdout, false-positive suite, end-to-end system numbers.
"""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from ..intel import url_model

router = APIRouter(prefix="/api/model", tags=["Model"])

PUBLIC_KEYS = ("model", "datasets", "holdout", "fresh_phishing", "fp_suite", "system", "thresholds")


@router.get("/metrics")
async def metrics():
    try:
        stored = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise HTTPException(404, "no model metrics stored") from exc
    out = {k: stored.get(k) for k in PUBLIC_KEYS}
    out["installed"] = url_model.available()
    return out
