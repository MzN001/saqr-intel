"""GET /api/public/awareness — the citizen copy of the awareness alert.

Same response shape as the police-only `GET /api/awareness-alert` (same generator), but open to
everyone, rate limited, cached ~5 minutes per `hours`, and it never broadcasts `awareness.drafted`.
"""
from __future__ import annotations

import copy
import time
from typing import Any

from fastapi import APIRouter, Depends, Query

from ..intel import awareness
from ..police_state import police_state
from ..security import rate_limit

router = APIRouter(prefix="/api/public", tags=["Public (citizen)"])

CACHE_TTL_S = 300
_cache: dict[int, tuple[float, dict[str, Any]]] = {}


@router.get("/awareness", dependencies=[Depends(rate_limit)])
async def public_awareness(hours: int = Query(72, ge=1, le=720)):
    """The trending scam wave + bilingual public warning, for the citizen app."""
    now = time.monotonic()
    hit = _cache.get(hours)
    if hit and now - hit[0] < CACHE_TTL_S:
        alert = copy.deepcopy(hit[1])
    else:
        alert = await awareness.generate_alert(hours, None, True)
        _cache[hours] = (now, copy.deepcopy(alert))
    # Not cached: an official warning the police just sent shows at once.
    alert["official_police_warning"] = police_state.warnings[0] if police_state.warnings else None
    return alert
