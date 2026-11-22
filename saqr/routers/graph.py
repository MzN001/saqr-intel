"""GET /api/syndicate-graph  (Module 4)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..intel import graph_engine
from ..security import require_police

router = APIRouter(prefix="/api", tags=["Syndicate graph"], dependencies=[Depends(require_police)])


@router.get("/syndicate-graph")
async def syndicate_graph(syndicate_id: str | None = None, include_reports: bool = True):
    """Force-directed graph payload (`nodes` + `links`/`edges`) with named syndicate clusters."""
    return await graph_engine.build_graph(syndicate_id, include_reports)


@router.get("/syndicates")
async def syndicates():
    _, syns, *_ = await graph_engine.compute_clusters()
    return {"syndicates": syns}


@router.get("/syndicates/{syndicate_id}")
async def syndicate(syndicate_id: str):
    _, syns, *_ = await graph_engine.compute_clusters()
    for s in syns:
        if s["id"] == syndicate_id:
            return s
    raise HTTPException(404, "Syndicate not found")
