"""GET /api/campaigns - the phishing-campaign feed (public, cacheable).

The browser extension and the email scanner use it to recognise mails that belong to a scam wave
that is spreading right now (wording + known scam domains). Clients send If-None-Match with the
last ETag and get "304 Not Modified" (no body) while nothing changed; the feed refreshes every
6 hours (campaigns.CampaignFeed).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from ..intel.campaigns import TTL_HOURS, campaign_feed, etag_matches
from ..security import rate_limit

router = APIRouter(prefix="/api", tags=["Phishing campaigns"])

# Browsers / CDNs may keep it for an hour, then must revalidate (cheap: a 304 without a body).
CACHE_CONTROL = "public, max-age=3600, must-revalidate"


@router.get("/campaigns", dependencies=[Depends(rate_limit)],
            summary="Phishing campaigns spreading now (brands, wording EN/AR, known scam domains)")
async def get_campaigns(request: Request) -> Response:
    etag = campaign_feed.etag
    headers = {"ETag": etag, "Cache-Control": CACHE_CONTROL, "Access-Control-Expose-Headers": "ETag",
               "X-Feed-TTL-Hours": str(TTL_HOURS)}
    if etag_matches(request.headers.get("if-none-match"), etag):
        return Response(status_code=304, headers=headers)
    return JSONResponse(campaign_feed.snapshot(), headers=headers)
