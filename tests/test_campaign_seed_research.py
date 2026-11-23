"""Researched campaign seed (2026-11-23 update) + tools/build_campaign_seed.py writing outside the repo.

Run: pytest -q tests/test_campaign_seed_research.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402

from saqr.intel import campaigns as cm  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
FEED = cm.CampaignFeed()
BY_ID = {c["id"]: c for c in FEED.seed_campaigns}


def test_new_campaigns_are_in_the_seed_with_sources():
    for cid in ("cmp-3f41c199", "cmp-c72711ee", "cmp-d25e2692", "cmp-14a5ee34", "cmp-b82add26", "cmp-28d49192",
                "cmp-3a416f33", "cmp-6cb2941e"):
        c = BY_ID[cid]
        assert c["references"] and c["title_ar"] and c["summary_ar"] and "email" in c["channels"]
    # whole platforms the sources also named (r2.dev, screenconnect.com) are never indicators
    every = {d for c in FEED.seed_campaigns for k in ("sender_domains", "url_domains") for d in c["indicators"][k]}
    assert not every & {"r2.dev", "screenconnect.com", "sendgrid.net", "googleapis.com", "workers.dev"}


@pytest.mark.parametrize("inp,cid,kind", [
    # Microsoft's listed sender domain of the 12-17 Nov outage wave
    ({"sender_domain": "mail.moments-notice.com", "subject": "Outage - action needed"}, "cmp-ca016168", "ioc"),
    ({"subject": "Outlook is disconnected after the Microsoft 365 outage",
      "body_text": "4 messages held after the outage. Restore messages now."}, "cmp-ca016168", "lure"),
    ({"link_domains": ["9l2v3vupv5.synerghylnksloads.cfd"], "subject": "Scheduled electronic payment"},
     "cmp-56dcb5b5", "ioc"),
    ({"subject": "Due to the ongoing situation involving Binance", "body_text":
      "Your address was returned as UNCLAIMED in the reconciliation index. Pay the wallet-verification fee."},
     "cmp-3f41c199", "lure"),
    ({"subject": "Black Friday $5,000! Secret Link Access",
      "body_text": "You were randomly selected for the Kanye West reward. Enter the promo code."}, "cmp-b82add26", "lure"),
])
def test_new_seed_entries_match(inp, cid, kind):
    hits = {m["id"]: m["match"] for m in FEED.match(inp)}
    assert hits.get(cid) == kind, hits


def test_ordinary_thanksgiving_and_bank_mail_do_not_match_new_campaigns():
    for inp in ({"subject": "Thanksgiving dinner on Thursday?", "body_text": "Bring a dessert. RSVP by Monday."},
                {"subject": "Your Lloyds Bank statement is ready", "body_text": "Log in to the app to view it."},
                {"subject": "British Gas: your bill", "body_text": "Your bill for November is ready."}):
        new = {m["id"] for m in FEED.match(inp)} & {"cmp-c72711ee", "cmp-d25e2692", "cmp-3a416f33", "cmp-6cb2941e"}
        assert not new, (inp, new)


def test_build_tool_can_write_outside_the_repo(tmp_path):
    out = tmp_path / "seed.json"
    shutil.copy(cm.SEED_PATH, out)
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "build_campaign_seed.py"), "--offline", "--out", str(out)],
                       cwd=ROOT, capture_output=True, text=True, timeout=120,
                       env={**os.environ, "OFFLINE_MODE": "true", "CT_MODE": "off"})
    assert r.returncode == 0, r.stdout + r.stderr
    assert "Wrote" in r.stdout and len(cm.load_seed(out)["campaigns"]) == len(FEED.seed_campaigns)
