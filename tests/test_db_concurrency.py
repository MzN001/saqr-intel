"""Regression: concurrent scans of the same new domain must not crash with IntegrityError.

Found in the email E2E test: several emails with the same scam link scanned at once (inbox "scan all")
made db.upsert_node race (SELECT, then plain INSERT) and the link scans failed, so the emails lost
their LINK_HIGH_RISK flag.
"""
import asyncio
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"


def test_upsert_node_concurrent_same_id():
    from saqr.db import Database  # imported here so collecting this file never loads settings early

    async def run():
        d = Database(os.path.join(tempfile.mkdtemp(), "race.db"))
        await d.connect()
        try:
            res = await asyncio.gather(*(d.upsert_node("domain:race-test.example", "domain", "race-test.example",
                                                       risk=10 * i, data={f"k{i}": i}) for i in range(8)))
            row = await d.fetchone("SELECT risk, data_json FROM graph_nodes WHERE id=?", ("domain:race-test.example",))
            return res, row
        finally:
            await d.close()

    res, row = asyncio.run(run())
    assert res.count(True) == 1  # exactly one scan created the node, the others merged into it
    assert row["risk"] == 70
