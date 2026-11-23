"""Regression: link extraction must stay linear on long tokens (found by the web-app E2E test).

pipeline.URL_IN_TEXT backtracks quadratically on a long run of letters without a dot: a 100 kB "xxxx..."
email took 77 s of CPU and a 2.6 MB .eml froze the one-worker server. email_parse uses a look-behind
variant with the same matches.
"""
import os
import random
import tempfile
import time

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402

email_parse = pytest.importorskip("saqr.intel.email_parse")


@pytest.mark.parametrize("body", ["x" * 200_000, "a." * 100_000, "a[.]" * 50_000, "-" * 200_000,
                                  ("a" * 3000 + ". ") * 60])
def test_links_from_text_is_linear(body):
    t = time.perf_counter()
    email_parse.links_from_text(body)
    assert time.perf_counter() - t < 2.0


def test_same_matches_as_pipeline_pattern():
    from saqr.pipeline import URL_IN_TEXT

    random.seed(7)
    texts = ["visit evil.com now", "...evil.com", "a..b.com", "x_y.example.org/p", "hxxps://bad[.]com/x",
             "foo@bar.com", "1.2.3.example.com", "www.paypal.com/x?y=1", "تفضل tamm-fine.test/pay"]
    texts += ["".join(random.choice("ab.-/[]:h tp@x1") for _ in range(random.randint(1, 40))) for _ in range(5000)]
    for t in texts:
        assert [m.span() for m in email_parse._URL_SCAN.finditer(t)] == [m.span() for m in URL_IN_TEXT.finditer(t)], t


def test_long_body_still_finds_links():
    links = email_parse.links_from_text("x" * 50_000 + " pay at https://tamm-fine.test/pay and evil.example.com ")
    assert {l.href for l in links} >= {"https://tamm-fine.test/pay", "evil.example.com"}


@pytest.mark.parametrize("blob", [b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 40, b"%PDF-1.7\n" + bytes(range(128, 256)) * 80,
                                  b"PK\x03\x04" + b"\x00\x14" * 500])
def test_binary_file_renamed_eml_is_rejected(blob):
    """A picture/PDF/zip renamed to .eml was read as text and came back HIGH-RISK (look-alike letters)."""
    with pytest.raises(ValueError, match="not an email"):
        email_parse.parse(source="eml", file_bytes=blob, file_name="photo.eml")


def test_headerless_text_eml_still_read():
    p = email_parse.parse(source="eml", file_bytes="Hello, see you at 5 pm. مرحبا\n".encode(), file_name="note.eml")
    assert not p.has_headers and "Hello" in p.text_body
