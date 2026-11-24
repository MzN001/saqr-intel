"""tools/url_datasets.py (generic labelled-URL loader) and tools/augment.py (offline parts)."""
from __future__ import annotations

import random
import sys
import warnings
from pathlib import Path
from urllib.parse import urlsplit

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import augment  # noqa: E402
import url_datasets as ud  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "url_datasets"
POPULAR = frozenset({"google.com", "youtube.com", "microsoft.com", "wikipedia.org", "amazon.com", "apple.com",
                     "github.com", "bbc.com", "facebook.com", "linkedin.com"})


def labels(rows):
    return {url: label for url, label, _ in rows}


def test_word_labels_and_column_detection():
    with pytest.warns(ud.AmbiguousLabelWarning, match="unknown-kind"):
        rows = ud.load_labelled(FIX / "words.csv", popular=POPULAR)
    got = labels(rows)
    assert got["https://www.google.com/search?q=weather"] == 0
    assert got["http://paypa1-secure-login.xyz/signin.php"] == 1
    assert got["http://update-account.top/wp-admin/x/"] == 1
    assert got["http://old-defaced.example.org/index.html"] == 1
    assert "http://weird.example.net/" not in got
    assert len(rows) == 6
    assert {source for _, _, source in rows} == {"words"}


def test_numeric_labels_flip_when_one_is_the_popular_class():
    with pytest.warns(ud.AmbiguousLabelWarning, match="label 1 looks LEGITIMATE"):
        rows = ud.load_labelled(FIX / "numeric_one_is_legit.csv", popular=POPULAR)
    got = labels(rows)
    assert got["https://www.google.com"] == 0
    assert got["https://www.small-legit-shop.example"] == 0
    assert got["http://tamm-fines-pay.xyz/pay"] == 1
    assert sum(got.values()) == 3


def test_numeric_labels_kept_when_zero_is_the_popular_class():
    with warnings.catch_warnings():
        warnings.simplefilter("error", ud.AmbiguousLabelWarning)
        rows = ud.load_labelled(FIX / "numeric_one_is_phishing.tsv", popular=POPULAR)
    got = labels(rows)
    assert got["https://accounts.google.com/signin"] == 0
    assert got["http://amaz0n-refund.click/claim"] == 1
    assert len(rows) == 5


def test_ambiguous_numeric_labels_warn_loudly_and_default_to_one_is_phishing():
    with pytest.warns(ud.AmbiguousLabelWarning, match="AMBIGUOUS"):
        rows = ud.load_labelled(FIX / "numeric_ambiguous.csv", popular=POPULAR)
    assert labels(rows)["http://alpha-one.example/a"] == 1
    assert labels(rows)["http://delta-four.example/d"] == 0


def test_explicit_positive_overrides_detection():
    with warnings.catch_warnings():
        warnings.simplefilter("error", ud.AmbiguousLabelWarning)
        rows = ud.load_labelled(FIX / "numeric_ambiguous.csv", positive={"0"}, popular=POPULAR)
        named = ud.load_labelled(FIX / "words.csv", url_col="website", label_col="verdict",
                                 positive=["phishing", "malware"], popular=POPULAR)
    assert labels(rows)["http://alpha-one.example/a"] == 0
    assert labels(rows)["http://delta-four.example/d"] == 1
    assert labels(named)["http://old-defaced.example.org/index.html"] == 0
    assert labels(named)["http://update-account.top/wp-admin/x/"] == 1


def test_phiusiil_quirk_one_is_legit_without_popular_hosts():
    with warnings.catch_warnings():
        warnings.simplefilter("error", ud.AmbiguousLabelWarning)
        rows = ud.load_labelled(FIX / "PhiUSIIL_sample.csv", popular=POPULAR)
    assert rows == [("https://www.unknown-legit-one.example", 0, "phiusiil"),
                    ("http://phish-kit.example.top/login/index.php", 1, "phiusiil"),
                    ("https://www.unknown-legit-two.example", 0, "phiusiil")]


def test_plain_text_needs_a_label_and_normalises_lines():
    with pytest.raises(ValueError, match="no label column"):
        ud.load_labelled(FIX / "plain_hosts.txt")
    rows = ud.load_labelled(FIX / "plain_hosts.txt", label=1, source="feed")
    assert rows == [("http://evil-login.top", 1, "feed"), ("http://hosts-format.xyz", 1, "feed"),
                    ("http://full-url.example/path/kit.php", 1, "feed")]


def test_json_and_jsonl():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ud.AmbiguousLabelWarning)
        rows = ud.load_labelled(FIX / "rows.json", popular=POPULAR)
    assert labels(rows) == {"https://www.bbc.com/news": 0, "http://bbc-news-login.cfd/": 1,
                            "https://www.facebook.com/login/": 0}
    lines = ud.load_labelled(FIX / "rows.jsonl", popular=POPULAR)
    assert labels(lines) == {"https://www.linkedin.com/feed/": 0, "http://linkedin-verify.buzz/in": 1}


def test_headerless_csv_and_comment_header():
    ranked = ud.load_labelled(FIX / "headerless_ranked.csv", label=0, source="tranco")
    assert [u for u, _, _ in ranked] == ["http://google.com", "http://facebook.com", "http://microsoft.com"]
    haus = ud.load_labelled(FIX / "urlhaus_sample.csv")
    assert haus == [("http://198.51.100.7/bins/mips", 1, "urlhaus"),
                    ("http://files.example.net/update.exe", 1, "urlhaus")]


def test_source_column_is_kept_per_row():
    rows = ud.load_labelled(FIX / "with_source.csv", positive={"1"})
    assert rows == [("https://tamm-fines.xyz/pay", 1, "synthetic"),
                    ("https://www.tamm.abudhabi/en/login", 0, "harvest_uae_official")]
    assert {s for _, _, s in ud.load_labelled(FIX / "with_source.csv", positive={"1"}, source="x")} == {"x"}


def test_missing_named_column_is_an_error():
    with pytest.raises(ValueError, match="URL column 'nope' not found"):
        ud.load_labelled(FIX / "words.csv", url_col="nope")


def test_parquet_round_trip(tmp_path):
    pa = pytest.importorskip("pyarrow")
    import pyarrow.parquet as pq

    table = pa.table({"url": ["https://www.google.com/maps", "http://g00gle-login.top/a"],
                      "label": ["benign", "phish"], "html": ["<html>", "<html>"]})
    pq.write_table(table, tmp_path / "set.parquet")
    rows = ud.load_labelled(tmp_path / "set.parquet", popular=POPULAR)
    assert labels(rows) == {"https://www.google.com/maps": 0, "http://g00gle-login.top/a": 1}


def test_summarise_reports_the_path_bias():
    rows = [("https://a.example/", 0, "s"), ("https://b.example", 0, "s"), ("https://c.example/login", 0, "s"),
            ("http://x.top/a/b.php", 1, "s"), ("http://y.top/?id=1", 1, "s")]
    summary = ud.summarise(rows, popular=POPULAR)
    assert summary["legit"] == 3 and summary["phishing"] == 2
    assert summary["legit_with_path_share"] == pytest.approx(0.3333, abs=1e-4)
    assert summary["phishing_with_path_share"] == 1.0
    assert summary["legit_rows_have_paths"] is True
    assert ud.has_path("https://a.example/") is False
    assert ud.is_popular("accounts.google.com", POPULAR) and not ud.is_popular("google.com.evil.top", POPULAR)


@pytest.fixture(scope="module")
def reg():
    return augment.registry_data()


def test_synthetic_phishing_is_deterministic_and_never_an_official_host(reg):
    data = [("http://kit.example.top/secure/login.php?victim=a%40b.c", 1, "openphish"),
            ("http://kit2.example.top/ae/pay/index.html", 1, "openphish")]
    first = augment.synthetic_phishing(reg, data, 20, random.Random(5))
    again = augment.synthetic_phishing(reg, data, 20, random.Random(5))
    assert first == again and len(first) > 20 * len(reg["brands"]) * 0.8
    official = set(reg["official"])
    techniques = set()
    for url, label, source, variant in first:
        host = ud.host_of(url)
        assert label == 1 and source == "synthetic"
        assert host not in official and not augment.on_suffix(host, official)
        assert "%40" not in url and "@" not in url
        techniques.add(variant.split(":")[0])
    assert {"homoglyph", "idn_homoglyph", "tld_swap", "brand_lure", "brand_subdomain", "free_hosting",
            "arabic_translit"} <= techniques
    assert any(ud.host_of(u).startswith("xn--") for u, *_ in first)
    assert any(not ud.has_path(u) for u, *_ in first) or all(ud.has_path(u) for u, *_ in first)


def test_evasion_keeps_label_and_site_and_userinfo_is_phishing_only(reg):
    base = [(f"https://shop{i}.example.com/account/login", 0, "legit") for i in range(300)]
    base += [(f"http://kit{i}.example.top/verify/index.php", 1, "feed") for i in range(300)]
    rows = augment.evasion_variants(base, reg, 300, random.Random(3))
    assert rows == augment.evasion_variants(base, reg, 300, random.Random(3))
    by_label = {0: set(), 1: set()}
    originals = {u for u, _, _ in base}
    for url, label, source, variant in rows:
        assert url not in originals and source in ("legit+evasion", "feed+evasion")
        assert ud.normalise_url(url) == url
        assert (label == 1) == source.startswith("feed")
        host = (urlsplit(url).hostname or "").lower().rstrip(".").removeprefix("www.")
        assert host.endswith(".example.com" if label == 0 else ".example.top")
        by_label[label].add(variant)
    assert "userinfo" in by_label[1] and "userinfo" not in by_label[0]
    assert {"scheme", "www", "case", "slash", "percent", "port"} <= by_label[0]


def test_same_site_filter_and_link_choice():
    links = ["https://www.bank.example/en/login", "https://evil.example.net/en/login", "https://bank.example/",
             "https://cdn.bank.example/app.js", "https://bank.example/ar/خدمات", "mailto:a@bank.example",
             "https://user@bank.example/x", "https://bank.example/about#team"]
    kept = augment._same_site(links, "bank.example")
    assert kept == ["https://www.bank.example/en/login", "https://bank.example/ar/خدمات",
                    "https://bank.example/about"]
    chosen = augment.choose_links(kept, 2, random.Random(1))
    assert len(chosen) == 2 and "https://bank.example/about" not in chosen


def test_permutations_cover_dnstwist_techniques():
    variants = augment.permutations("emirates", random.Random(2))
    kinds = {kind for _, kind in variants}
    assert {"homoglyph", "idn_homoglyph", "omission", "transposition", "insertion", "repetition", "replacement",
            "hyphenation"} <= kinds
    assert ("emirats", "omission") in variants and ("emiartes", "transposition") in variants
    assert all(v != "emirates" for v, _ in variants)
