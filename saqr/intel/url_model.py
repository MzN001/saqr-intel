"""Trained phishing-hostname classifier (logistic regression over hashed character n-grams).

Trained offline by `tools/train_url_model.py` on ~400k labelled hostnames (PhiUSIIL research
dataset, the Phishing Army community blocklist, and real top sites from the Tranco list). It looks
only at the website address (not the path), because that is where phishing gives itself away:
`exchangeportal-owa-auth-login-hyttgygh.infura-ipfs.io`, `secure-paypa1-verify.com`, ...

Pure Python at runtime (no numpy / scikit-learn): one model file of 2^18 float32 weights, ~1 MB,
scores a hostname in well under a millisecond. Feature extraction here and in training is the same
function, so the two can never drift apart.
"""
from __future__ import annotations

import math
import re
import zlib
from array import array
from functools import lru_cache
from pathlib import Path

N_FEATURES = 1 << 18
MODEL_PATH = Path(__file__).with_name("url_model.bin")

# Free hosting / website builders / file shares: legitimate platforms, but most "brand on a free
# sub-domain" phishing lives here (abc-login.web.app, wallet-sync.vercel.app ...).
FREE_HOSTING = (
    "web.app", "firebaseapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "github.io",
    "gitlab.io", "glitch.me", "herokuapp.com", "onrender.com", "repl.co", "replit.app", "replit.dev",
    "weebly.com", "wixsite.com", "wix.com", "square.site", "godaddysites.com", "blogspot.com",
    "wordpress.com", "webflow.io", "framer.app", "framer.website", "carrd.co", "strikingly.com",
    "jimdosite.com", "site123.me", "mystrikingly.com", "000webhostapp.com", "azurewebsites.net",
    "web.core.windows.net", "blob.core.windows.net", "appspot.com", "ipfs.io", "infura-ipfs.io",
    "dweb.link", "cloudflare-ipfs.com", "fleek.co", "surge.sh", "translate.goog", "sharepoint.com",
    "trycloudflare.com", "ngrok-free.app", "ngrok.io", "codeanyapp.com", "r2.dev", "my.canva.site",
    "notion.site", "typedream.app", "teachable.com", "myshopify.com", "hubspotpagebuilder.com",
)
LURES = (
    "login", "log-in", "signin", "sign-in", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "support", "service", "billing", "payment", "pay", "wallet", "recover", "unlock",
    "suspend", "alert", "auth", "authentication", "validate", "claim", "reward", "bonus", "gift", "refund",
    "invoice", "delivery", "parcel", "track", "customs", "fine", "bank", "online", "web", "portal",
    "official", "help", "center", "desk", "sso", "owa", "webmail", "mail", "office", "connect", "sync",
    "airdrop", "metamask", "seed", "token", "kyc", "app", "id", "my",
)


def normalise_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    h = re.sub(r"^www\d*\.", "", h)
    return h.split(":")[0]


def _h(token: str) -> int:
    return zlib.crc32(token.encode("utf-8", "ignore")) % N_FEATURES


def features(host: str) -> dict[int, float]:
    """Sparse feature vector for one hostname (shared by training and inference)."""
    h = normalise_host(host)
    feats: dict[int, float] = {}

    def add(tok: str, v: float = 1.0) -> None:
        i = _h(tok)
        feats[i] = feats.get(i, 0.0) + v

    s = f"^{h}$"
    for n in (3, 4, 5):
        for i in range(len(s) - n + 1):
            add(f"c{n}:{s[i:i + n]}")
    labels = h.split(".")
    tld = labels[-1] if labels else ""
    add(f"tld:{tld}")
    platform = next((p for p in FREE_HOSTING if h == p or h.endswith("." + p)), None)
    if platform:
        add("free_hosting")
        add(f"platform:{platform}")
        sub = h[: -len(platform) - 1] if h != platform else ""
        labels_for_tokens = sub.split(".") if sub else []
    else:
        labels_for_tokens = labels[:-1]
    tokens = [t for lab in labels_for_tokens for t in re.split(r"[-_]", lab) if t]
    for t in tokens:
        add(f"tok:{t}")
        if t in LURES:
            add("lure")
            add(f"lure:{t}")
        if re.fullmatch(r"[a-z]*\d+[a-z\d]*", t) and re.search(r"[a-z]", t):
            add("alnum_mix")
    digits = sum(ch.isdigit() for ch in h)
    add(f"len:{min(len(h) // 8, 10)}")
    add(f"labels:{min(len(labels), 7)}")
    add(f"hyphens:{min(h.count('-'), 6)}")
    add(f"digits:{min(digits, 8)}")
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", h):
        add("raw_ip")
    if "xn--" in h:
        add("punycode")
    # Normalise to unit length so long hostnames don't dominate.
    norm = math.sqrt(sum(v * v for v in feats.values())) or 1.0
    return {k: v / norm for k, v in feats.items()}


@lru_cache(maxsize=1)
def _model() -> tuple[array, float] | None:
    if not MODEL_PATH.exists():
        return None
    raw = MODEL_PATH.read_bytes()
    w = array("f")
    w.frombytes(raw[: N_FEATURES * 4])
    b = array("f")
    b.frombytes(raw[N_FEATURES * 4: N_FEATURES * 4 + 4])
    return w, float(b[0])


def available() -> bool:
    return _model() is not None


@lru_cache(maxsize=4096)
def phishing_probability(host: str) -> float | None:
    """0..1 probability that this hostname is a phishing site, or None if no model is installed."""
    m = _model()
    if not m or not host:
        return None
    w, b = m
    z = b + sum(w[i] * v for i, v in features(host).items())
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))
