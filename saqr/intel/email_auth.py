"""Email sender authentication for the email scanner (workstream A): SPF, DKIM, DMARC and ARC.

verify(parsed) never raises and never blocks for long. It combines two kinds of evidence:

1. What the citizen's own mailbox provider already decided, written into the message as
   Authentication-Results (RFC 8601), ARC-Authentication-Results and Received-SPF headers.
   Anyone can type such a header into a scam email, so we believe ONLY:
     * a header whose authserv-id belongs to a well-known mailbox provider (Gmail, Outlook,
       Yahoo, iCloud, Zoho, Proton - extendable with EMAIL_TRUSTED_AUTHSERV), and
     * the topmost such header, sitting above every Received header written by a server we do not
       know. Headers lower down could have been written by the sender.
2. Our own checks (only when not offline): DKIM + ARC signatures with dkimpy (only meaningful when
   we hold the exact original bytes, i.e. an uploaded .eml), SPF with pyspf for the client IP that a
   trusted provider recorded, and DMARC (TXT _dmarc.<domain>) with relaxed / strict alignment.

The provider's verdict wins over our recomputation for the same check: it saw the message as it
arrived, before forwarding, exporting or key rotation could change anything.
Offline (tests / OFFLINE_MODE): only the headers are read, plus DKIM / ARC / DMARC through an
injected dnsfunc (a dkimpy-style function name -> TXT bytes), so tests never touch the network.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..config import settings
from .email_types import AuthARC, AuthDKIM, AuthDMARC, AuthReport, AuthSPF, ParsedEmail

log = logging.getLogger("saqr.email.auth")

# dkimpy logs every failed signature at ERROR level; a failed scam signature is a result, not an error.
_DKIM_LOG = logging.getLogger("saqr.email.auth.dkimpy")
_DKIM_LOG.setLevel(logging.CRITICAL)

# Mailbox providers whose Authentication-Results we believe (the host itself or any sub-domain).
TRUSTED_AUTHSERV_DOMAINS: tuple[str, ...] = (
    "mx.google.com", "google.com",                       # Gmail ("google.com:" in Received-SPF comments)
    "outlook.com", "office365.com", "mx.microsoft.com",  # Outlook.com / Microsoft 365 (*.protection / *.prod)
    "yahoo.com",                                         # mta*.mail.yahoo.com, atlas-*.mail.*.yahoo.com
    "icloud.com", "me.com",                              # iCloud (dkim-verifier.icloud.com, spf.icloud.com ...)
    "zoho.com", "zohomail.com",
    "protonmail.ch", "proton.me", "protonmail.com",
)

SPF_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}


def _extra_trusted() -> tuple[str, ...]:
    """EMAIL_TRUSTED_AUTHSERV="mail.example.ae,mx.myisp.ae" (env) or settings.email_trusted_authserv."""
    items = list(settings.email_trusted_authserv)
    # Also read at call time so a changed environment (tests, a reloaded shell) is honoured.
    items += [x for x in os.getenv("EMAIL_TRUSTED_AUTHSERV", "").split(",")]
    return tuple(x.strip().lower().lstrip(".") for x in items if x and x.strip())


def is_trusted_host(host: Optional[str]) -> bool:
    """True when this authserv-id / receiving host belongs to a trusted mailbox provider."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    for base in TRUSTED_AUTHSERV_DOMAINS + _extra_trusted():
        if h == base or h.endswith("." + base):
            return True
    return False


def _is_ip(value: str) -> bool:
    v = (value or "").strip().strip("[]")
    if v.lower().startswith("ipv6:"):
        v = v[5:]
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


_INTERNAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
    "::/128", "::1/128", "fc00::/7", "fe80::/10"))


def _external_ip(value: str) -> bool:
    """An address a mail server outside the provider could connect from (not loopback / RFC 1918 / CGNAT).

    Documentation ranges (192.0.2.0/24 ...) count as external so the fictitious fixtures behave like real mail.
    """
    v = (value or "").strip().strip("[]")
    if v.lower().startswith("ipv6:"):
        v = v[5:]
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return not any(ip in net for net in _INTERNAL_NETS if net.version == ip.version)


def org_domain(host: str) -> str:
    """Organizational ("registered") domain via the Public Suffix List; last two labels as a fallback."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    from .domain_intel import _EXTRACT

    try:
        r = _EXTRACT(h)
        if r.domain and r.suffix:
            return f"{r.domain}.{r.suffix}"
    except Exception:  # noqa: BLE001
        pass
    parts = h.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def aligned(domain: str, from_domain: str, mode: str = "r") -> bool:
    """DMARC identifier alignment: strict = same host, relaxed = same organizational domain."""
    d, f = (domain or "").lower().rstrip("."), (from_domain or "").lower().rstrip(".")
    if not d or not f:
        return False
    if mode == "s":
        return d == f
    return org_domain(d) == org_domain(f)


# ---------------------------------------------------------------------------
# RFC 8601 Authentication-Results parsing
# ---------------------------------------------------------------------------
@dataclass
class ARMethod:
    method: str  # "spf" | "dkim" | "dmarc" | "arc" | ...
    result: str
    props: dict[str, str] = field(default_factory=dict)  # "smtp.mailfrom", "header.d", "header.from", ...
    comment: str = ""  # text of the (comments), e.g. "(p=REJECT sp=REJECT dis=NONE)"


@dataclass
class ARHeader:
    authserv_id: Optional[str]  # None when missing (Microsoft 365 omits it)
    methods: list[ARMethod] = field(default_factory=list)
    instance: Optional[int] = None  # ARC-Authentication-Results i=


def _split_top(value: str, sep: str = ";") -> list[str]:
    """Split on sep outside quoted strings and (nested) comments."""
    out, cur, depth, inq, esc = [], [], 0, False, False
    for ch in value:
        if esc:
            cur.append(ch)
            esc = False
            continue
        if ch == "\\":
            cur.append(ch)
            esc = True
            continue
        if inq:
            cur.append(ch)
            if ch == '"':
                inq = False
            continue
        if ch == '"' and not depth:
            inq = True
        elif ch == "(":
            depth += 1
        elif ch == ")" and depth:
            depth -= 1
        elif ch == sep and not depth:
            out.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    out.append("".join(cur))
    return out


def _strip_comments(value: str) -> tuple[str, str]:
    """Remove (comments) outside quoted strings -> (text with comments replaced by spaces, joined comments)."""
    out, comments, cur, depth, inq, esc = [], [], [], 0, False, False
    for ch in value:
        if esc:
            (cur if depth else out).append(ch)
            esc = False
            continue
        if ch == "\\":
            esc = True
            if not depth:
                out.append(ch)
            continue
        if inq:
            out.append(ch)
            if ch == '"':
                inq = False
            continue
        if depth:
            if ch == "(":
                depth += 1
                cur.append(ch)
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    comments.append("".join(cur))
                    cur = []
                    out.append(" ")
                else:
                    cur.append(ch)
            else:
                cur.append(ch)
            continue
        if ch == '"':
            inq = True
            out.append(ch)
        elif ch == "(":
            depth = 1
        else:
            out.append(ch)
    if cur:
        comments.append("".join(cur))
    return "".join(out), " ".join(c.strip() for c in comments if c.strip())


def _tokens(value: str) -> list[str]:
    """Whitespace-separated tokens, quoted strings kept whole (quotes removed)."""
    return [a or b for a, b in re.findall(r'"((?:[^"\\]|\\.)*)"|(\S+)', value)] if value else []


def _kv_tokens(value: str) -> list[tuple[str, str]]:
    out = []
    for m in re.finditer(r'([A-Za-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]+)?', value):
        v = (m.group(2) or "").strip()
        if v.startswith('"') and v.endswith('"') and len(v) >= 2:
            v = v[1:-1]
        out.append((m.group(1), v))
    return out


def parse_authentication_results(value: str, *, arc: bool = False) -> ARHeader:
    """Parse one Authentication-Results (or ARC-Authentication-Results when arc=True) header value."""
    segments = _split_top(value or "")
    instance: Optional[int] = None
    if arc and segments:
        m = re.match(r"\s*i\s*=\s*(\d+)\s*$", _strip_comments(segments[0])[0])
        if m:
            instance = int(m.group(1))
            segments = segments[1:]
    header = ARHeader(authserv_id=None, instance=instance)
    if not segments:
        return header
    first, _ = _strip_comments(segments[0])
    if "=" not in first:  # "mx.google.com" or "mx.microsoft.com 1" (version number)
        toks = first.split()
        header.authserv_id = toks[0].lower().rstrip(".") if toks else None
        segments = segments[1:]
    for seg in segments:
        text, comment = _strip_comments(seg)
        pairs = _kv_tokens(text)
        if not pairs:
            continue  # "none" (no checks were performed) or garbage
        method, result = pairs[0]
        method = method.split("/")[0].lower()
        props = {k.lower(): v for k, v in pairs[1:]}
        header.methods.append(ARMethod(method=method, result=result.lower(), props=props, comment=comment))
    return header


def parse_received(value: str) -> dict[str, str]:
    """from-host, from-ip, helo and by-host of one Received header ("" when absent)."""
    v = value or ""
    # The date sits after the last ";": drop it so it cannot be mistaken for anything else.
    if ";" in v:
        v = v[: v.rfind(";")]
    plain, _ = _strip_comments(v)
    out = {"from": "", "helo": "", "ip": "", "by": ""}
    m = re.search(r"\bfrom\s+(\S+)", plain, re.I)
    if m:
        out["from"] = out["helo"] = m.group(1).strip("[]").rstrip(".").lower()
    m = re.search(r"\bby\s+(\S+)", plain, re.I)
    if m:
        out["by"] = m.group(1).rstrip(".").lower()
    # The connecting IP is in the comment after "from" ("(host [1.2.3.4])", "(1.2.3.4)", "[IPv6:...]").
    from_part = re.split(r"\bby\s", v, maxsplit=1, flags=re.I)[0]
    for cand in re.findall(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]", from_part) + re.findall(
            r"[\s(]([0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})[\s)\]]", from_part + " "):
        if _is_ip(cand):
            out["ip"] = cand
            break
    if not out["ip"] and _is_ip(out["from"]):
        out["ip"] = out["from"]
    return out


def parse_received_spf(value: str) -> dict[str, str]:
    """Received-SPF (RFC 7208 section 9.1): result word, comment, and key=value pairs."""
    text, comment = _strip_comments(value or "")
    toks = text.split()
    result = toks[0].lower().rstrip(";") if toks else ""
    out = {"result": result, "comment": comment}
    for k, val in _kv_tokens(text):
        out[k.lower()] = val.rstrip(";")
    m = re.match(r"\s*([A-Za-z0-9.-]+):", comment)
    out["comment_host"] = m.group(1).lower() if m else ""
    return out


# ---------------------------------------------------------------------------
# Trust boundary: which of the headers were written by the citizen's own mailbox provider?
# ---------------------------------------------------------------------------
@dataclass
class _Chain:
    trusted_authserv: Optional[str] = None
    methods: list[ARMethod] = field(default_factory=list)  # from the trusted A-R (merged same-org headers)
    arc_methods: list[ARMethod] = field(default_factory=list)  # from the trusted ARC-A-R (fallback)
    arc_authserv: Optional[str] = None
    received_spf: Optional[dict[str, str]] = None
    entry: Optional[dict[str, str]] = None  # Received header where the mail entered the trusted provider
    return_path: str = ""


def _received_kind(rec: dict[str, str]) -> str:
    """trusted | neutral (internal hop: by an IP / a host without dots / nothing) | untrusted."""
    by = rec.get("by", "")
    if not by or _is_ip(by) or "." not in by:
        return "neutral"
    return "trusted" if is_trusted_host(by) else "untrusted"


def analyse_chain(headers: list[tuple[str, str]]) -> _Chain:
    """Walk the headers top-down until the hop where the mail entered a trusted provider (or an unknown server).

    Postfix-based providers place their Authentication-Results just BELOW their own Received header (a
    milter cannot insert above it). So right after the entry hop, a contiguous block of A-R / ARC-A-R /
    Received-SPF headers is still read - but only from that same provider (same organizational domain as
    the entry hop's "by" host), which by RFC 8601 section 5 removes forged headers carrying its own name.
    """
    chain = _Chain()
    org: Optional[str] = None  # organisation of the trusted A-R we picked (merge iCloud's split headers)
    merging = False
    received_seen = 0
    entry_org: Optional[str] = None  # set once we are below the entry hop
    for idx, (name, value) in enumerate(headers):
        n = name.lower()
        if entry_org is not None and n not in ("authentication-results", "arc-authentication-results", "received-spf"):
            break  # past the provider's block: everything below was written before it got the mail
        if n == "received":
            merging = False
            rec = parse_received(value)
            kind = _received_kind(rec)
            if kind == "untrusted":
                break  # written by a server we do not know: everything below could come from the sender
            received_seen += 1
            if kind == "trusted" and rec["ip"] and _external_ip(rec["ip"]) and not is_trusted_host(rec["from"]):
                chain.entry = rec  # where the mail entered the trusted provider from the outside world
                entry_org = org_domain(rec["by"])
            continue
        if n == "authentication-results":
            ar = parse_authentication_results(value)
            sid = ar.authserv_id
            if sid is None:
                # Microsoft 365 omits the authserv-id; it belongs to the server of the next Received below.
                sid = _next_received_by(headers, idx) if entry_org is None else ""
            if not is_trusted_host(sid) or (entry_org is not None and org_domain(sid) != entry_org):
                continue
            if chain.trusted_authserv is None:
                chain.trusted_authserv = sid
                chain.methods = list(ar.methods)
                org = org_domain(sid)
                merging = True
            elif merging and org_domain(sid) == org:
                chain.methods.extend(ar.methods)  # e.g. iCloud: dkim-verifier / spf / dmarc .icloud.com
            continue
        if n == "arc-authentication-results":
            ar = parse_authentication_results(value, arc=True)
            if (chain.arc_authserv is None and is_trusted_host(ar.authserv_id)
                    and (entry_org is None or org_domain(ar.authserv_id or "") == entry_org)):
                chain.arc_authserv = ar.authserv_id
                chain.arc_methods = list(ar.methods)
            continue
        if n == "received-spf":
            rs = parse_received_spf(value)
            host = rs.get("receiver") if is_trusted_host(rs.get("receiver")) else rs.get("comment_host")
            if (chain.received_spf is None and is_trusted_host(host)
                    and (entry_org is None or org_domain(host or "") == entry_org)):
                chain.received_spf = rs
            continue
        if n == "return-path" and not chain.return_path:
            m = re.search(r"<([^<>]*)>", value)
            chain.return_path = (m.group(1) if m else value).strip()
    if not received_seen:
        # No receiving server ever handled this copy (e.g. an export without Received headers):
        # any Authentication-Results in it could just as well have been typed by the sender.
        return _Chain()
    return chain


def _next_received_by(headers: list[tuple[str, str]], idx: int) -> str:
    for name, value in headers[idx + 1:]:
        if name.lower() == "received":
            return parse_received(value).get("by", "")
    return ""


# ---------------------------------------------------------------------------
# Result normalisation
# ---------------------------------------------------------------------------
def _norm_spf(result: str) -> str:
    r = (result or "").lower()
    if r == "hardfail":
        return "fail"
    if r in ("error",):
        return "temperror"
    return r if r in SPF_RESULTS else "none"


def _norm_dkim(result: str) -> str:
    r = (result or "").lower()
    if r == "pass":
        return "pass"
    if r in ("fail", "permerror"):
        return "fail"
    if r == "temperror":
        return "not_checked"
    return "none"  # none / neutral / policy


def _norm_dmarc(result: str) -> str:
    r = (result or "").lower()
    if r in ("pass", "fail"):
        return r
    if r == "temperror":
        return "not_checked"
    return "none"  # none / permerror / bestguesspass


def _domain_of(value: str) -> str:
    v = (value or "").strip().strip("<>\"'").lower()
    return v.rpartition("@")[2].rstrip(".") if v else ""


def _ip_from_comment(comment: str) -> str:
    for pat in (r"designates\s+([0-9A-Fa-f:.]+)\s+as", r"sender ip is\s+([0-9A-Fa-f:.]+)",
                r"client-ip=([0-9A-Fa-f:.]+)", r"\bip[:=]\s*([0-9A-Fa-f:.]+)"):
        m = re.search(pat, comment or "", re.I)
        if m and _is_ip(m.group(1).rstrip(".;")):
            return m.group(1).rstrip(".;")
    return ""


def _policy_from_method(m: ARMethod, from_domain: str = "") -> Optional[str]:
    """DMARC policy stated by the provider: comment "(p=REJECT sp=...)", policy.dmarc=, or Microsoft action=."""
    hit = None
    if from_domain and org_domain(from_domain) != from_domain.lower():
        hit = re.search(r"\bsp\s*=\s*([A-Za-z]+)", m.comment or "")  # a sub-domain gets the sp= policy
    hit = hit or re.search(r"\bp\s*=\s*([A-Za-z]+)", m.comment or "")
    p = (hit.group(1) if hit else m.props.get("policy.dmarc", "") or m.props.get("policy.published-domain-policy", ""))
    p = p.lower()
    if p in ("reject", "quarantine", "none"):
        return p
    action = m.props.get("action", "").lower()
    if m.result == "fail" and action:
        return {"reject": "reject", "oreject": "reject", "quarantine": "quarantine", "none": "none"}.get(action)
    return None


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------
DnsFunc = Callable[..., Any]


class _TxtLookup:
    """TXT lookups: the injected dnsfunc, real DNS (not offline), or nothing (offline)."""

    def __init__(self, offline: bool, dnsfunc: Optional[DnsFunc]) -> None:
        self.offline, self.dnsfunc = offline, dnsfunc

    @property
    def available(self) -> bool:
        return self.dnsfunc is not None or not self.offline

    async def __call__(self, name: str) -> Optional[list[str]]:
        """List of TXT strings ([] = no record), None = lookup failed / not possible."""
        if self.dnsfunc is not None:
            fn = self.dnsfunc

            def _do() -> Any:
                return fn(name.rstrip(".").encode("ascii", "ignore") + b".")

            try:
                res = await asyncio.wait_for(asyncio.to_thread(_do), settings.dns_timeout_s + 1)
            except Exception:  # noqa: BLE001 - timeout or the stub raised: a temporary failure
                return None
            if not res:
                return []
            items = res if isinstance(res, (list, tuple)) else [res]
            return [x.decode("utf-8", "replace") if isinstance(x, (bytes, bytearray)) else str(x) for x in items]
        if self.offline:
            return None
        import dns.asyncresolver
        import dns.exception
        import dns.resolver

        res = dns.asyncresolver.Resolver()
        res.lifetime = settings.dns_timeout_s
        try:
            ans = await res.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except (dns.exception.DNSException, OSError):
            return None
        return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]


def _dkim_dnsfunc(dnsfunc: Optional[DnsFunc], state: dict[str, bool]) -> DnsFunc:
    """dkimpy-style TXT function that remembers temporary failures (timeout -> "not_checked", not "fail")."""

    def fn(name: bytes, timeout: float = 5) -> Optional[bytes]:
        if dnsfunc is not None:
            try:
                try:
                    return dnsfunc(name, timeout=timeout)
                except TypeError:
                    return dnsfunc(name)
            except Exception:  # noqa: BLE001
                state["temp"] = True
                return None
        import dns.exception
        import dns.resolver

        try:
            ans = dns.resolver.resolve(name.decode("ascii", "ignore"), "TXT",
                                       lifetime=min(float(timeout), settings.dns_timeout_s))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None  # no key published: a permanent failure
        except (dns.exception.DNSException, OSError):
            state["temp"] = True
            return None
        for r in ans:
            return b"".join(r.strings)
        return None

    return fn


# ---------------------------------------------------------------------------
# DKIM + ARC (dkimpy, in a worker thread)
# ---------------------------------------------------------------------------
def _dkim_tags(value: str) -> dict[str, str]:
    out = {}
    for part in re.sub(r"\s+", "", value or "").split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.lower()] = v
    return out


def _verify_dkim_sync(raw: bytes, count: int, dnsfunc: Optional[DnsFunc]) -> list[str]:
    import dkim

    results: list[str] = []
    for idx in range(count):
        state = {"temp": False}
        try:
            d = dkim.DKIM(raw, logger=_DKIM_LOG, timeout=settings.dns_timeout_s)
            ok = d.verify(idx=idx, dnsfunc=_dkim_dnsfunc(dnsfunc, state))
            results.append("pass" if ok else ("not_checked" if state["temp"] else "fail"))
        except dkim.NaClNotFoundError:
            results.append("not_checked")  # ed25519 signature but PyNaCl is not installed: cannot check
        except dkim.DKIMException:
            results.append("not_checked" if state["temp"] else "fail")  # malformed signature / key
        except Exception:  # noqa: BLE001
            results.append("not_checked")
    return results


def _verify_arc_sync(raw: bytes, dnsfunc: Optional[DnsFunc]) -> str:
    import dkim

    state = {"temp": False}
    try:
        cv, _res, _reason = dkim.arc_verify(raw, logger=_DKIM_LOG, dnsfunc=_dkim_dnsfunc(dnsfunc, state))
    except Exception:  # noqa: BLE001
        return "none"
    if state["temp"]:
        return "none"
    if cv is None:
        return "fail"  # dkimpy: an earlier ARC set reported failure, the chain is terminated
    cv = cv.decode("ascii", "replace") if isinstance(cv, bytes) else str(cv)
    return cv if cv in ("pass", "fail") else "none"


async def _in_thread(fn: Callable[[], Any], timeout: float, default: Any) -> Any:
    try:
        return await asyncio.wait_for(asyncio.to_thread(fn), timeout)
    except Exception:  # noqa: BLE001 - timeout / crash: degrade, never raise
        log.debug("email auth worker failed or timed out", exc_info=True)
        return default


# ---------------------------------------------------------------------------
# SPF (pyspf)
# ---------------------------------------------------------------------------
def _spf_check_sync(ip: str, mailfrom: str, helo: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # pyspf has old regex escapes (SyntaxWarning on Python 3.12+)
        import spf
    result, _explanation = spf.check2(i=ip, s=mailfrom, h=helo or "unknown", timeout=settings.dns_timeout_s)
    return _norm_spf(str(result))


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------
def parse_dmarc_record(txt: str) -> Optional[dict[str, str]]:
    """Tags of a "v=DMARC1; p=..." record, or None when it is not one."""
    tags: dict[str, str] = {}
    for part in (txt or "").split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    if tags.get("v", "").upper() != "DMARC1":
        return None
    return tags


async def lookup_dmarc(from_domain: str, txt: _TxtLookup) -> tuple[Optional[dict[str, str]], bool]:
    """(record tags + "effective_p", lookup_ok). Tries the From domain, then its organizational domain."""
    domain = (from_domain or "").lower().rstrip(".")
    org = org_domain(domain)
    for name, at_org in ((domain, False), (org, True)) if org != domain else ((domain, False),):
        res = await txt(f"_dmarc.{name}")
        if res is None:
            return None, False
        for item in res:
            rec = parse_dmarc_record(item)
            if rec is not None:
                p = rec.get("p", "none").lower()
                if at_org and rec.get("sp"):
                    p = rec["sp"].lower()
                rec["effective_p"] = p if p in ("none", "quarantine", "reject") else "none"
                return rec, True
    return None, True


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
async def verify(parsed: ParsedEmail, *, offline: Optional[bool] = None,
                 dnsfunc: Optional[DnsFunc] = None) -> AuthReport:
    """Authentication report for a parsed email. Never raises; unknown checks are "not_checked"."""
    try:
        return await _verify(parsed, offline=settings.offline_mode if offline is None else bool(offline),
                             dnsfunc=dnsfunc)
    except Exception:  # noqa: BLE001 - authentication is evidence, never a reason to fail the scan
        log.warning("email authentication check failed", exc_info=True)
        return AuthReport.not_checked()


async def _verify(parsed: ParsedEmail, *, offline: bool, dnsfunc: Optional[DnsFunc]) -> AuthReport:
    if not parsed.has_headers or not parsed.headers:
        return AuthReport.not_checked()
    report = AuthReport.not_checked()
    chain = analyse_chain(parsed.headers)
    report.trusted_authserv = chain.trusted_authserv
    methods = chain.methods or chain.arc_methods  # the provider's own A-R, else its ARC copy
    txt = _TxtLookup(offline, dnsfunc)
    from_domain = (parsed.from_.domain or "").lower()

    # --- DKIM ---------------------------------------------------------------------
    sig_values = parsed.headers_all("DKIM-Signature")
    sigs = [_dkim_tags(v) for v in sig_values]
    can_verify = bool(parsed.byte_exact and parsed.raw_bytes and sigs and (dnsfunc is not None or not offline))
    verified: list[str] = ["not_checked"] * len(sigs)
    if can_verify:
        raw = parsed.raw_bytes or b""
        verified = await _in_thread(lambda: _verify_dkim_sync(raw, len(sigs), dnsfunc),
                                    timeout=(settings.dns_timeout_s + 1) * max(1, len(sigs)) + 2,
                                    default=["not_checked"] * len(sigs))
    ar_dkim = [m for m in methods if m.method == "dkim"]
    dkim_entries: list[AuthDKIM] = []
    used_sigs: set[int] = set()
    for m in ar_dkim:
        d = (m.props.get("header.d") or _domain_of(m.props.get("header.i", ""))).lower()
        if d == "none":
            d = ""  # Microsoft writes "dkim=none (message not signed) header.d=none"
        s = m.props.get("header.s", "")
        dkim_entries.append(AuthDKIM(domain=d, selector=s, result=_norm_dkim(m.result), source="auth_results"))
        for i, tags in enumerate(sigs):
            if i not in used_sigs and tags.get("d", "").lower() == d and (not s or not tags.get("s")
                                                                            or tags.get("s") == s):
                used_sigs.add(i)
                break
    for i, tags in enumerate(sigs):
        if i in used_sigs:
            continue  # the provider already judged this signature
        dkim_entries.append(AuthDKIM(domain=tags.get("d", "").lower(), selector=tags.get("s", ""),
                                     result=verified[i] if i < len(verified) else "not_checked", source="verified"))
    report.dkim = dkim_entries

    # --- ARC ----------------------------------------------------------------------
    seals = parsed.headers_all("ARC-Seal")
    instances = [int(x) for v in seals for x in re.findall(r"(?:^|;)\s*i\s*=\s*(\d+)", v)[:1]]
    chain_len = max(instances) if instances else len(seals)
    arc_result = "none"
    if seals and parsed.byte_exact and parsed.raw_bytes and (dnsfunc is not None or not offline):
        raw = parsed.raw_bytes
        arc_result = await _in_thread(lambda: _verify_arc_sync(raw, dnsfunc),
                                      timeout=(settings.dns_timeout_s + 1) * 2 * max(1, chain_len) + 2,
                                      default="none")
    else:
        for m in chain.methods:
            if m.method == "arc":
                arc_result = m.result if m.result in ("pass", "fail") else "none"
                break
    report.arc = AuthARC(result=arc_result, chain_length=chain_len)

    # --- SPF ----------------------------------------------------------------------
    spf_m = next((m for m in methods if m.method == "spf"), None)
    entry_ip = chain.entry["ip"] if chain.entry else ""
    if spf_m is not None:
        mailfrom = spf_m.props.get("smtp.mailfrom", "")
        domain = _domain_of(mailfrom) or _domain_of(spf_m.props.get("smtp.helo", ""))
        report.spf = AuthSPF(result=_norm_spf(spf_m.result), domain=domain,
                             client_ip=_ip_from_comment(spf_m.comment) or entry_ip, source="auth_results")
    elif chain.received_spf is not None and chain.received_spf.get("result"):
        rs = chain.received_spf
        domain = _domain_of(rs.get("envelope-from", "")) or _domain_of(rs.get("helo", ""))
        report.spf = AuthSPF(result=_norm_spf(rs["result"]), domain=domain,
                             client_ip=rs.get("client-ip", "") or _ip_from_comment(rs.get("comment", "")) or entry_ip,
                             source="auth_results")
    elif chain.entry and not offline:
        mailfrom = chain.return_path
        helo = chain.entry.get("helo", "")
        if mailfrom or helo:
            result = await _in_thread(lambda: _spf_check_sync(entry_ip, mailfrom, helo),
                                      timeout=settings.dns_timeout_s * 4 + 2, default="not_checked")
            report.spf = AuthSPF(result=result, domain=_domain_of(mailfrom) or helo, client_ip=entry_ip,
                                 source="computed" if result != "not_checked" else "none")

    # --- DMARC --------------------------------------------------------------------
    dmarc_m = next((m for m in methods if m.method == "dmarc"), None)
    record: Optional[dict[str, str]] = None
    record_ok = False
    need_record = bool(from_domain) and txt.available and (dmarc_m is None or _policy_from_method(dmarc_m, from_domain) is None)
    if need_record:
        record, record_ok = await lookup_dmarc(from_domain, txt)
    adkim = (record or {}).get("adkim", "r").lower()[:1] or "r"
    aspf = (record or {}).get("aspf", "r").lower()[:1] or "r"
    for entry in report.dkim:
        entry.aligned = aligned(entry.domain, from_domain, adkim)
    spf_aligned = report.spf.result == "pass" and aligned(report.spf.domain, from_domain, aspf)
    dkim_aligned = any(e.result == "pass" and e.aligned for e in report.dkim)
    alignment = {"spf": spf_aligned, "dkim": dkim_aligned}

    if dmarc_m is not None:
        policy = _policy_from_method(dmarc_m, from_domain) or ((record or {}).get("effective_p") if record else None)
        report.dmarc = AuthDMARC(result=_norm_dmarc(dmarc_m.result), policy=policy, alignment=alignment,
                                 source="auth_results")
    elif from_domain and record_ok:
        if record is None:
            report.dmarc = AuthDMARC(result="none", policy=None, alignment=alignment, source="computed")
        else:
            spf_known = report.spf.result not in ("not_checked", "temperror")
            dkim_known = bool(report.dkim) and all(e.result != "not_checked" for e in report.dkim)
            if spf_aligned or dkim_aligned:
                result = "pass"
            elif spf_known and (dkim_known or not sig_values):
                result = "fail"
            else:
                result = "not_checked"  # one of the two checks could not be done: no verdict
            report.dmarc = AuthDMARC(result=result, policy=record.get("effective_p"), alignment=alignment,
                                     source="computed")
    else:
        report.dmarc = AuthDMARC(result="not_checked", policy=None, alignment=alignment, source="none")
    return report
