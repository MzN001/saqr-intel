"""Email parsing for the email scanner (workstream A).

One entry point, parse(), turns whatever the citizen (or the browser extension) gave us into a
saqr.intel.email_types.ParsedEmail:

* source="eml"  - an uploaded .eml file. The bytes are kept untouched (byte_exact=True) so DKIM
  signatures can be checked later by email_auth.
* source="raw"  - the full message source pasted into a text box ("Show original" in Gmail,
  "View message source" in Outlook). Line endings are normalised to CRLF; a paste is never
  byte-exact (the browser / clipboard may have changed spaces or encodings).
* source="msg"  - an Outlook .msg file (an OLE "compound file"). Read with olefile straight from the
  __substg1.0_* property streams; the transport-headers property gives us real headers.
* source="text" - the visible text of an email (copied from the screen). Optional leading
  From: / Subject: ... lines (English + Arabic, Gmail / Outlook copy formats) are picked up; there is
  never a real header block (has_headers=False). If the "text" is really the full source it is read
  as raw.
* meta          - what the extension read from the Gmail / Outlook web page (sender, subject,
  links...). It can come alone or together with the raw source.

Design rules:
* Never lose the original Unicode spelling of a domain: Address.address and Link.href keep what the
  email really said (Cyrillic letters, invisible characters...) - the Unicode rules need it.
  Address.domain is the lowercase ASCII / punycode form (what DNS would resolve).
* Inputs larger than 4 MB are refused; unusable input raises ValueError with a message that is safe
  to show to a citizen.
"""
from __future__ import annotations

import io
import logging
import re
import struct
import unicodedata
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser, HeaderParser
from email.utils import getaddresses, parseaddr
from typing import Any, Iterable, Optional
from urllib.parse import unquote, urlsplit

from .email_types import Address, Attachment, Link, ParsedEmail

log = logging.getLogger("saqr.email.parse")

MAX_BYTES = 4 * 1024 * 1024  # decoded size limit (contract: body cap 4 MB)
MAX_LINKS = 100
MAX_ANCHOR_TEXT = 300

SOURCES = ("text", "raw", "eml", "msg")

# File extensions that the bare-domain URL pattern would otherwise mistake for a TLD ("invoice.pdf").
_FILE_EXTS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "rtf", "png", "jpg", "jpeg", "gif",
    "bmp", "webp", "svg", "exe", "html", "htm", "js", "json", "xml", "eml", "msg", "ics", "vcf", "php",
}
_LINK_SCHEMES = ("http://", "https://", "hxxp://", "hxxps://")
_TRAILING_PUNCT = ".,;:!?)]}>\"'"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


# ---------------------------------------------------------------------------
# Small helpers other email modules may reuse
# ---------------------------------------------------------------------------
def ascii_host(host: str) -> str:
    """Lowercase ASCII / punycode form of a host ("pаypal.com" with a Cyrillic а -> "xn--pypal-4ve.com").

    Label by label, so one bad label (e.g. containing a bidi control) does not spoil the others. A label
    that is not a valid IDN, or that IDNA would silently change (invisible characters dropped, fullwidth
    letters folded), is punycoded exactly as written - so a disguised "paypal" never becomes "paypal".
    """
    h = (host or "").strip().strip("[]<>").rstrip(".")
    out: list[str] = []
    for label in h.split("."):
        if not label:
            continue
        if label.isascii():
            out.append(label.lower())
            continue
        try:
            encoded = label.encode("idna").decode("ascii").lower()  # IDNA 2003 + nameprep (stdlib)
            # nameprep silently drops invisible characters (U+200B) and folds fullwidth letters, so
            # "pay<U+200B>pal" would become plain "paypal". Never let a disguised label turn into the
            # real brand: when the round trip does not give the label back, punycode it as written.
            if encoded.encode("ascii").decode("idna") != unicodedata.normalize("NFC", label).lower():
                encoded = "xn--" + label.lower().encode("punycode").decode("ascii")
            out.append(encoded)
            continue
        except UnicodeError:
            pass
        try:
            import idna  # IDNA 2008 / UTS 46 (installed with httpx)

            out.append(idna.encode(label, uts46=True).decode("ascii").lower())
        except Exception:  # noqa: BLE001 - not a valid IDN (e.g. a bidi control): punycode it as written
            try:
                out.append("xn--" + label.lower().encode("punycode").decode("ascii"))
            except UnicodeError:
                out.append(label.lower())
    return ".".join(out)


def unicode_domain(addr: Optional[Address]) -> str:
    """The domain of an address as the email spelled it (Unicode kept), for the "unicode_domain" field."""
    if not addr:
        return ""
    original = addr.address.rpartition("@")[2].strip().rstrip(".") if "@" in addr.address else ""
    if original and not original.isascii():
        return original
    from .domain_intel import to_unicode_host

    return to_unicode_host(addr.domain or original.lower())


def link_host(href: str) -> tuple[str, str]:
    """(ascii_host, original_host) of a link as it appears in the email; ("", "") when there is no host."""
    from .domain_intel import refang

    s = refang(href or "")
    if s.startswith("//"):
        s = "https:" + s
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "http://" + s
    try:
        netloc = urlsplit(s).netloc
    except ValueError:
        return "", ""
    host = netloc.rpartition("@")[2]
    if host.startswith("["):  # IPv6 literal
        host = host.split("]")[0] + "]"
    else:
        host = host.split(":")[0]
    if "%" in host and not re.search(r"[/@?#\\\s%:]", unquote(host)):
        host = unquote(host)  # browsers decode a percent-encoded host ("p%D0%B0ypal.com" opens pаypal.com)
    host = host.strip().rstrip(".")
    return (ascii_host(host), host) if host else ("", "")


def make_address(display_name: str = "", address: str = "") -> Address:
    """Build an Address; domain = lowercase ASCII form of the part after "@"."""
    address = _fix8((address or "").strip())
    domain = ascii_host(address.rpartition("@")[2]) if "@" in address else ""
    return Address(display_name=_fix8((display_name or "").strip()), address=address, domain=domain)


def _parse_address_text(value: str) -> Optional[Address]:
    """Address from free text: 'Name <a@b>', 'Name [mailto:a@b]', 'a@b' or just a name."""
    v = (value or "").strip()
    if not v:
        return None
    m = re.match(r"^(.*?)\s*[<\[](?:mailto:)?([^<>\[\]\s]+@[^<>\[\]\s]+)[>\]]\s*$", v, re.I)
    if m:
        return make_address(m.group(1).strip().strip("\"'"), m.group(2))
    m = re.search(r"[^\s<>\[\]\"',;:]+@[^\s<>\[\]\"',;:]+", v)
    if m:
        name = (v[: m.start()] + v[m.end():]).strip().strip("\"'<>[]()").strip()
        return make_address(name, m.group(0))
    return Address(display_name=v.strip("\"'"), address="", domain="")


# ---------------------------------------------------------------------------
# Link extraction
# ---------------------------------------------------------------------------
def _strip_scheme(href: str) -> str:
    return re.sub(r"^[a-z][a-z0-9+.-]*://", "", href, flags=re.I)


class _LinkCollector:
    """Dedupes links (first occurrence wins, anchors before plain-text links) and caps them at MAX_LINKS."""

    def __init__(self) -> None:
        self.links: list[Link] = []
        self._seen: set[str] = set()
        self._anchor_hosts: set[str] = set()

    def add(self, href: str, text: str = "", *, from_anchor: bool = False) -> None:
        href = (href or "").strip()
        if not href or len(self.links) >= MAX_LINKS:
            return
        key = href.rstrip("/")
        if key in self._seen:
            return
        host, _orig = link_host(href)
        if not host:
            return
        if not from_anchor and host in self._anchor_hosts and "/" not in _strip_scheme(href).rstrip("/"):
            # A bare "www.bank.com" in the text part when the HTML part already links to that site.
            return
        self._seen.add(key)
        if from_anchor:
            self._anchor_hosts.add(host)
        self.links.append(Link(href=href, text=(text or "")[:MAX_ANCHOR_TEXT]))

    def extend(self, links: Iterable[Link]) -> None:
        for link in links:
            self.add(link.href, link.text, from_anchor=True)


def _html_soup(html: str):
    from bs4 import BeautifulSoup

    return BeautifulSoup(html, "html.parser")


def links_from_html(html: str) -> list[Link]:
    """http(s) / www links from <a href> (and <area href>) with their visible text (or image alt text)."""
    if not html:
        return []
    try:
        soup = _html_soup(html)
    except Exception:  # noqa: BLE001 - broken HTML must never break the scan
        return []
    out: list[Link] = []
    for tag in soup.find_all(["a", "area"], href=True):
        href = re.sub(r"\s+", "", str(tag.get("href") or ""))
        low = href.lower()
        if low.startswith("//"):
            href = "https:" + href
        elif not (low.startswith(_LINK_SCHEMES) or low.startswith("www.")):
            continue  # mailto:, tel:, cid:, #anchor, javascript: ...
        text = " ".join(tag.get_text(" ", strip=True).split())
        if not text:
            img = tag.find("img", alt=True)
            text = " ".join(str(img.get("alt") or "").split()) if img else ""
        out.append(Link(href=href, text=text))
    return out


def links_from_text(text: str) -> list[Link]:
    """URLs and bare domains in plain text (refanged), reusing the pipeline's URL pattern."""
    if not text:
        return []
    from ..pipeline import URL_IN_TEXT
    from .domain_intel import _EXTRACT, refang

    out: list[Link] = []
    for m in URL_IN_TEXT.finditer(text):
        raw = re.split(r"[<>\"]", m.group(0))[0].rstrip(_TRAILING_PUNCT)
        if not raw:
            continue
        has_scheme = bool(re.match(r"^(?:hxxps?|https?)://", raw, re.I))
        if not has_scheme:
            start = m.start()
            if start and text[start - 1] in "@./":  # part of an e-mail address / a longer token
                continue
            host = raw.split("/")[0].replace("[.]", ".").lower()
            last = host.rsplit(".", 1)[-1]
            if last in _FILE_EXTS or not _EXTRACT(host).suffix:
                continue
        out.append(Link(href=refang(raw), text=""))
    return out


def html_to_text(html: str) -> str:
    """Readable text of an HTML body (scripts / styles dropped, blank lines collapsed)."""
    if not html:
        return ""
    try:
        soup = _html_soup(html)
        for tag in soup(["script", "style", "head", "title"]):
            tag.decompose()
        text = soup.get_text("\n")
    except Exception:  # noqa: BLE001
        text = re.sub(r"<[^>]+>", " ", html)
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# ---------------------------------------------------------------------------
# RFC 5322 messages (.eml and pasted source)
# ---------------------------------------------------------------------------
_HEADER_LINE = re.compile(r"^[!-9;-~]+:")
_TRANSPORT_HEADERS = re.compile(
    r"^(received|delivered-to|return-path|authentication-results|arc-[a-z-]+|dkim-signature|x-[a-z0-9-]+|"
    r"mime-version|message-id|received-spf)\s*:", re.I)


def _fix8(value: str) -> str:
    """Undo surrogateescape: raw 8-bit (usually UTF-8) header bytes that the stdlib parser left undecoded."""
    if not value or not re.search("[\udc80-\udcff]", value):
        return value
    data = value.encode("utf-8", "surrogateescape")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace")


def _unfold(value: str) -> str:
    return re.sub(r"\r?\n(?=[ \t])", "", value or "").replace("\r", "").replace("\n", " ").strip()


def _header_items(msg: Message) -> list[tuple[str, str]]:
    """Every header, top first, unfolded and RFC 2047-decoded (falls back to the raw text)."""
    out: list[tuple[str, str]] = []
    for name, raw in msg.raw_items():
        try:
            value = str(msg.policy.header_fetch_parse(name, raw))
        except Exception:  # noqa: BLE001 - one odd header must not lose the whole message
            value = str(raw)
        out.append((str(name), _unfold(_fix8(value))))
    return out


def _addresses(msg: Optional[Message], name: str) -> list[Address]:
    if msg is None:
        return []
    try:
        header = msg.get(name)
    except Exception:  # noqa: BLE001
        header = None
    if header is None:
        return []
    out: list[Address] = []
    try:
        for a in getattr(header, "addresses", None) or ():
            addr = a.addr_spec if (a.username or a.domain) else ""
            if addr in ("<>", '""'):
                addr = ""
            out.append(make_address(a.display_name or "", addr))
        if out:
            return out
    except Exception:  # noqa: BLE001 - malformed address header: fall back to the lenient stdlib parser
        out = []
    for display, addr in getaddresses([str(header)]):
        if display or addr:
            out.append(make_address(display, addr))
    return out


def _single_address(msg: Optional[Message], name: str) -> Optional[Address]:
    if msg is None:
        return None
    addrs = _addresses(msg, name)
    if addrs:
        return addrs[0]
    raw = msg.get(name)
    if raw is None:
        return None
    display, addr = parseaddr(str(raw))  # Return-Path is not an address header for the stdlib policy
    if not (display or addr):
        return None
    return make_address(display, addr)


def _part_text(part: Message) -> str:
    """Decoded text of a body part. Undeclared / wrong "us-ascii" 8-bit text is tried as UTF-8 first."""
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:  # noqa: BLE001 - broken transfer encoding
        payload = str(part.get_payload() or "").encode("utf-8", "replace")
    if isinstance(payload, str):
        payload = payload.encode("utf-8", "replace")
    charset = (part.get_content_charset() or "us-ascii").lower()
    if charset in ("us-ascii", "ascii", "ansi_x3.4-1968") and not payload.isascii():
        try:
            return payload.decode("utf-8")
        except UnicodeDecodeError:
            return payload.decode("cp1252", "replace")
    try:
        return payload.decode(charset, "replace")
    except LookupError:  # unknown charset name
        return payload.decode("utf-8", "replace")


def _attachments(msg: Message) -> list[Attachment]:
    out: list[Attachment] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        try:
            name = part.get_filename()
        except Exception:  # noqa: BLE001
            name = None
        disposition = (part.get_content_disposition() or "").lower()
        if not name and disposition != "attachment":
            continue
        try:
            size = len(part.get_payload(decode=True) or b"")
        except Exception:  # noqa: BLE001
            size = 0
        out.append(Attachment(name=str(name or ""), size=size, content_type=part.get_content_type()))
    return out


def _first(headers: list[tuple[str, str]], name: str) -> str:
    n = name.lower()
    for k, v in headers:
        if k.lower() == n:
            return v
    return ""


def _from_message(msg: Message, *, source: str, raw_bytes: Optional[bytes], byte_exact: bool,
                  notes: list[str]) -> ParsedEmail:
    headers = _header_items(msg)
    text_body = html_body = ""
    if isinstance(msg, EmailMessage):
        plain = msg.get_body(preferencelist=("plain",))
        html_part = msg.get_body(preferencelist=("html",))
        text_body = _part_text(plain) if plain is not None else ""
        html_body = _part_text(html_part) if html_part is not None else ""
    if not text_body and html_body:
        text_body = html_to_text(html_body)
        notes.append("The body text was taken from the HTML part.")

    links = _LinkCollector()
    links.extend(links_from_html(html_body))
    for link in links_from_text(text_body):
        links.add(link.href, link.text)

    from_list = _addresses(msg, "From")
    to_count = len([a for a in _addresses(msg, "To") + _addresses(msg, "Cc") if a.address])
    return ParsedEmail(
        source=source,
        has_headers=bool(headers),
        byte_exact=byte_exact,
        raw_bytes=raw_bytes,
        headers=headers,
        subject=_first(headers, "Subject"),
        date=_first(headers, "Date"),
        from_=from_list[0] if from_list else Address(),
        reply_to=_single_address(msg, "Reply-To"),
        return_path=_single_address(msg, "Return-Path"),
        sender=_single_address(msg, "Sender"),
        to_count=to_count,
        list_id=_first(headers, "List-Id") or None,
        text_body=text_body,
        html_body=html_body,
        links=links.links,
        attachments=_attachments(msg),
        message_id=_first(headers, "Message-ID"),
        notes=notes,
    )


def _looks_like_headers(text: str) -> bool:
    """True when the text starts with a real header block (at least 2 header lines before a blank line)."""
    count = 0
    for line in text.splitlines()[:300]:
        if not line.strip():
            break
        if line[:1] in (" ", "\t"):
            continue
        if not _HEADER_LINE.match(line):
            return False
        count += 1
    return count >= 2


_MBOX_FROM = re.compile(rb"^From [^\r\n]*\r?\n")


def _strip_mbox_from(data: bytes) -> bytes:
    """Drop a leading mbox "From sender date" line (Thunderbird .eml, public-inbox /raw): it is not a header."""
    m = _MBOX_FROM.match(data)
    if not m:
        return data
    rest = data[m.end():]
    if not _looks_like_headers(rest[:65536].decode("utf-8", "replace")):
        return data  # a plain-text file that merely starts with "From ..."
    if m.group(0).startswith(b"From mboxrd@z"):
        rest = re.sub(rb"(?m)^>(>*From )", rb"\1", rest)  # undo mboxrd ">From " quoting (DKIM needs the original)
    return rest


def _parse_rfc822(data: bytes, *, source: str, byte_exact: bool, notes: list[str]) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return _from_message(msg, source=source, raw_bytes=data, byte_exact=byte_exact, notes=notes)


# ---------------------------------------------------------------------------
# Pasted visible text
# ---------------------------------------------------------------------------
_LABELS = {
    "from": ("from", "sender", "من", "المرسل"),
    "reply_to": ("reply-to", "reply to", "الرد على", "رد إلى", "الرد إلى"),
    "to": ("to", "إلى", "الى", "إلي"),
    "cc": ("cc", "نسخة", "نسخة إلى"),
    "subject": ("subject", "الموضوع", "موضوع"),
    "date": ("date", "sent", "التاريخ", "تاريخ", "أرسل", "تم الإرسال", "الإرسال"),
    # Shown by Gmail's "show details" box; skipped (pasted text cannot prove them).
    "_ignored": ("mailed-by", "signed-by", "security", "importance", "الأهمية"),
}
_LABEL_RE = re.compile(
    r"^\s*\**\s*(" + "|".join(re.escape(x) for xs in _LABELS.values() for x in sorted(xs, key=len, reverse=True))
    + r")\s*\**\s*[:：]\s*(.*)$", re.I)
_SEPARATOR_RE = re.compile(
    r"^\s*(?:-{2,}\s*(?:forwarded message|original message|الرسالة المعاد توجيهها|الرسالة الأصلية|"
    r"رسالة معاد توجيهها)\s*-{2,}|begin forwarded message:?)\s*$", re.I)
_SENDER_LINE_RE = re.compile(r"^(.{0,120}?)\s*<([^<>\s@]+@[^<>\s]+)>\s*$")
_GMAIL_NOISE_RE = re.compile(r"^(?:to\s+\S.{0,50}|إلى\s+\S.{0,50}|inbox|البريد الوارد|.*\d{1,2}:\d{2}.*)$", re.I)


def _label_key(label: str) -> str:
    low = label.lower()
    for key, names in _LABELS.items():
        if low in names:
            return key
    return "_ignored"


def split_visible_text(text: str) -> tuple[dict[str, str], str]:
    """Pick optional header-like lines off the top of pasted visible text -> (fields, body).

    fields may hold "from", "reply_to", "to", "cc", "subject", "date" (raw strings).
    """
    lines = text.splitlines()
    start = 0
    for i, line in enumerate(lines[:60]):
        if _SEPARATOR_RE.match(line):
            start = i + 1  # a forwarded email: the original sender is in the block after the separator
            break
    fields: dict[str, str] = {}
    i = start
    while i < len(lines) and not lines[i].strip():
        i += 1
    j = i
    while j < len(lines) and j - i < 20:
        line = lines[j]
        if not line.strip():
            if fields:
                break
            j += 1
            continue
        m = _LABEL_RE.match(line)
        if not m:
            break
        key = _label_key(m.group(1))
        if key != "_ignored" and key not in fields:
            fields[key] = m.group(2).strip()
        j += 1
    if fields:
        return fields, "\n".join(lines[j:]).strip()
    if start:
        return {}, "\n".join(lines[start:]).strip()

    # Gmail "opened email" copy: subject line, maybe "Inbox", then "Name <address>", "to me", a time ...
    nonblank = [(k, line.strip()) for k, line in enumerate(lines) if line.strip()][:8]
    for pos, (k, line) in enumerate(nonblank):
        if not _SENDER_LINE_RE.match(line):
            continue
        fields["from"] = line
        if pos > 0 and "@" not in nonblank[0][1]:
            fields["subject"] = nonblank[0][1]
        body_lines = lines[k + 1:]
        drop = 0  # the short "to me" / time-stamp lines Gmail shows right under the sender
        for line2 in body_lines[:6]:
            s = line2.strip()
            if not s or (len(s) < 60 and _GMAIL_NOISE_RE.match(s)):
                drop += 1
                continue
            break
        return fields, "\n".join(body_lines[drop:]).strip()
    return {}, text.strip()


def _count_recipients(value: str) -> int:
    return len([p for p in re.split(r"[,;؛،]", value or "") if p.strip()])


def _from_visible_text(text: str, *, source: str, notes: list[str]) -> ParsedEmail:
    fields, body = split_visible_text(text)
    links = _LinkCollector()
    for link in links_from_text(body):
        links.add(link.href, link.text)
    return ParsedEmail(
        source=source,
        has_headers=False,
        byte_exact=False,
        raw_bytes=None,
        headers=[],
        subject=fields.get("subject", ""),
        date=fields.get("date", ""),
        from_=_parse_address_text(fields.get("from", "")) or Address(),
        reply_to=_parse_address_text(fields.get("reply_to", "")),
        return_path=None,
        sender=None,
        to_count=_count_recipients(fields.get("to", "")) + _count_recipients(fields.get("cc", "")),
        list_id=None,
        text_body=body,
        html_body="",
        links=links.links,
        attachments=[],
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Outlook .msg (OLE compound file, MS-OXMSG)
# ---------------------------------------------------------------------------
PT_UNICODE = "001F"
PT_STRING8 = "001E"
PT_BINARY = "0102"
_PROP = "__substg1.0_"
_ATTACH_PREFIX = "__attach_version1.0_#"
_RECIP_PREFIX = "__recip_version1.0_#"


def decode_msg_string(data: bytes, prop_type: str, codepage: str = "cp1252") -> str:
    """Decode one string property stream: 001F = UTF-16LE, 001E = 8-bit (UTF-8 if valid, else the code page)."""
    if prop_type == PT_UNICODE:
        text = data.decode("utf-16-le", "replace")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                text = data.decode(codepage, "replace")
            except LookupError:
                text = data.decode("cp1252", "replace")
    return text.split("\x00", 1)[0]


def decode_msg_html(data: bytes) -> str:
    """HTML property (often binary 0102): honour a <meta charset>, else UTF-8, else Windows-1252."""
    m = re.search(rb"charset\s*=\s*[\"']?([A-Za-z0-9_.:-]+)", data[:4096], re.I)
    if m:
        try:
            return data.decode(m.group(1).decode("ascii"), "replace").rstrip("\x00")
        except LookupError:
            pass
    try:
        return data.decode("utf-8").rstrip("\x00")
    except UnicodeDecodeError:
        return data.decode("cp1252", "replace").rstrip("\x00")


def filetime_to_iso(value: int) -> str:
    """Windows FILETIME (100 ns steps since 1601) -> ISO 8601 UTC; "" when out of range."""
    if not value:
        return ""
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=value // 10)).isoformat()
    except (OverflowError, ValueError):
        return ""


class _MsgReader:
    """Reads MAPI properties from an olefile.OleFileIO."""

    def __init__(self, ole: Any) -> None:
        self.ole = ole
        self.entries = [tuple(e) for e in ole.listdir(streams=True, storages=True)]

    def _stream(self, path: tuple[str, ...]) -> Optional[bytes]:
        name = "/".join(path)
        try:
            if self.ole.exists(name) and self.ole.get_type(name) == 2:  # STGTY_STREAM
                return self.ole.openstream(name).read()
        except Exception:  # noqa: BLE001 - damaged stream
            return None
        return None

    def raw(self, prop: str, base: tuple[str, ...] = ()) -> tuple[Optional[bytes], str]:
        for ptype in (PT_UNICODE, PT_STRING8, PT_BINARY):
            data = self._stream(base + (f"{_PROP}{prop.upper()}{ptype}",))
            if data is not None:
                return data, ptype
        return None, ""

    def text(self, prop: str, base: tuple[str, ...] = ()) -> str:
        data, ptype = self.raw(prop, base)
        if data is None:
            return ""
        if ptype == PT_BINARY:
            return decode_msg_html(data)
        return decode_msg_string(data, ptype).strip()

    def storages(self, prefix: str) -> list[str]:
        return sorted({e[0] for e in self.entries if e and e[0].startswith(prefix)})

    def size(self, path: tuple[str, ...]) -> int:
        try:
            return int(self.ole.get_size("/".join(path)))
        except Exception:  # noqa: BLE001
            return 0

    def submit_time(self) -> str:
        """PidTagClientSubmitTime (0x0039) from the fixed-size property stream, as ISO 8601."""
        data = self._stream(("__properties_version1.0",))
        if not data or len(data) < 48:
            return ""
        for off in range(32, len(data) - 15, 16):  # 32-byte header for the top-level message
            tag, _flags, value = struct.unpack_from("<IIQ", data, off)
            if tag == 0x00390040:
                return filetime_to_iso(value)
        return ""


def _first_smtp(*values: str) -> str:
    for v in values:
        v = (v or "").strip()
        if "@" in v and not v.lower().startswith("/o="):  # skip Exchange X.500 names
            return v
    return ""


def _from_msg(data: bytes, *, notes: list[str]) -> ParsedEmail:
    try:
        import olefile
    except ImportError as exc:  # pragma: no cover - dependency missing
        raise ValueError("Outlook .msg files cannot be read on this server. Please upload a .eml file.") from exc
    if not data.startswith(_OLE_MAGIC) or not olefile.isOleFile(io.BytesIO(data)):
        raise ValueError("This file is not an Outlook .msg email.")
    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise ValueError("This Outlook .msg file is damaged and cannot be read.") from exc
    try:
        r = _MsgReader(ole)
        transport = r.text("007D")
        headers: list[tuple[str, str]] = []
        hmsg: Optional[Message] = None
        if transport.strip():
            hmsg = HeaderParser(policy=policy.default).parsestr(transport.lstrip() + "\n\n")
            headers = _header_items(hmsg)
        else:
            notes.append("This .msg file has no internet headers (for example a draft or a sent item), "
                         "so the sender could not be authenticated.")

        from_list = _addresses(hmsg, "From")
        if from_list:
            from_ = from_list[0]
        else:
            name = r.text("0C1A") or r.text("0042")
            addr = _first_smtp(r.text("5D01"), r.text("0C1F"), r.text("5D02"), r.text("0065"))
            from_ = make_address(name, addr)

        text_body = r.text("1000")
        html_body = r.text("1013")
        if not text_body and not html_body:
            rtf, _ = r.raw("1009")
            if rtf is not None:
                notes.append("This .msg file only has a formatted (RTF) body, which is not read; "
                             "the sender details and attachments were still checked.")
        if not text_body and html_body:
            text_body = html_to_text(html_body)

        links = _LinkCollector()
        links.extend(links_from_html(html_body))
        for link in links_from_text(text_body):
            links.add(link.href, link.text)

        attachments: list[Attachment] = []
        for storage in r.storages(_ATTACH_PREFIX):
            base = (storage,)
            name = r.text("3707", base) or r.text("3704", base) or r.text("3001", base)
            size = r.size(base + (f"{_PROP}37010102",))
            attachments.append(Attachment(name=name, size=size, content_type=r.text("370E", base)))

        if hmsg is not None and (_first(headers, "To") or _first(headers, "Cc")):
            to_count = len([a for a in _addresses(hmsg, "To") + _addresses(hmsg, "Cc") if a.address])
        else:
            to_count = len(r.storages(_RECIP_PREFIX))

        return ParsedEmail(
            source="msg",
            has_headers=bool(headers),
            byte_exact=False,
            raw_bytes=None,
            headers=headers,
            subject=_first(headers, "Subject") or r.text("0037"),
            date=_first(headers, "Date") or r.submit_time(),
            from_=from_,
            reply_to=_single_address(hmsg, "Reply-To"),
            return_path=_single_address(hmsg, "Return-Path"),
            sender=_single_address(hmsg, "Sender"),
            to_count=to_count,
            list_id=_first(headers, "List-Id") or None,
            text_body=text_body,
            html_body=html_body,
            links=links.links,
            attachments=attachments,
            message_id=_first(headers, "Message-ID") or r.text("1035"),
            notes=notes,
        )
    finally:
        ole.close()


# ---------------------------------------------------------------------------
# Extension DOM capture ("meta")
# ---------------------------------------------------------------------------
def _meta_get(meta: Any, key: str, default: Any = None) -> Any:
    if meta is None:
        return default
    if isinstance(meta, dict):
        return meta.get(key, default)
    return getattr(meta, key, default)


def _meta_items(value: Any) -> list[dict[str, Any]]:
    out = []
    for item in value or []:
        if isinstance(item, dict):
            out.append(item)
        elif hasattr(item, "model_dump"):
            out.append(item.model_dump())
        elif hasattr(item, "__dict__"):
            out.append(dict(vars(item)))
    return out


def _merge_meta(parsed: ParsedEmail, meta: Any, *, prefer_meta: bool) -> ParsedEmail:
    """Fill / override fields with what the extension saw on the page.

    With a real header block the headers win (prefer_meta=False); for pasted text the page's sender
    and subject are more reliable than our guess from the text.
    """
    if meta is None:
        return parsed
    from_name = str(_meta_get(meta, "from_name") or "")
    from_address = str(_meta_get(meta, "from_address") or "")
    if (from_address or from_name) and (prefer_meta or not parsed.from_.address):
        parsed.from_ = make_address(from_name or parsed.from_.display_name, from_address or parsed.from_.address)
    reply_to = str(_meta_get(meta, "reply_to") or "")
    if reply_to and (prefer_meta or parsed.reply_to is None):
        parsed.reply_to = _parse_address_text(reply_to)
    for key in ("subject", "date"):
        val = str(_meta_get(meta, key) or "")
        if val and (prefer_meta or not getattr(parsed, key)):
            setattr(parsed, key, val)
    body = str(_meta_get(meta, "body_text") or "")
    if body and (prefer_meta or not parsed.text_body):
        parsed.text_body = body

    links = _LinkCollector()
    links.extend(parsed.links)
    for item in _meta_items(_meta_get(meta, "links")):
        links.add(str(item.get("href") or ""), str(item.get("text") or ""), from_anchor=True)
    for link in links_from_text(body):
        links.add(link.href, link.text)
    parsed.links = links.links

    if not parsed.attachments:
        attachments = []
        for a in _meta_items(_meta_get(meta, "attachments")):
            if not a.get("name"):
                continue
            try:
                size = int(a.get("size") or 0)
            except (TypeError, ValueError):
                size = 0
            attachments.append(Attachment(name=str(a["name"]), size=size))
        parsed.attachments = attachments
    return parsed


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def _too_big() -> ValueError:
    return ValueError("This email is too large to check (the limit is 4 MB).")


def _empty(source: str, notes: list[str]) -> ParsedEmail:
    return ParsedEmail(source=source, has_headers=False, byte_exact=False, raw_bytes=None, headers=[],
                       subject="", date="", from_=Address(), reply_to=None, return_path=None, sender=None,
                       to_count=0, list_id=None, text_body="", html_body="", links=[], attachments=[],
                       notes=notes)


def parse(*, source: str, text: Optional[str] = None, file_bytes: Optional[bytes] = None,
          file_name: Optional[str] = None, html: Optional[str] = None, meta: Any = None) -> ParsedEmail:
    """Turn the citizen's input into a ParsedEmail. Raises ValueError (citizen-safe message) on unusable input.

    file_name is only a hint (an Outlook file renamed to .eml is still read as .msg).
    """
    source = (source or "").strip().lower()
    if source not in SOURCES:
        raise ValueError("Unknown email source. Use text, raw, eml or msg.")
    for value in (file_bytes, text, html):
        if value is not None and len(value) > MAX_BYTES:  # chars <= bytes: a quick, safe pre-check
            raise _too_big()
    notes: list[str] = []
    parsed: Optional[ParsedEmail] = None

    if source == "eml" and not file_bytes and text:
        file_bytes = text.encode("utf-8", "replace")  # an .eml the client read as text
    if source in ("eml", "msg") and not file_bytes and meta is None and not html:
        raise ValueError("Please choose an email file to upload.")

    if file_bytes and (source == "msg" or file_bytes.startswith(_OLE_MAGIC)
                       or (file_name or "").lower().endswith(".msg")):
        if file_bytes.startswith(_OLE_MAGIC) or source == "msg":
            parsed = _from_msg(file_bytes, notes=notes)
    if parsed is None and file_bytes and source in ("eml", "msg"):
        file_bytes = _strip_mbox_from(file_bytes)
        head = file_bytes[:65536].decode("utf-8", "replace").lstrip("﻿")
        if _looks_like_headers(head):
            parsed = _parse_rfc822(file_bytes, source=source, byte_exact=True, notes=notes)
        else:
            notes.append("The file has no email header block; it was read as plain text.")
            parsed = _from_visible_text(file_bytes.decode("utf-8", "replace"), source=source, notes=notes)
    elif parsed is None and source in ("raw", "text") and text and text.strip():
        stripped = text.lstrip("﻿ \t\r\n")
        if stripped.startswith("From ") and _looks_like_headers(stripped.partition("\n")[2]):
            stripped = stripped.partition("\n")[2]  # mbox "From sender date" line before the headers
        is_raw = _looks_like_headers(stripped) and (
            source == "raw" or _TRANSPORT_HEADERS.match(stripped) is not None)
        if is_raw:
            data = re.sub(r"\r\n|\r|\n", "\r\n", stripped).encode("utf-8", "replace")
            if len(data) > MAX_BYTES:
                raise _too_big()
            if source == "text":
                notes.append("The pasted text looked like the full email source and was read as such.")
            parsed = _parse_rfc822(data, source=source, byte_exact=False, notes=notes)
        else:
            if source == "raw":
                notes.append("No email header block was found; the text was read as the visible email.")
            parsed = _from_visible_text(stripped, source=source, notes=notes)

    if parsed is None:
        if meta is None and not html:
            raise ValueError("Please paste the email text or upload the email file.")
        parsed = _empty(source, notes)

    if html:
        # Extra HTML (e.g. the message body the extension read from the page).
        collector = _LinkCollector()
        collector.extend(parsed.links)
        collector.extend(links_from_html(html))
        parsed.links = collector.links
        if not parsed.html_body:
            parsed.html_body = html
        if not parsed.text_body:
            parsed.text_body = html_to_text(html)

    parsed = _merge_meta(parsed, meta, prefer_meta=not parsed.has_headers)
    if not (parsed.has_headers or parsed.text_body.strip() or parsed.from_.address or parsed.subject
            or parsed.links or parsed.attachments):
        raise ValueError("This email looks empty, so there is nothing to check.")
    return parsed
