"""Shared email-scanning types (frozen contract, section 6). Pure dataclasses: no I/O, no heavy imports.

Producers / consumers:
    email_parse.parse(*, source, text=None, file_bytes=None, file_name=None, html=None, meta=None) -> ParsedEmail
    async email_auth.verify(parsed: ParsedEmail, *, offline: bool | None = None, dnsfunc=None) -> AuthReport

ParsedEmail and AuthReport are consumed by email_rules / email_pipeline. Do not rename fields:
AuthReport.to_dict() must match the "authentication" block of the POST /api/analyze-email response.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class Address:
    display_name: str = ""
    address: str = ""
    domain: str = ""  # lowercased ASCII / punycode (xn--) host part of the address

    def to_dict(self) -> dict[str, Any]:
        return {"display_name": self.display_name, "address": self.address, "domain": self.domain}


@dataclass
class Link:
    href: str
    text: str = ""


@dataclass
class Attachment:
    name: str
    size: int = 0
    content_type: str = ""


@dataclass
class ParsedEmail:
    source: str  # "text" | "raw" | "eml" | "msg" (as in the request)
    has_headers: bool  # real RFC 5322 header block available
    byte_exact: bool  # raw bytes are the original message (DKIM can be verified)
    raw_bytes: Optional[bytes]
    headers: list[tuple[str, str]]  # in order, top first
    subject: str
    date: str
    from_: Address
    reply_to: Optional[Address]
    return_path: Optional[Address]
    sender: Optional[Address]
    to_count: int
    list_id: Optional[str]
    text_body: str
    html_body: str
    links: list[Link]
    attachments: list[Attachment]
    message_id: str = ""
    notes: list[str] = field(default_factory=list)

    def header(self, name: str) -> Optional[str]:
        """First header with this name (case-insensitive), or None."""
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def headers_all(self, name: str) -> list[str]:
        """Every header with this name (case-insensitive), top first."""
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]


@dataclass
class AuthSPF:
    result: str = "not_checked"  # pass|fail|softfail|neutral|none|temperror|permerror|not_checked
    domain: str = ""
    client_ip: str = ""
    source: str = "none"  # computed|auth_results|none

    def to_dict(self) -> dict[str, Any]:
        return {"result": self.result, "domain": self.domain, "client_ip": self.client_ip, "source": self.source}


@dataclass
class AuthDKIM:
    domain: str = ""
    selector: str = ""
    result: str = "not_checked"  # pass|fail|none|not_checked
    aligned: bool = False
    source: str = "verified"  # verified|auth_results

    def to_dict(self) -> dict[str, Any]:
        return {"domain": self.domain, "selector": self.selector, "result": self.result,
                "aligned": self.aligned, "source": self.source}


@dataclass
class AuthDMARC:
    result: str = "not_checked"  # pass|fail|none|not_checked
    policy: Optional[str] = None  # reject|quarantine|none|None
    alignment: dict[str, bool] = field(default_factory=lambda: {"spf": False, "dkim": False})
    source: str = "none"  # computed|auth_results|none

    def to_dict(self) -> dict[str, Any]:
        return {"result": self.result, "policy": self.policy,
                "alignment": {"spf": bool(self.alignment.get("spf")), "dkim": bool(self.alignment.get("dkim"))},
                "source": self.source}


@dataclass
class AuthARC:
    result: str = "none"  # pass|fail|none
    chain_length: int = 0
    # True only when the pass is vouched for by someone we trust: the citizen's own mailbox provider
    # wrote arc=pass in its Authentication-Results, or the newest ARC seal was made by a trusted
    # provider (d=google.com, microsoft.com ...). Anyone can create a VALID ARC seal for any mail, so an
    # untrusted pass proves nothing. Internal: not part of to_dict() (the response contract is frozen).
    trusted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"result": self.result, "chain_length": self.chain_length}


@dataclass
class AuthReport:
    trusted_authserv: Optional[str] = None  # e.g. "mx.google.com"
    spf: AuthSPF = field(default_factory=AuthSPF)
    dkim: list[AuthDKIM] = field(default_factory=list)
    dmarc: AuthDMARC = field(default_factory=AuthDMARC)
    arc: AuthARC = field(default_factory=AuthARC)

    def to_dict(self) -> dict[str, Any]:
        return {"trusted_authserv": self.trusted_authserv, "spf": self.spf.to_dict(),
                "dkim": [d.to_dict() for d in self.dkim], "dmarc": self.dmarc.to_dict(), "arc": self.arc.to_dict()}

    @classmethod
    def not_checked(cls) -> "AuthReport":
        """Nothing could be checked (e.g. pasted visible text with no headers)."""
        return cls(trusted_authserv=None,
                   spf=AuthSPF(result="not_checked", source="none"),
                   dkim=[],
                   dmarc=AuthDMARC(result="not_checked", policy=None, alignment={"spf": False, "dkim": False}, source="none"),
                   arc=AuthARC(result="none", chain_length=0))
