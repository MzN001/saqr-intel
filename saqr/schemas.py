"""Request models (responses are rich JSON documents described in README)."""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, Field, SecretStr, model_validator

Interception = Literal["MOBILE_OS_SHARE_SHEET", "AUTO_TELECOM_DNS", "AUTO_SMS_GUARD", "CITIZEN_MANUAL_CHECK",
                       "PC_BROWSER_EXTENSION", "ANDROID_APP_GUARD", "DIRECT_API", "MANUAL", "PROACTIVE_HUNTER"]
Channel = Literal["sms", "whatsapp", "email", "social", "web", "call", "maps", "other"]


class AnalyzeURLRequest(BaseModel):
    url: str | None = Field(None, max_length=2048, examples=["https://tamm-smart-pay.net/refund"])
    message_text: str | None = Field(None, max_length=4000,
                                     description="Optional SMS/WhatsApp text; a URL is extracted if `url` is empty.")
    channel: Channel | None = "web"
    reporter_id: str | None = Field(None, max_length=128, description="Pseudonymous citizen id (no PII).")
    run_sandbox: bool = True
    device_profile: Literal["mobile", "desktop"] = "mobile"
    use_llm: bool = True
    include_screenshot: bool = True
    interception_channel: Interception = Field(
        "DIRECT_API", description="How the link reached SAQR-INTEL (share sheet, telecom DNS shield, SMS guard, …).")

    @model_validator(mode="after")
    def _need_target(self) -> "AnalyzeURLRequest":
        if not self.url and not self.message_text:
            raise ValueError("Provide `url` or `message_text`")
        return self


class AnalyzeMessageRequest(BaseModel):
    """An SMS / WhatsApp message a citizen pasted (POST /api/analyze-message)."""
    text: str = Field(..., min_length=1, max_length=4000,
                      examples=["TAMM: You have an unpaid fine of AED 350. Pay today at tamm-smart-pay.net/fine"])
    sender: str | None = Field(None, max_length=64, description="Sender phone number or alphanumeric sender id.",
                               examples=["+971 50 000 7781", "ADPolice"])
    channel: Channel | None = "sms"
    reporter_id: str | None = Field(None, max_length=128, description="Pseudonymous citizen id (no PII).")
    use_llm: bool = True
    follow_links: bool = True
    interception_channel: Interception = "DIRECT_API"

    @model_validator(mode="after")
    def _need_text(self) -> "AnalyzeMessageRequest":
        if not self.text.strip():
            raise ValueError("Provide the message `text`")
        return self


class ScanMapsRequest(BaseModel):
    maps_url: str | None = Field(None, max_length=2048,
                                 examples=["https://www.google.com/maps/place/Abu+Dhabi+Police+Fines/@24.3489,54.5052,17z"])
    business_name: str | None = Field(None, max_length=200)
    query: str | None = Field(None, max_length=200, description="Free text or 'lat,lng'")
    website: str | None = Field(None, max_length=512)
    phone: str | None = Field(None, max_length=32)
    lat: float | None = Field(None, ge=-90, le=90)
    lng: float | None = Field(None, ge=-180, le=180)
    reporter_id: str | None = Field(None, max_length=128)
    interception_channel: Interception = "DIRECT_API"

    @model_validator(mode="after")
    def _need_target(self) -> "ScanMapsRequest":
        if not any([self.maps_url, self.business_name, self.query, self.lat is not None]):
            raise ValueError("Provide maps_url, business_name, query or coordinates")
        return self


class TakedownRequest(BaseModel):
    officer_id: str | None = Field(None, max_length=64)



# ---------------------------------------------------------------------------
# POST /api/analyze-email (email workstream B; frozen contract section 1)
# ---------------------------------------------------------------------------
class EmailLink(BaseModel):
    href: str = Field("", max_length=4096)
    text: str = Field("", max_length=2000)


class EmailAttachmentMeta(BaseModel):
    name: str = Field("", max_length=512)
    size: int = Field(0, ge=0)


class EmailMeta(BaseModel):
    """What the browser extension saw on the page (Gmail / Outlook DOM capture)."""
    provider: str | None = Field(None, max_length=32, examples=["gmail"])
    message_key: str | None = Field(None, max_length=128, description="sha256 of provider + message id")
    from_name: str = Field("", max_length=512)
    from_address: str = Field("", max_length=512)
    reply_to: str | None = Field(None, max_length=512)
    subject: str = Field("", max_length=2000)
    date: str | None = Field(None, max_length=128)
    body_text: str = Field("", max_length=200_000)
    links: list[EmailLink] = Field(default_factory=list, max_length=100)
    attachments: list[EmailAttachmentMeta] = Field(default_factory=list, max_length=100)


class UserLLMConfig(BaseModel):
    """Optional personal OpenAI-compatible AI model. Used for this one request only: never stored,
    logged or echoed. The key is a SecretStr so it never shows up in reprs or error messages."""
    base_url: str = Field("", max_length=512, examples=["https://api.openai.com/v1"])
    api_key: SecretStr = Field(SecretStr(""), max_length=512)
    model: str = Field("", max_length=128, examples=["gpt-4o-mini"])

    def to_cfg(self) -> dict[str, str]:
        return {"base_url": self.base_url, "api_key": self.api_key.get_secret_value(), "model": self.model}


class AnalyzeEmailRequest(BaseModel):
    source: Literal["text", "raw", "eml", "msg"] = Field(
        "text", description="text: pasted visible text; raw: pasted full source in 'text'; "
                            "eml|msg: the file in 'file_base64'.")
    text: str | None = Field(None, max_length=200_000)
    file_base64: str | None = Field(None, max_length=4_000_000)
    file_name: str | None = Field(None, max_length=255)
    html: str | None = Field(None, max_length=300_000)
    meta: EmailMeta | None = None
    channel: Channel | None = "email"
    reporter_id: str | None = Field(None, max_length=128, description="Pseudonymous citizen id (no PII).")
    interception_channel: Interception = "DIRECT_API"
    use_llm: bool = True
    follow_links: bool = True
    use_user_model: bool = True
    llm: UserLLMConfig | None = None

    @model_validator(mode="after")
    def _need_input(self) -> "AnalyzeEmailRequest":
        if not (self.text or self.file_base64 or self.meta):
            raise ValueError("Provide the email as 'text', 'file_base64' or 'meta'")
        return self


# ---------------------------------------------------------------------------
# POST /api/batch-verdict and /api/check-phone (pre-click badges on search results, ads and Maps)
# ---------------------------------------------------------------------------
class BatchVerdictRequest(BaseModel):
    urls: list[Annotated[str, Field(max_length=2048)]] = Field(
        ..., min_length=1, max_length=200,
        examples=[["https://tamm-smart-pay.net/refund", "https://www.tamm.abudhabi/"]])
    expand: bool = Field(False, description="Also expand URL shorteners over the network (small time budget).")


class CheckPhoneRequest(BaseModel):
    phone: str = Field(..., min_length=3, max_length=40, examples=["+971 50 000 7781"])
    claimed_entity: str | None = Field(None, max_length=200, examples=["TAMM Service Center"],
                                       description="The institution the ad / Maps card claims to be.")
    context: Literal["ad", "maps", "panel", "result"] | None = Field(
        None, description="Where the number was shown: a sponsored ad (a wrong number there is treated as "
                          "a fake helpline), a Maps card, a knowledge panel or an organic result.")
