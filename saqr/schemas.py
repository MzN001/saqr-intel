"""Request models (responses are rich JSON documents described in README)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, model_validator

Interception = Literal["MOBILE_OS_SHARE_SHEET", "AUTO_TELECOM_DNS", "AUTO_SMS_GUARD", "CITIZEN_MANUAL_CHECK", "MANUAL"]
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
    interception_channel: Interception | None = Field(
        None, description="How the link reached SAQR-INTEL (share sheet, telecom DNS shield, SMS guard).")

    @model_validator(mode="after")
    def _need_target(self) -> "AnalyzeURLRequest":
        if not self.url and not self.message_text:
            raise ValueError("Provide `url` or `message_text`")
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
    interception_channel: Interception | None = None

    @model_validator(mode="after")
    def _need_target(self) -> "ScanMapsRequest":
        if not any([self.maps_url, self.business_name, self.query, self.lat is not None]):
            raise ValueError("Provide maps_url, business_name, query or coordinates")
        return self


class TakedownRequest(BaseModel):
    officer_id: str | None = Field(None, max_length=64)
