package ae.saqrintel.shield.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Wire models for the SAQR-INTEL API. The server adds fields often, so every field is
 * nullable or defaulted and unknown keys are ignored. A response that still fails to decode
 * becomes [ApiResult.Failed], never a crash.
 */
val ApiJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    coerceInputValues = true
    isLenient = true
}

@Serializable
data class RedFlagDto(
    val code: String? = null,
    val severity: String? = null,
    val points: Double? = null,
    val en: String? = null,
    val ar: String? = null,
)

@Serializable
data class LinkDto(
    val url: String? = null,
    val domain: String? = null,
    val official: Boolean? = null,
    val scanned: Boolean? = null,
    val verdict: String? = null,
    @SerialName("risk_score") val riskScore: Double? = null,
)

@Serializable
data class PhoneDto(
    val masked: String? = null,
    val status: String? = null,
    val level: String? = null,
    @SerialName("line_type") val lineType: String? = null,
)

@Serializable
data class SenderDto(
    val type: String? = null,
    val masked: String? = null,
    val status: String? = null,
)

@Serializable
data class MessageDto(
    val excerpt: String? = null,
    val sender: SenderDto? = null,
    @SerialName("credential_requests") val credentialRequests: List<String>? = null,
)

@Serializable
data class ListingDto(
    val name: String? = null,
    @SerialName("website_domain") val websiteDomain: String? = null,
    @SerialName("website_host") val websiteHost: String? = null,
)

/** Shared shape of analyze-url / analyze-message / analyze-email / scan-maps responses. */
@Serializable
data class ScanResponse(
    @SerialName("scan_id") val scanId: String? = null,
    val kind: String? = null,
    val domain: String? = null,
    @SerialName("input_domain") val inputDomain: String? = null,
    val verdict: String? = null,
    @SerialName("risk_score") val riskScore: Double? = null,
    @SerialName("impersonated_entity") val impersonatedEntity: String? = null,
    @SerialName("impersonated_entity_ar") val impersonatedEntityAr: String? = null,
    @SerialName("claimed_entity") val claimedEntity: String? = null,
    @SerialName("claimed_entity_ar") val claimedEntityAr: String? = null,
    @SerialName("official_domains") val officialDomains: List<String>? = null,
    @SerialName("verified_official") val verifiedOfficial: Boolean? = null,
    @SerialName("citizen_explanation_en") val explanationEn: String? = null,
    @SerialName("citizen_explanation_ar") val explanationAr: String? = null,
    @SerialName("red_flags") val redFlags: List<RedFlagDto>? = null,
    val message: MessageDto? = null,
    val links: List<LinkDto>? = null,
    val phones: List<PhoneDto>? = null,
    val listing: ListingDto? = null,
)

@Serializable
data class PhoneReasonDto(
    val code: String? = null,
    val en: String? = null,
    val ar: String? = null,
)

@Serializable
data class EntityDto(
    val id: String? = null,
    @SerialName("name_en") val nameEn: String? = null,
    @SerialName("name_ar") val nameAr: String? = null,
    @SerialName("official_domains") val officialDomains: List<String>? = null,
    @SerialName("official_phones_display") val officialPhonesDisplay: List<String>? = null,
)

/** POST /api/check-phone */
@Serializable
data class PhoneCheckResponse(
    val phone: String? = null,
    val normalized: String? = null,
    val status: String? = null,
    val level: String? = null,
    val entity: EntityDto? = null,
    val reasons: List<PhoneReasonDto>? = null,
    @SerialName("line_type") val lineType: String? = null,
    @SerialName("verified_official") val verifiedOfficial: Boolean? = null,
)

@Serializable
data class FalseAlarmResponse(
    val ok: Boolean? = null,
    val id: String? = null,
    val status: String? = null,
)

@Serializable
data class XAlertLogResponse(
    val ok: Boolean? = null,
    @SerialName("x_alerts_dispatched") val dispatched: Int? = null,
)

@Serializable
data class HealthResponse(
    val status: String? = null,
    val version: String? = null,
)
