package ae.saqrintel.shield.data

import kotlin.math.roundToInt

/** The three verdict bands the backend uses (SAFE < 30, SUSPICIOUS 30-64, HIGH-RISK SCAM >= 65). */
enum class Verdict(val wire: String) {
    SAFE("SAFE"),
    SUSPICIOUS("SUSPICIOUS"),
    SCAM("HIGH-RISK SCAM");

    companion object {
        fun fromScore(score: Int): Verdict = when {
            score >= 65 -> SCAM
            score >= 30 -> SUSPICIOUS
            else -> SAFE
        }

        /** Exact wire string first; falls back to the score band. */
        fun parse(wire: String?, score: Int?): Verdict =
            entries.firstOrNull { it.wire.equals(wire?.trim(), ignoreCase = true) }
                ?: fromScore(score ?: 0)
    }
}

/** What was checked. Also decides the X wording ("links" / "text messages" / "emails"). */
enum class ScanKind { WEB, MAPS, MESSAGE, EMAIL, PHONE }

data class Reason(val code: String?, val en: String, val ar: String, val points: Int = 0)

data class FoundLink(val domain: String, val verdict: Verdict?, val score: Int?, val official: Boolean)

data class FoundPhone(val masked: String, val level: String?)

/** One result, ready for [ae.saqrintel.shield.ui.verdict.VerdictSheet]. Built from any endpoint. */
data class VerdictInfo(
    val kind: ScanKind,
    val scanId: String?,
    val verdict: Verdict,
    /** 0-100; null for phone checks (they return a level, not a score). */
    val score: Int?,
    /** The suspicious (or checked) domain, plain (not defanged). */
    val domain: String?,
    val entityEn: String?,
    val entityAr: String?,
    val officialDomain: String?,
    val verifiedOfficial: Boolean,
    /** Highest-points first, at most 3. */
    val reasons: List<Reason>,
    val allFlags: List<Reason> = reasons,
    val links: List<FoundLink> = emptyList(),
    val phones: List<FoundPhone> = emptyList(),
    val credentialRequest: Boolean = false,
    /** Phone checks: official | none | caution | danger. */
    val phoneLevel: String? = null,
    val detectedAt: Long = System.currentTimeMillis(),
) {
    /** X warning is offered only for a non-safe result with score >= 60 (same rule as the web app). */
    val xEligible: Boolean get() = verdict != Verdict.SAFE && (score ?: 0) >= 60
}

private fun Double?.toScore(): Int? = this?.takeIf { !it.isNaN() }?.roundToInt()?.coerceIn(0, 100)

private fun flagsOf(dto: List<RedFlagDto>?): List<Reason> =
    dto.orEmpty()
        .mapNotNull { f ->
            val en = f.en?.trim().orEmpty()
            if (en.isEmpty() || (f.points ?: 0.0) <= 0.0) null
            else Reason(f.code, en, f.ar?.trim().takeUnless { it.isNullOrEmpty() } ?: en, (f.points ?: 0.0).roundToInt())
        }
        .sortedByDescending { it.points }

fun ScanResponse.toVerdictInfo(kind: ScanKind): VerdictInfo {
    val score = riskScore.toScore() ?: 0
    val verdict = Verdict.parse(this.verdict, score)
    val flags = flagsOf(redFlags)
    val explanation = explanationEn?.trim().takeUnless { it.isNullOrEmpty() }
        ?.let { listOf(Reason(null, it, explanationAr?.trim().takeUnless { a -> a.isNullOrEmpty() } ?: it)) }
        .orEmpty()
    val found = links.orEmpty().mapNotNull { l ->
        val d = l.domain?.trim()?.lowercase()
        if (d.isNullOrEmpty()) null
        else FoundLink(d, l.verdict?.let { Verdict.parse(it, l.riskScore.toScore()) }, l.riskScore.toScore(),
            l.official == true || OfficialDomains.isOfficial(d))
    }.distinctBy { it.domain }
    val worstLink = found.filter { !it.official }.maxByOrNull { it.score ?: -1 }
    val shownDomain = when (kind) {
        ScanKind.WEB -> domain ?: inputDomain
        ScanKind.MAPS -> listing?.websiteDomain ?: listing?.websiteHost ?: domain
        ScanKind.MESSAGE, ScanKind.EMAIL -> worstLink?.domain
        ScanKind.PHONE -> null
    }?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
    return VerdictInfo(
        kind = kind,
        scanId = scanId?.takeIf { it.isNotBlank() },
        verdict = verdict,
        score = score,
        domain = shownDomain,
        entityEn = impersonatedEntity ?: claimedEntity.takeIf { verdict != Verdict.SAFE },
        entityAr = impersonatedEntityAr ?: claimedEntityAr.takeIf { verdict != Verdict.SAFE },
        officialDomain = officialDomains.orEmpty().firstOrNull { it.isNotBlank() },
        verifiedOfficial = verifiedOfficial == true,
        reasons = (flags.ifEmpty { explanation }).take(3),
        allFlags = flags,
        links = found,
        phones = phones.orEmpty().mapNotNull { p -> p.masked?.takeIf { it.isNotBlank() }?.let { FoundPhone(it, p.level) } },
        credentialRequest = !message?.credentialRequests.isNullOrEmpty(),
    )
}

fun PhoneCheckResponse.toVerdictInfo(): VerdictInfo {
    val verdict = when (level?.lowercase()) {
        "danger" -> Verdict.SCAM
        "caution" -> Verdict.SUSPICIOUS
        else -> Verdict.SAFE
    }
    val reasons = reasons.orEmpty().mapNotNull { r ->
        val en = r.en?.trim().orEmpty()
        if (en.isEmpty()) null else Reason(r.code, en, r.ar?.trim().takeUnless { it.isNullOrEmpty() } ?: en)
    }
    return VerdictInfo(
        kind = ScanKind.PHONE,
        scanId = null,
        verdict = verdict,
        score = null,
        domain = null,
        entityEn = entity?.nameEn,
        entityAr = entity?.nameAr,
        officialDomain = entity?.officialDomains.orEmpty().firstOrNull(),
        verifiedOfficial = verifiedOfficial == true,
        reasons = reasons.take(3),
        allFlags = reasons,
        phoneLevel = level,
    )
}
