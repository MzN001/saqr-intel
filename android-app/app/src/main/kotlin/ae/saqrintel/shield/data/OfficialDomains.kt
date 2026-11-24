package ae.saqrintel.shield.data

import java.util.Locale

/**
 * Local list of official UAE domains. Used on the phone only to skip messages whose
 * only links are official (they never leave the phone). Exact or true sub-domain match:
 * `www.adpolice.gov.ae` matches, `adpolice.gov.ae.evil.com` and `myadcb.com` do not.
 */
object OfficialDomains {
    val DOMAINS: Set<String> = setOf(
        "tamm.abudhabi",
        "abudhabi.ae",
        "adpolice.gov.ae",
        "uaepass.ae",
        "emiratespost.ae",
        "icp.gov.ae",
        "adcb.com",
        "bankfab.com",
        "emiratesnbd.com",
        "eand.com",
        "etisalat.ae",
        "du.ae",
        "salik.ae",
    )

    /** Lower-cased host without scheme, port, path, credentials or trailing dot; null if empty. */
    fun normaliseHost(input: String?): String? {
        var s = input?.trim()?.lowercase(Locale.ROOT) ?: return null
        s = s.substringAfter("://", s)
        s = s.substringBefore('/').substringBefore('?').substringBefore('#')
        s = s.substringAfterLast('@')
        if (s.startsWith("[")) return null // IPv6 literal: never official
        s = s.substringBefore(':').trimEnd('.')
        return s.takeIf { it.isNotEmpty() && !it.contains(' ') }
    }

    fun isOfficial(hostOrUrl: String?): Boolean {
        val host = normaliseHost(hostOrUrl) ?: return false
        // Any registered domain under gov.ae (TDRA restricted zone): x.gov.ae, www.x.gov.ae.
        if (host.endsWith(".gov.ae") && host.length > ".gov.ae".length) return true
        return DOMAINS.any { host == it || host.endsWith(".$it") }
    }
}
