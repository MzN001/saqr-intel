package ae.saqrintel.shield.guard

import ae.saqrintel.shield.data.OfficialDomains
import ae.saqrintel.shield.data.Verdict
import java.util.Locale

/**
 * Pure rules of the web blocker (no Android types, unit-tested): how the text of a browser's
 * address bar becomes a URL, which URLs are never sent to the server, the per-URL cooldown /
 * per-host de-duplication, and the block / caution thresholds. Mirrors extension/background.js.
 */
object WebGuardPolicy {

    /** Browsers the blocker reads, with the view ids of their address bar (in lookup order). */
    val URL_BAR_IDS: Map<String, List<String>> = mapOf(
        "com.android.chrome" to listOf("com.android.chrome:id/url_bar"),
        "com.sec.android.app.sbrowser" to listOf("com.sec.android.app.sbrowser:id/location_bar_edit_text"),
        "org.mozilla.firefox" to listOf(
            "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
            "org.mozilla.firefox:id/url_bar_title",
        ),
        "com.microsoft.emmx" to listOf("com.microsoft.emmx:id/url_bar"),
    )

    const val COOLDOWN_MS = 5_000L
    const val BLOCK_SCORE = 65
    const val SUSPICIOUS_SCORE = 30
    const val FAST_TIMEOUT_MS = 15_000L
    const val DEEP_TIMEOUT_MS = 75_000L
    const val MOCK_SCAM_PATH = "/mock-scam/"

    /** One address-bar URL ready to check. [key] = host, or host + path for a demo scam page. */
    data class Target(val url: String, val host: String, val port: Int, val path: String) {
        val isMockScam: Boolean get() = path.startsWith(MOCK_SCAM_PATH)
        val key: String get() = if (isMockScam) "$host$path" else host
    }

    enum class Skip { OFFICIAL, PRIVATE, API_HOST, ALLOWED }

    enum class Action { BLOCK, CAUTION, NONE }

    private val SCHEME = Regex("^([a-z][a-z0-9+.-]*)://")
    /** "about:blank", "chrome:flags", "javascript:..." (a colon NOT followed by a port number). */
    private val OTHER_SCHEME = Regex("^[a-z][a-z0-9+.-]*:(?![0-9])")
    private val IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val GOOGLE = Regex("(^|\\.)google\\.[a-z]{2,3}(\\.[a-z]{2})?$")

    /**
     * Address-bar text -> [Target], or null when it is not a web page worth checking: empty,
     * a search query (has spaces), about: / chrome: / other schemes, or a search-results page.
     * Adds the scheme browsers hide (http for private hosts, else https), lower-cases the host,
     * drops credentials (`https://tamm.abudhabi@evil.com` is evil.com) and the #fragment.
     */
    fun normalise(raw: String?): Target? {
        var s = raw?.trim()?.substringBefore('#') ?: return null
        if (s.isEmpty() || s.any { it.isWhitespace() } || s.length > 2048) return null
        val lower = s.lowercase(Locale.ROOT)
        val schemeMatch = SCHEME.find(lower)
        val scheme: String?
        if (schemeMatch != null) {
            scheme = schemeMatch.groupValues[1]
            if (scheme != "http" && scheme != "https") return null
            s = s.substring(schemeMatch.range.last + 1)
        } else {
            if (OTHER_SCHEME.containsMatchIn(lower)) return null
            scheme = null
        }
        val cut = s.indexOfFirst { it == '/' || it == '?' }
        val authority = (if (cut >= 0) s.substring(0, cut) else s).substringAfterLast('@')
        var rest = if (cut >= 0) s.substring(cut) else ""
        if (rest.startsWith("?")) rest = "/$rest"
        val path = rest.substringBefore('?').ifEmpty { "/" }

        val host: String
        val port: Int
        if (authority.startsWith("[")) {
            val end = authority.indexOf(']')
            if (end < 0) return null
            host = authority.substring(0, end + 1).lowercase(Locale.ROOT)
            port = authority.substring(end + 1).removePrefix(":").toIntOrNull() ?: -1
        } else {
            host = authority.substringBefore(':').lowercase(Locale.ROOT).trimEnd('.')
            val p = authority.substringAfter(':', "")
            port = if (p.isEmpty()) -1 else p.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            if (host.isEmpty() || !host.all { it.isLetterOrDigit() || it == '-' || it == '.' }) return null
            if (!host.contains('.') && host != "localhost") return null
        }
        if (isSearchPage(host, path)) return null
        val finalScheme = scheme ?: if (isPrivateHost(host)) "http" else "https"
        val portPart = if (port > 0) ":$port" else ""
        return Target("$finalScheme://$host$portPart$rest", host, port, path)
    }

    /** Google (any google.* country domain) and the other big search engines' result pages. */
    fun isSearchPage(host: String, path: String): Boolean {
        if (GOOGLE.containsMatchIn(host)) return true
        if (host == "duckduckgo.com" || host.endsWith(".duckduckgo.com")) return true
        if (host == "search.yahoo.com" || host.endsWith(".search.yahoo.com")) return true
        if ((host == "bing.com" || host.endsWith(".bing.com")) && path.startsWith("/search")) return true
        return false
    }

    /** Loopback, LAN, link-local and "localhost" hosts (routers, intranet, dev servers). */
    fun isPrivateHost(host: String): Boolean {
        val h = host.lowercase(Locale.ROOT)
        if (h == "localhost" || h.endsWith(".localhost") || h == "[::1]") return true
        if (h.startsWith("[")) return h.startsWith("[fc") || h.startsWith("[fd") || h.startsWith("[fe80")
        if (!IPV4.matches(h)) return false
        val o = h.split('.').map { it.toInt() }
        if (o.any { it > 255 }) return false
        return o[0] == 127 || o[0] == 10 || (o[0] == 192 && o[1] == 168) ||
            (o[0] == 172 && o[1] in 16..31) || (o[0] == 169 && o[1] == 254) || o[0] == 0
    }

    /**
     * Why [t] must NOT be sent to the server, or null to check it. [apiHost] = "host" or
     * "host:port" of the configured SAQR API; its pages (and private hosts) are checked only
     * under /mock-scam/ (the demo scam page).
     */
    fun skipReason(t: Target, apiHost: String?, allowList: Set<String>): Skip? {
        if (t.host in allowList) return Skip.ALLOWED
        if (OfficialDomains.isOfficial(t.host)) return Skip.OFFICIAL
        if (apiHost != null && sameHost(t, apiHost)) return if (t.isMockScam) null else Skip.API_HOST
        if (isPrivateHost(t.host) && !t.isMockScam) return Skip.PRIVATE
        return null
    }

    private fun sameHost(t: Target, apiHost: String): Boolean {
        val a = apiHost.lowercase(Locale.ROOT)
        val aHost = if (a.startsWith("[")) a.substringBefore(']') + "]" else a.substringBefore(':')
        val aPort = a.substringAfterLast(':', "").takeIf { !a.endsWith("]") }?.toIntOrNull()
        if (aHost != t.host) return false
        return aPort == null || t.port == -1 || aPort == t.port
    }

    /** HIGH-RISK (verdict or score >= 65) blocks; 30-64 gets the quieter caution notification. */
    fun action(verdict: Verdict, score: Int?): Action {
        val s = score ?: 0
        return when {
            verdict == Verdict.SCAM || s >= BLOCK_SCORE -> Action.BLOCK
            verdict == Verdict.SUSPICIOUS || s >= SUSPICIOUS_SCORE -> Action.CAUTION
            else -> Action.NONE
        }
    }

    /** Like the extension: one deep scan (sandbox + LLM) only for a fast result of 30-64. */
    fun wantsDeepScan(verdict: Verdict, score: Int?): Boolean = action(verdict, score) == Action.CAUTION
}

/**
 * 5-second per-URL cooldown and per-host in-flight de-duplication, so the stream of
 * accessibility events for one page causes at most one server check.
 */
class UrlThrottle(
    private val cooldownMs: Long = WebGuardPolicy.COOLDOWN_MS,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val lastSeen = LinkedHashMap<String, Long>()
    private val inFlight = HashSet<String>()

    /** True if [urlKey] may be checked now; then [host] is in flight until [finish]. */
    @Synchronized
    fun tryStart(urlKey: String, host: String): Boolean {
        val t = now()
        if (lastSeen.size > 128) lastSeen.entries.removeAll { t - it.value >= cooldownMs }
        lastSeen[urlKey]?.let { if (t - it < cooldownMs) return false }
        if (host in inFlight) return false
        lastSeen[urlKey] = t
        inFlight += host
        return true
    }

    @Synchronized
    fun finish(host: String) {
        inFlight -= host
    }
}

/**
 * When the full-screen block may open: never twice for the same URL within the cooldown, never
 * while it already shows that host, and not for a short while after the user closed it (the
 * browser is still on its way back from the scam page).
 */
class BlockGate(
    private val cooldownMs: Long = WebGuardPolicy.COOLDOWN_MS,
    private val now: () -> Long = System::currentTimeMillis,
) {
    private val lastLaunch = HashMap<String, Long>()
    private val suppressedUntil = HashMap<String, Long>()

    @Volatile
    var showingHost: String? = null
        private set

    @Synchronized
    fun tryLaunch(urlKey: String, host: String): Boolean {
        val t = now()
        if (showingHost == host) return false
        suppressedUntil[host]?.let { if (t < it) return false else suppressedUntil.remove(host) }
        lastLaunch[urlKey]?.let { if (t - it < cooldownMs) return false }
        lastLaunch[urlKey] = t
        if (lastLaunch.size > 64) lastLaunch.entries.removeAll { t - it.value >= cooldownMs }
        return true
    }

    @Synchronized
    fun onShown(host: String) {
        showingHost = host
    }

    /** The block screen closed; [suppressMs] keeps it from reopening while the browser goes back. */
    @Synchronized
    fun onClosed(host: String, suppressMs: Long = 3_000L) {
        if (showingHost == host) showingHost = null
        if (suppressMs > 0) suppressedUntil[host] = now() + suppressMs
    }
}

/** Process-lifetime ("session") state shared by the service and the block screen. */
object WebSession {
    /** Hosts the user opened with "Continue anyway". Cleared when the app process ends. */
    private val allowed = HashSet<String>()
    val throttle = UrlThrottle()
    val gate = BlockGate()

    @Synchronized
    fun allow(host: String) {
        allowed += host.lowercase(Locale.ROOT)
    }

    @Synchronized
    fun allowList(): Set<String> = allowed.toSet()
}
