package ae.saqrintel.shield.data

import java.util.Locale

/** Which endpoint a manual check goes to. */
enum class ScanRoute { WEB, MAPS, MESSAGE, EMAIL, PHONE }

/** Auto mode: decides locally, from the pasted text alone, which check to run. Pure Kotlin. */
object AutoRouter {
    private val SCHEME_URL = Regex("^[a-z][a-z0-9+.-]*://\\S+$", RegexOption.IGNORE_CASE)
    private val BARE_URL = Regex(
        "^(?:www\\.)?(?:[\\p{L}\\p{N}](?:[\\p{L}\\p{N}-]{0,61}[\\p{L}\\p{N}])?\\.)+[\\p{L}]{2,24}(?::\\d{1,5})?(?:[/?#]\\S*)?$",
    )
    private val PHONE_ONLY = Regex("^\\+?[0-9٠-٩][0-9٠-٩\\s().-]{4,24}$")
    private val FROM_LINE = Regex("(?im)^\\s*from\\s*:")
    private val SUBJECT_LINE = Regex("(?im)^\\s*subject\\s*:")

    fun route(input: String): ScanRoute {
        val text = input.trim()
        if (text.isEmpty()) return ScanRoute.MESSAGE
        if (isSingleUrl(text)) return if (isMapsUrl(text)) ScanRoute.MAPS else ScanRoute.WEB
        if (isPhoneOnly(text)) return ScanRoute.PHONE
        if (looksLikeEmail(text)) return ScanRoute.EMAIL
        return ScanRoute.MESSAGE
    }

    fun isSingleUrl(text: String): Boolean {
        val t = text.trim()
        if (t.any { it.isWhitespace() }) return false
        if (t.contains('@') && !t.contains('/')) return false // an email address, not a link
        return (SCHEME_URL.matches(t) && t.startsWith("http", ignoreCase = true)) || BARE_URL.matches(t)
    }

    fun isPhoneOnly(text: String): Boolean {
        val t = text.trim()
        if (!PHONE_ONLY.matches(t)) return false
        val digits = t.count { it.isDigit() }
        return digits in 6..15
    }

    fun looksLikeEmail(text: String): Boolean = FROM_LINE.containsMatchIn(text) && SUBJECT_LINE.containsMatchIn(text)

    /** Raw source (full headers) rather than the visible text of an email. */
    fun looksLikeRawEmail(text: String): Boolean =
        Regex("(?im)^(received|authentication-results|dkim-signature|return-path|message-id)\\s*:").containsMatchIn(text)

    fun isMapsUrl(text: String): Boolean {
        val t = text.trim().lowercase(Locale.ROOT)
        val withScheme = if (t.contains("://")) t else "https://$t"
        val host = OfficialDomains.normaliseHost(withScheme) ?: return false
        val path = withScheme.substringAfter("://").substringAfter('/', "")
        if (host == "maps.app.goo.gl") return true
        if (host == "goo.gl" && path.startsWith("maps")) return true
        if (host.startsWith("maps.google.")) return true
        val isGoogle = Regex("^(www\\.)?google\\.[a-z.]{2,6}$").matches(host)
        return isGoogle && path.startsWith("maps")
    }
}
