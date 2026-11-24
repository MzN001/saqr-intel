package ae.saqrintel.shield.util

/** Make a domain unclickable wherever it is shown or pasted: https://tamm-pay.net/x -> tamm-pay[.]net */
object Defang {
    private val SCHEME = Regex("^[a-z][a-z0-9+.-]*://", RegexOption.IGNORE_CASE)

    fun defang(domainOrUrl: String): String =
        domainOrUrl.trim()
            .replace(SCHEME, "")
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .replace(".", "[.]")

    /**
     * Host defanged, path kept (shortened) for the block screen:
     * https://tamm-pay.net/fine?id=1 -> tamm-pay[.]net/fine?id=1. No scheme, so nothing is clickable.
     */
    fun defangUrl(url: String, maxPath: Int = 48): String {
        val noScheme = url.trim().replace(SCHEME, "").substringBefore('#')
        val cut = noScheme.indexOfFirst { it == '/' || it == '?' }
        val authority = if (cut >= 0) noScheme.substring(0, cut) else noScheme
        val rest = if (cut >= 0) noScheme.substring(cut) else ""
        val shownRest = when {
            rest == "/" -> ""
            rest.length > maxPath -> rest.take(maxPath - 1) + "…"
            else -> rest
        }
        return authority.replace(".", "[.]") + shownRest
    }

    fun refang(defanged: String): String = defanged.replace("[.]", ".")
}
