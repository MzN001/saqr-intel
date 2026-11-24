package ae.saqrintel.shield.data

import android.util.LruCache
import java.security.MessageDigest

/**
 * In-memory verdict cache (200 entries, lost when the process dies). Key = normalised host
 * for links, SHA-256 of the text for messages. Safe results live 30 min, risky ones 10 min
 * (a site's verdict can change quickly while police act on it).
 */
class ScanCache(private val now: () -> Long = System::currentTimeMillis) {
    private class Entry(val value: VerdictInfo, val expiresAt: Long)

    private val lru = LruCache<String, Entry>(MAX_ENTRIES)

    fun get(key: String): VerdictInfo? {
        val e = lru.get(key) ?: return null
        if (e.expiresAt <= now()) {
            lru.remove(key)
            return null
        }
        return e.value
    }

    fun put(key: String, value: VerdictInfo) {
        val ttl = if (value.verdict == Verdict.SAFE) SAFE_TTL_MS else RISKY_TTL_MS
        lru.put(key, Entry(value, now() + ttl))
    }

    fun clear() = lru.evictAll()

    companion object {
        const val MAX_ENTRIES = 200
        const val SAFE_TTL_MS = 30 * 60 * 1000L
        const val RISKY_TTL_MS = 10 * 60 * 1000L

        fun hostKey(hostOrUrl: String): String? = OfficialDomains.normaliseHost(hostOrUrl)?.let { "h:$it" }

        fun messageKey(text: String, sender: String?): String = "m:" + sha256("${sender.orEmpty()}\u0000$text")

        fun sha256(s: String): String =
            MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") {
                "%02x".format(it.toInt() and 0xff)
            }
    }
}
