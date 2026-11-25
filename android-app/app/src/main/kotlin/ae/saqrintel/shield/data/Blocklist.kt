package ae.saqrintel.shield.data

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import java.io.File
import java.util.Locale

@Serializable
data class BlockEntry(
    val domain: String,
    @SerialName("risk_score") val riskScore: Double? = null,
    @SerialName("impersonated_entity") val entity: String? = null,
)

/** GET /api/dns-blocklist (the same feed telecom resolvers would take). */
@Serializable
data class BlocklistResponse(val domains: List<BlockEntry> = emptyList())

/** Pure matching, so it can be unit-tested without Android. */
object BlockMatcher {
    /** Hosts the firewall must never block, whatever a list says. */
    private val NEVER = setOf("saqr-intel.vercel.app", "saqr-intel-api.onrender.com")

    fun index(entries: List<BlockEntry>): Map<String, BlockEntry> =
        entries.mapNotNull { e -> OfficialDomains.normaliseHost(e.domain)?.let { it to e } }.toMap()

    /**
     * The entry that blocks [host]: the host itself or a parent domain on the list
     * (`pay.tamm-fine.top` is blocked by `tamm-fine.top`). Official UAE sites and Saqr's own
     * addresses are never blocked. A single label ("top", "com") never matches.
     */
    fun find(host: String?, index: Map<String, BlockEntry>): BlockEntry? {
        val h = host?.trim()?.trimEnd('.')?.lowercase(Locale.ROOT)?.takeIf { it.isNotEmpty() } ?: return null
        if (index.isEmpty() || OfficialDomains.isOfficial(h) || h in NEVER) return null
        var name = h
        while (name.contains('.')) {
            index[name]?.let { return it }
            name = name.substringAfter('.')
        }
        return null
    }
}

/**
 * Saqr's published scam-domain list, kept on the phone. The DNS firewall matches against this copy,
 * so the names a phone looks up are never sent anywhere.
 */
class Blocklist(context: Context) {
    private val file = File(context.filesDir, "blocklist.json")

    @Volatile
    private var index: Map<String, BlockEntry> = emptyMap()
    private val _count = MutableStateFlow(0)
    val count: StateFlow<Int> = _count.asStateFlow()

    @Volatile
    var loadedAt: Long = 0
        private set

    fun match(host: String?): BlockEntry? = BlockMatcher.find(host, index)

    /** Loads the last saved copy (cheap; call before the first refresh). */
    suspend fun loadSaved() = withContext(Dispatchers.IO) {
        if (index.isNotEmpty() || !file.exists()) return@withContext
        try {
            apply(ApiJson.decodeFromString(BlocklistResponse.serializer(), file.readText()), save = false)
        } catch (_: Exception) {
            // A damaged cache file is simply replaced by the next refresh.
        }
    }

    /** Downloads the current list. False = kept the previous copy. */
    suspend fun refresh(api: ApiClient): Boolean {
        val result = api.dnsBlocklist()
        if (result !is ApiResult.Ok || result.value.domains.isEmpty()) return false
        apply(result.value, save = true)
        return true
    }

    private suspend fun apply(response: BlocklistResponse, save: Boolean) = withContext(Dispatchers.IO) {
        index = BlockMatcher.index(response.domains)
        _count.value = index.size
        loadedAt = System.currentTimeMillis()
        if (save) {
            try {
                file.writeText(ApiJson.encodeToString(BlocklistResponse.serializer(), response))
            } catch (_: Exception) {
                // Not being able to cache the list never stops the firewall.
            }
        }
    }
}
