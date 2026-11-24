package ae.saqrintel.shield.data

import ae.saqrintel.shield.settings.settingsStore
import ae.saqrintel.shield.util.Defang
import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId
import java.util.UUID

/** Where an alert came from. */
enum class AlertKind { SMS, WHATSAPP, EMAIL, WEB, MANUAL, MESSAGE }

/**
 * One stored alert. Privacy: NEVER the message text or the sender number; only the defanged
 * domain (or null = "text message"), the result, the entity and at most 2 short reasons.
 */
@Serializable
data class AlertRecord(
    val id: String,
    val time: Long,
    val kind: AlertKind,
    /** Defanged domain, e.g. tamm-pay[.]net, or null for a message without a link. */
    val label: String? = null,
    val score: Int? = null,
    val verdict: String,
    val entityEn: String? = null,
    val entityAr: String? = null,
    val officialDomain: String? = null,
    val scanId: String? = null,
    val reasonsEn: List<String> = emptyList(),
    val reasonsAr: List<String> = emptyList(),
    val scanKind: ScanKind = ScanKind.MESSAGE,
    val credentialRequest: Boolean = false,
) {
    val verdictValue: Verdict get() = Verdict.parse(verdict, score)

    /** Rebuilds a (reduced) verdict for the sheet: no links/phones lists are stored. */
    fun toVerdictInfo(): VerdictInfo = VerdictInfo(
        kind = scanKind,
        scanId = scanId,
        verdict = verdictValue,
        score = score,
        domain = label?.let(Defang::refang),
        entityEn = entityEn,
        entityAr = entityAr,
        officialDomain = officialDomain,
        verifiedOfficial = false,
        reasons = reasonsEn.mapIndexed { i, en -> Reason(null, en, reasonsAr.getOrNull(i) ?: en) },
        credentialRequest = credentialRequest,
        detectedAt = time,
    )

    companion object {
        fun from(info: VerdictInfo, kind: AlertKind): AlertRecord = AlertRecord(
            id = info.scanId ?: UUID.randomUUID().toString(),
            time = info.detectedAt,
            kind = kind,
            label = info.domain?.let(Defang::defang),
            score = info.score,
            verdict = info.verdict.wire,
            entityEn = info.entityEn,
            entityAr = info.entityAr,
            officialDomain = info.officialDomain,
            scanId = info.scanId,
            reasonsEn = info.reasons.take(2).map { it.en.take(200) },
            reasonsAr = info.reasons.take(2).map { it.ar.take(200) },
            scanKind = info.kind,
            credentialRequest = info.credentialRequest,
        )
    }
}

/** Last [MAX] alerts as one JSON string in the app DataStore. */
class AlertStore(private val context: Context) {
    private val key = stringPreferencesKey("alerts_json")
    private val serializer = ListSerializer(AlertRecord.serializer())

    val alerts: Flow<List<AlertRecord>> = context.settingsStore.data.map { decode(it[key]) }

    /** HIGH-RISK alerts the guard raised today (manual checks do not count as "blocked"). */
    val blockedToday: Flow<Int> = alerts.map { list ->
        val zone = ZoneId.systemDefault()
        val today = LocalDate.now(zone)
        list.count {
            it.kind != AlertKind.MANUAL && it.verdictValue == Verdict.SCAM &&
                Instant.ofEpochMilli(it.time).atZone(zone).toLocalDate() == today
        }
    }

    suspend fun add(record: AlertRecord) {
        context.settingsStore.edit { p ->
            val list = decode(p[key]).filterNot { it.id == record.id }
            p[key] = ApiJson.encodeToString(serializer, (listOf(record) + list).take(MAX))
        }
    }

    suspend fun find(id: String): AlertRecord? = alerts.first().firstOrNull { it.id == id }

    suspend fun clear() {
        context.settingsStore.edit { it.remove(key) }
    }

    private fun decode(json: String?): List<AlertRecord> {
        if (json.isNullOrEmpty()) return emptyList()
        return try {
            ApiJson.decodeFromString(serializer, json)
        } catch (_: IllegalArgumentException) {
            emptyList()
        }
    }

    companion object {
        const val MAX = 50
    }
}
