package ae.saqrintel.shield.guard

import ae.saqrintel.shield.AppGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.Interception
import ae.saqrintel.shield.data.ScanCache
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.toVerdictInfo
import android.content.Context
import kotlinx.coroutines.delay

/** Source apps the guard reads, and how each is reported. */
enum class GuardSource(val channel: String, val alertKind: AlertKind, val scanKind: ScanKind) {
    SMS("sms", AlertKind.SMS, ScanKind.MESSAGE),
    WHATSAPP("whatsapp", AlertKind.WHATSAPP, ScanKind.MESSAGE),
    EMAIL("email", AlertKind.EMAIL, ScanKind.MESSAGE),
    MESSENGER("social", AlertKind.MESSAGE, ScanKind.MESSAGE),
    ;

    companion object {
        val PACKAGES: Map<String, GuardSource> = mapOf(
            "com.google.android.apps.messaging" to SMS,
            "com.samsung.android.messaging" to SMS,
            "com.android.mms" to SMS,
            "com.google.android.gm" to EMAIL,
            "com.microsoft.office.outlook" to EMAIL,
            "com.whatsapp" to WHATSAPP,
            "com.whatsapp.w4b" to WHATSAPP,
            "org.telegram.messenger" to MESSENGER,
        )
    }
}

/**
 * Scans one message that passed [MessageFilter] and raises the alert. Runs on the listener's
 * IO scope. Server waking / failing = silent, with at most ONE retry after 20 s (no loops).
 */
class GuardEngine(private val context: Context, private val graph: AppGraph) {

    suspend fun scan(rawText: String, sender: String?, source: GuardSource) {
        val text = MessageFilter.prepareForServer(rawText)
        val safeSender = senderForServer(sender, source)
        val key = ScanCache.messageKey(text, safeSender)
        if (graph.cache.get(key) != null) return // already checked (and alerted) recently

        val reporter = try {
            graph.settings.reporterId()
        } catch (_: Exception) {
            null
        }
        var result = request(text, safeSender, source, reporter)
        if (result is ApiResult.ServerWaking) {
            delay(RETRY_DELAY_MS)
            result = request(text, safeSender, source, reporter)
        }
        if (result !is ApiResult.Ok) return

        graph.settings.incrementChecked()
        val info = result.value.toVerdictInfo(source.scanKind)
        graph.cache.put(key, info)
        if (info.verdict == Verdict.SAFE) return

        val record = AlertRecord.from(info, source.alertKind)
        graph.alertStore.add(record)
        AlertNotifier.notify(context, record, info.xEligible)
    }

    private suspend fun request(text: String, sender: String?, source: GuardSource, reporter: String?) =
        graph.api.analyzeMessage(
            text = text,
            sender = sender,
            channel = source.channel,
            reporterId = reporter,
            useLlm = false,
            followLinks = true,
            interception = Interception.GUARD,
        )

    companion object {
        const val RETRY_DELAY_MS = 20_000L
        private val PHONE_LIKE = Regex("^\\+?[0-9][0-9 ()-]{5,20}$")
        private val SENDER_ID = Regex("^[A-Za-z0-9][A-Za-z0-9.&-]{2,10}$")

        /**
         * Only a phone number or an SMS alphanumeric sender id (e.g. "ADPolice") is sent; a saved
         * contact name or a chat / group title never leaves the phone.
         */
        fun senderForServer(sender: String?, source: GuardSource): String? {
            val s = sender?.let(MessageFilter::normalise)?.trim()?.take(64) ?: return null
            if (PHONE_LIKE.matches(s)) return s
            // Sender ids look like "ADPolice", "TAMM", "AD-POLICE": 2+ capitals or a digit, so a
            // one-word contact name like "Ahmed" is not sent.
            if (source == GuardSource.SMS && SENDER_ID.matches(s) &&
                (s.count { it.isUpperCase() } >= 2 || s.any { it.isDigit() })
            ) {
                return s
            }
            return null
        }
    }
}
