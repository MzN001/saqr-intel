package ae.saqrintel.shield.guard

import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.locale.LocaleController
import android.app.Notification
import android.content.ComponentName
import android.content.Context
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Message guard. Reads notifications of the allow-listed messaging / mail apps only, and only
 * after the user consented. Each message goes through [MessageFilter] on the phone first; only
 * messages with a link, a phone number + lure, or a code request are sent to the server.
 * Never crashes on odd extras: everything is null-safe inside try/catch.
 */
class SaqrNotificationListenerService : NotificationListenerService() {

    private var scope: CoroutineScope? = null
    private var consentJob: Job? = null

    @Volatile
    private var consent = false

    /** hash -> time seen, for the 10 s de-duplication window. Touched on the main thread only. */
    private val recent = LinkedHashMap<String, Long>()

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onListenerConnected() {
        super.onListenerConnected()
        val s = scope ?: CoroutineScope(SupervisorJob() + Dispatchers.IO).also { scope = it }
        val graph = appGraph ?: return
        consentJob?.cancel()
        consentJob = s.launch {
            try {
                graph.settings.guardConsent.collect { consent = it }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                consent = false
            }
        }
    }

    override fun onListenerDisconnected() {
        stopWork()
        super.onListenerDisconnected()
    }

    override fun onDestroy() {
        stopWork()
        super.onDestroy()
    }

    private fun stopWork() {
        consent = false
        scope?.cancel()
        scope = null
        consentJob = null
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        try {
            handle(sbn ?: return)
        } catch (_: Exception) {
            // A malformed notification from another app must never take the guard down.
        }
    }

    private fun handle(sbn: StatusBarNotification) {
        val pkg = sbn.packageName ?: return
        if (pkg == packageName) return
        val source = GuardSource.PACKAGES[pkg] ?: return
        val n = sbn.notification ?: return
        if (n.flags and Notification.FLAG_ONGOING_EVENT != 0) return
        if (n.flags and Notification.FLAG_GROUP_SUMMARY != 0) return
        if (!consent) return
        val s = scope ?: return
        val graph = appGraph ?: return

        val (sender, text) = extract(n) ?: return

        val key = "$pkg\u0000${sender.orEmpty()}\u0000$text".hashCode().toString() + ":" + text.length
        val now = System.currentTimeMillis()
        recent.entries.removeAll { now - it.value > DEDUPE_MS }
        if (recent.containsKey(key)) return
        recent[key] = now
        while (recent.size > 64) recent.remove(recent.keys.first())

        val engine = GuardEngine(applicationContext, graph)
        s.launch {
            try {
                // On-device filter (off the main thread): ordinary chat stays on the phone.
                if (MessageFilter.decide(text) !is MessageFilter.Decision.Send) return@launch
                engine.scan(text, sender, source)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                // Silent: the guard never nags when the server is down.
            }
        }
    }

    companion object {
        const val DEDUPE_MS = 10_000L

        fun component(context: Context) = ComponentName(context, SaqrNotificationListenerService::class.java)

        /** True when the user enabled SAQR in Settings > Notification access. */
        fun isEnabled(context: Context): Boolean = try {
            NotificationManagerCompat.getEnabledListenerPackages(context).contains(context.packageName)
        } catch (_: RuntimeException) {
            false
        }

        /** (sender, text) of the newest message in [n], or null when there is no text. */
        internal fun extract(n: Notification): Pair<String?, String>? {
            val extras = n.extras ?: return null
            var sender: String? = try {
                extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()
            } catch (_: RuntimeException) {
                null
            }
            var text: String? = try {
                (extras.getCharSequence(Notification.EXTRA_BIG_TEXT) ?: extras.getCharSequence(Notification.EXTRA_TEXT))
                    ?.toString()
            } catch (_: RuntimeException) {
                null
            }
            try {
                val style = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(n)
                val last = style?.messages?.lastOrNull()
                val body = last?.text?.toString()
                if (!body.isNullOrBlank()) {
                    text = body
                    last.person?.name?.toString()?.takeIf { it.isNotBlank() }?.let { sender = it }
                }
            } catch (_: RuntimeException) {
                // Not a messaging-style notification (or a broken one): keep the plain extras.
            }
            val clean = text?.trim()?.take(MAX_CHARS)
            if (clean.isNullOrEmpty()) return null
            return sender?.trim()?.take(64) to clean
        }

        private const val MAX_CHARS = 4000
    }
}
