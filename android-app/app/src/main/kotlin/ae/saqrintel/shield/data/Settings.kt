package ae.saqrintel.shield.data

import ae.saqrintel.shield.settings.ThemeController
import ae.saqrintel.shield.settings.ThemeMode
import ae.saqrintel.shield.settings.settingsStore
import android.content.Context
import android.content.pm.ApplicationInfo
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.net.URI
import java.security.SecureRandom
import java.time.LocalDate
import java.time.ZoneId
import java.util.Locale

/**
 * App settings in the single [settingsStore] DataStore: API base URL, message-guard consent,
 * pseudonymous reporter id and the "checked today" counter. Theme lives in [ThemeController]
 * (same store); language in [ae.saqrintel.shield.locale.LocaleController] (platform API / prefs).
 */
class Settings(private val context: Context) {
    private val store get() = context.settingsStore

    val isDebugBuild: Boolean =
        (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0

    val theme: Flow<ThemeMode> get() = ThemeController(context).mode

    val apiBaseUrl: Flow<String> = store.data.map { p ->
        p[KEY_API]?.let { validateBaseUrl(it, isDebugBuild) } ?: ApiClient.DEFAULT_BASE_URL
    }

    /** True once the user accepted the message-guard explanation. Turning it off stops all guard scans. */
    val guardConsent: Flow<Boolean> = store.data.map { it[KEY_GUARD_CONSENT] == true }

    /** True once the user accepted the web-blocker explanation. Off = the accessibility service does nothing. */
    val webConsent: Flow<Boolean> = store.data.map { it[KEY_WEB_CONSENT] == true }

    /** True while the user wants the scam-site firewall (local DNS filter) on. */
    val dnsFirewall: Flow<Boolean> = store.data.map { it[KEY_DNS_FIREWALL] == true }

    val checkedToday: Flow<Int> = store.data.map { p ->
        if (p[KEY_CHECKED_DAY] == today()) p[KEY_CHECKED_COUNT] ?: 0 else 0
    }

    suspend fun currentBaseUrl(): String = apiBaseUrl.first()

    /** Saves [input] if valid and returns the normalised URL, or null (nothing saved). */
    suspend fun setApiBaseUrl(input: String): String? {
        val url = validateBaseUrl(input, isDebugBuild) ?: return null
        store.edit { it[KEY_API] = url }
        return url
    }

    suspend fun resetApiBaseUrl() {
        store.edit { it.remove(KEY_API) }
    }

    suspend fun setGuardConsent(on: Boolean) {
        store.edit { it[KEY_GUARD_CONSENT] = on }
    }

    suspend fun setWebConsent(on: Boolean) {
        store.edit { it[KEY_WEB_CONSENT] = on }
    }

    suspend fun setDnsFirewall(on: Boolean) {
        store.edit { it[KEY_DNS_FIREWALL] = on }
    }

    /** "r-" + 32 random hex chars, generated once. Not linked to the person or the phone. */
    suspend fun reporterId(): String {
        store.data.first()[KEY_REPORTER]?.let { if (REPORTER_RE.matches(it)) return it }
        var id = ""
        store.edit { p ->
            val existing = p[KEY_REPORTER]
            id = if (existing != null && REPORTER_RE.matches(existing)) existing else newReporterId()
            p[KEY_REPORTER] = id
        }
        return id
    }

    suspend fun incrementChecked() {
        store.edit { p ->
            val day = today()
            val count = if (p[KEY_CHECKED_DAY] == day) p[KEY_CHECKED_COUNT] ?: 0 else 0
            p[KEY_CHECKED_DAY] = day
            p[KEY_CHECKED_COUNT] = count + 1
        }
    }

    companion object {
        private val KEY_API = stringPreferencesKey("api_base_url")
        private val KEY_GUARD_CONSENT = booleanPreferencesKey("guard_consent")
        private val KEY_WEB_CONSENT = booleanPreferencesKey("web_consent")
        private val KEY_DNS_FIREWALL = booleanPreferencesKey("dns_firewall")
        private val KEY_REPORTER =stringPreferencesKey("reporter_id")
        private val KEY_CHECKED_DAY = stringPreferencesKey("checked_day")
        private val KEY_CHECKED_COUNT = intPreferencesKey("checked_count")
        private val REPORTER_RE = Regex("^r-[0-9a-f]{32}$")

        /** Hosts the debug network-security config allows over plain HTTP. */
        val DEBUG_CLEARTEXT_HOSTS = setOf("10.0.2.2", "localhost", "127.0.0.1")

        fun today(): String = LocalDate.now(ZoneId.systemDefault()).toString()

        fun newReporterId(): String {
            val bytes = ByteArray(16).also { SecureRandom().nextBytes(it) }
            return "r-" + bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        }

        /**
         * Normalised base URL (scheme://host[:port][/path], no trailing slash) or null.
         * HTTPS is required; plain HTTP only in debug builds and only to [DEBUG_CLEARTEXT_HOSTS].
         */
        fun validateBaseUrl(input: String?, debug: Boolean): String? {
            val raw = input?.trim()?.trimEnd('/') ?: return null
            if (raw.isEmpty() || raw.any { it.isWhitespace() }) return null
            val uri = try {
                URI(raw)
            } catch (_: Exception) {
                return null
            }
            val scheme = uri.scheme?.lowercase(Locale.ROOT) ?: return null
            val host = uri.host?.lowercase(Locale.ROOT)?.takeIf { it.isNotEmpty() } ?: return null
            if (uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null) return null
            when (scheme) {
                "https" -> Unit
                "http" -> if (!debug || host !in DEBUG_CLEARTEXT_HOSTS) return null
                else -> return null
            }
            val port = if (uri.port in 1..65535) ":${uri.port}" else if (uri.port == -1) "" else return null
            val path = uri.rawPath.orEmpty().trimEnd('/')
            return "$scheme://$host$port$path"
        }
    }
}
