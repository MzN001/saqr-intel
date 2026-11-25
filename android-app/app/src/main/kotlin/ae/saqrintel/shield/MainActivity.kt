package ae.saqrintel.shield

import ae.saqrintel.shield.guard.AlertNotifier
import ae.saqrintel.shield.guard.SaqrDnsVpnService
import ae.saqrintel.shield.locale.LocaleController
import ae.saqrintel.shield.settings.ThemeController
import ae.saqrintel.shield.settings.ThemeMode
import ae.saqrintel.shield.ui.shell.SaqrShell
import ae.saqrintel.shield.ui.theme.SaqrShieldTheme
import ae.saqrintel.shield.ui.verdict.VerdictActions
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {

    /** Alert to show (from a guard notification); consumed by the shell. */
    private val openAlert = MutableStateFlow<String?>(null)

    /** Text shared to Saqr from another app ("Share" or the text-selection menu); consumed by the Scanner. */
    private val sharedText = MutableStateFlow<String?>(null)

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val themeController = ThemeController(applicationContext)
        if (savedInstanceState == null) handleIntent(intent)
        resumeFirewall()

        setContent {
            val mode by themeController.mode.collectAsStateWithLifecycle(initialValue = ThemeMode.LIGHT)
            val alertId by openAlert.collectAsStateWithLifecycle()
            val shared by sharedText.collectAsStateWithLifecycle()
            val dark = mode == ThemeMode.DARK
            val scope = rememberCoroutineScope()

            LaunchedEffect(dark) {
                val bars = if (dark) {
                    SystemBarStyle.dark(Color.TRANSPARENT)
                } else {
                    SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                }
                enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
            }

            SaqrShieldTheme(darkTheme = dark) {
                SaqrShell(
                    isDark = dark,
                    onToggleTheme = {
                        scope.launch { themeController.set(if (dark) ThemeMode.LIGHT else ThemeMode.DARK) }
                    },
                    onToggleLanguage = { LocaleController.toggle(this@MainActivity) },
                    openAlertId = alertId,
                    onAlertOpened = { openAlert.value = null },
                    sharedText = shared,
                    onSharedUsed = { sharedText.value = null },
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    /** The firewall stops with the app's process: bring it back if the user left it on. */
    private fun resumeFirewall() {
        val graph = appGraph ?: return
        lifecycleScope.launch {
            if (graph.settings.dnsFirewall.first() && !SaqrDnsVpnService.isRunning.value &&
                SaqrDnsVpnService.consentIntent(this@MainActivity) == null
            ) {
                SaqrDnsVpnService.start(this@MainActivity)
            }
        }
    }

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        val graph = appGraph
        val incoming = when (intent.action) {
            Intent.ACTION_SEND -> intent.getStringExtra(Intent.EXTRA_TEXT)
            Intent.ACTION_PROCESS_TEXT -> intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
            else -> null
        }?.trim()?.take(MAX_SHARED)
        if (!incoming.isNullOrEmpty()) {
            sharedText.value = incoming
            return
        }
        // Debug-only test hook: adb shell am start -n ae.saqrintel.shield/.MainActivity --es api_url http://10.0.2.2:8011
        val apiUrl = intent.getStringExtra(EXTRA_API_URL)
        if (apiUrl != null && graph != null && graph.settings.isDebugBuild) {
            lifecycleScope.launch {
                val saved = graph.settings.setApiBaseUrl(apiUrl)
                Log.i(TAG, if (saved != null) "API base URL set to $saved" else "Rejected API base URL")
            }
        }
        // Debug-only test hook: --ez web_consent true (same as accepting the web-blocker dialog).
        if (intent.hasExtra(EXTRA_WEB_CONSENT) && graph != null && graph.settings.isDebugBuild) {
            val on = intent.getBooleanExtra(EXTRA_WEB_CONSENT, false)
            lifecycleScope.launch {
                graph.settings.setWebConsent(on)
                Log.i(TAG, "Web blocker consent set to $on")
            }
        }
        val alertId = intent.getStringExtra(EXTRA_ALERT_ID) ?: return
        AlertNotifier.cancel(this, alertId)
        if (intent.getBooleanExtra(EXTRA_WARN_X, false) && graph != null) {
            lifecycleScope.launch {
                val record = graph.alertStore.find(alertId) ?: return@launch
                val arabic = LocaleController.current(this@MainActivity) == LocaleController.ARABIC
                VerdictActions.warnOnX(this@MainActivity, record.toVerdictInfo(), arabic)
            }
        }
        openAlert.value = alertId
    }

    companion object {
        private const val TAG = "SaqrShield"
        const val EXTRA_ALERT_ID = "ae.saqrintel.shield.ALERT_ID"
        const val EXTRA_WARN_X = "ae.saqrintel.shield.WARN_X"
        const val EXTRA_API_URL = "api_url"
        const val EXTRA_WEB_CONSENT = "web_consent"
        private const val MAX_SHARED = 4000

        fun alertIntent(context: Context, alertId: String, warnOnX: Boolean): Intent =
            Intent(context, MainActivity::class.java)
                .setAction(if (warnOnX) "ae.saqrintel.shield.WARN_X" else "ae.saqrintel.shield.VIEW_ALERT")
                .putExtra(EXTRA_ALERT_ID, alertId)
                .putExtra(EXTRA_WARN_X, warnOnX)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
    }
}
