package ae.saqrintel.shield.ui

import ae.saqrintel.shield.R
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.ApiJson
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.guard.SaqrBrowserGuardService
import ae.saqrintel.shield.guard.WebSession
import ae.saqrintel.shield.locale.LocaleController
import ae.saqrintel.shield.settings.ThemeController
import ae.saqrintel.shield.settings.ThemeMode
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.RiskMeter
import ae.saqrintel.shield.ui.common.SaqrCard
import ae.saqrintel.shield.ui.common.SaqrLockup
import ae.saqrintel.shield.ui.common.SecondaryButton
import ae.saqrintel.shield.ui.common.VerdictChip
import ae.saqrintel.shield.ui.common.bilingualVerdict
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.common.verdictFill
import ae.saqrintel.shield.ui.theme.SaqrShieldTheme
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.ui.verdict.VerdictActions
import ae.saqrintel.shield.util.Aman
import ae.saqrintel.shield.util.Defang
import ae.saqrintel.shield.util.XAlert
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.addCallback
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.animation.core.Animatable
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.roundToInt

/**
 * "Blocked by Saqr": full screen over the browser when the web blocker finds a HIGH-RISK
 * site. Not exported, excluded from recents, its own task (so finishing returns to the browser).
 * Back = "Close & stay safe".
 */
class BlockAlertActivity : ComponentActivity() {

    private data class Block(val record: AlertRecord, val url: String, val host: String, val browser: String?)

    private var block by mutableStateOf<Block?>(null)

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        block = parse(intent)
        if (block == null) {
            finish()
            return
        }
        onBackPressedDispatcher.addCallback(this) { closeAndStaySafe() }
        val themeController = ThemeController(applicationContext)

        setContent {
            val mode by themeController.mode.collectAsStateWithLifecycle(initialValue = ThemeMode.LIGHT)
            val dark = mode == ThemeMode.DARK
            LaunchedEffect(dark) {
                val bars = if (dark) SystemBarStyle.dark(Color.TRANSPARENT) else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
                enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
            }
            SaqrShieldTheme(darkTheme = dark) {
                block?.let { b ->
                    BlockScreen(
                        record = b.record,
                        url = b.url,
                        onClose = ::closeAndStaySafe,
                        onWarnX = { arabic ->
                            if (!VerdictActions.warnOnX(this, b.record.toVerdictInfo(), arabic)) toastNoApp()
                        },
                        onCallAman = { if (!Aman.dial(this)) toastNoApp() },
                        onContinue = ::continueAnyway,
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        parse(intent)?.let { block = it }
    }

    override fun onStart() {
        super.onStart()
        block?.let { WebSession.gate.onShown(it.host) }
    }

    override fun onStop() {
        // Hidden (Home, another app): the browser may show the site again, so let it re-block.
        block?.let { WebSession.gate.onClosed(it.host, suppressMs = 0) }
        super.onStop()
    }

    /**
     * Leaves the scam page: finish this screen (the browser is behind it), then the web-blocker
     * service presses BACK in the browser; if the browser still shows the site 1.8 s later (a tab
     * with no history), it opens the official site (or AD Police) in that browser instead.
     */
    private fun closeAndStaySafe() {
        val b = block ?: return finish()
        WebSession.gate.onClosed(b.host, suppressMs = 3_000)
        val safe = b.record.officialDomain?.takeIf { it.isNotBlank() }?.let { "https://$it" } ?: SAFE_FALLBACK
        val service = SaqrBrowserGuardService.running()
        finish()
        if (service != null) {
            service.leaveScamPage(b.host, b.browser, safe)
        } else {
            SaqrBrowserGuardService.openSafePage(applicationContext, safe, b.browser)
        }
    }

    private fun continueAnyway() {
        val b = block ?: return finish()
        WebSession.allow(b.host)
        WebSession.gate.onClosed(b.host, suppressMs = 0)
        finish()
    }

    private fun toastNoApp() = Toast.makeText(this, getString(R.string.toast_no_app), Toast.LENGTH_SHORT).show()

    private fun parse(intent: Intent?): Block? {
        intent ?: return null
        val json = intent.getStringExtra(EXTRA_RECORD) ?: return null
        val record = try {
            ApiJson.decodeFromString(AlertRecord.serializer(), json)
        } catch (_: IllegalArgumentException) {
            return null
        }
        val url = intent.getStringExtra(EXTRA_URL) ?: return null
        val host = intent.getStringExtra(EXTRA_HOST) ?: return null
        return Block(record, url, host, intent.getStringExtra(EXTRA_BROWSER))
    }

    companion object {
        private const val EXTRA_RECORD = "ae.saqrintel.shield.BLOCK_RECORD"
        private const val EXTRA_URL = "ae.saqrintel.shield.BLOCK_URL"
        private const val EXTRA_HOST = "ae.saqrintel.shield.BLOCK_HOST"
        private const val EXTRA_BROWSER = "ae.saqrintel.shield.BLOCK_BROWSER"
        const val SAFE_FALLBACK = "https://www.adpolice.gov.ae"

        fun intent(context: Context, record: AlertRecord, url: String, host: String, browserPkg: String?): Intent =
            Intent(context, BlockAlertActivity::class.java)
                .putExtra(EXTRA_RECORD, ApiJson.encodeToString(AlertRecord.serializer(), record))
                .putExtra(EXTRA_URL, url)
                .putExtra(EXTRA_HOST, host)
                .putExtra(EXTRA_BROWSER, browserPkg)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    }
}

@Composable
private fun BlockScreen(
    record: AlertRecord,
    url: String,
    onClose: () -> Unit,
    onWarnX: (arabic: Boolean) -> Unit,
    onCallAman: () -> Unit,
    onContinue: () -> Unit,
) {
    val c = SaqrTheme.colors
    val arabic = isArabic()
    var confirmContinue by remember { mutableStateOf(false) }
    val entity = if (arabic) record.entityAr ?: record.entityEn?.let { XAlert.ENTITY_AR[it] ?: it } else record.entityEn
    val reasons = (if (arabic) record.reasonsAr else record.reasonsEn).filter { it.isNotBlank() }.take(3)
    val verdict = record.verdictValue

    Box(
        Modifier
            .fillMaxSize()
            .background(c.canvas),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .systemBarsPadding()
                .padding(horizontal = 16.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            SaqrLockup(falcon = 28.dp, modifier = Modifier.align(Alignment.CenterHorizontally))

            SaqrCard(padding = 20.dp, spacing = 14.dp) {
                Text(
                    stringResource(R.string.block_title),
                    style = MaterialTheme.typography.headlineSmall,
                    color = c.ink,
                    modifier = Modifier.semantics { heading() },
                )
                Text(stringResource(R.string.block_sub), style = MaterialTheme.typography.bodyMedium, color = c.inkSoft)
                Text(
                    Defang.defangUrl(url),
                    style = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                        textDirection = TextDirection.Ltr,
                    ),
                    color = c.ink,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(c.muted, SaqrTheme.shapes.control)
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                )
                AnimatedScore(record.score ?: 0, verdict)
                if (entity != null || !record.officialDomain.isNullOrBlank()) {
                    HorizontalDivider(color = c.line)
                    if (entity != null) Field(stringResource(R.string.verdict_pretends), entity)
                    if (!record.officialDomain.isNullOrBlank()) {
                        Field(stringResource(R.string.verdict_official_site), record.officialDomain, ltr = true)
                    }
                }
                if (reasons.isNotEmpty()) {
                    HorizontalDivider(color = c.line)
                    reasons.forEach { r ->
                        Row(verticalAlignment = Alignment.Top) {
                            Box(
                                Modifier
                                    .padding(top = 8.dp)
                                    .size(6.dp)
                                    .background(verdictFill(verdict), CircleShape),
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                r,
                                style = MaterialTheme.typography.bodyMedium,
                                color = c.ink,
                                maxLines = 3,
                                overflow = TextOverflow.Ellipsis,
                            )
                        }
                    }
                }
            }

            PrimaryButton(stringResource(R.string.block_close), onClick = onClose, minHeight = 52.dp)
            if (verdict != Verdict.SAFE && (record.score ?: 0) >= 60) {
                SecondaryButton(stringResource(R.string.block_warn_x), onClick = { onWarnX(arabic) })
            }
            SecondaryButton(stringResource(R.string.action_call_aman), onClick = onCallAman)
            TextButton(
                onClick = { if (confirmContinue) onContinue() else confirmContinue = true },
                modifier = Modifier.align(Alignment.CenterHorizontally),
            ) {
                Text(
                    stringResource(if (confirmContinue) R.string.block_continue_confirm else R.string.block_continue),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (confirmContinue) c.scamInk else c.inkSoft,
                    textAlign = TextAlign.Center,
                )
            }
            Text(
                stringResource(R.string.block_privacy),
                style = MaterialTheme.typography.labelMedium,
                color = c.inkSoft,
                modifier = Modifier.fillMaxWidth(),
                textAlign = TextAlign.Center,
            )
        }
    }
}

/** Bold score counting up to the real value, the EN · AR verdict chip and the three-zone meter. */
@Composable
private fun AnimatedScore(score: Int, verdict: Verdict) {
    val c = SaqrTheme.colors
    val progress = remember { Animatable(0f) }
    LaunchedEffect(score) {
        progress.animateTo(score.coerceIn(0, 100) / 100f, tween(durationMillis = 700, easing = FastOutSlowInEasing))
    }
    val shown = (progress.value * 100).roundToInt()
    val label = stringResource(R.string.block_risk)
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Row(
            verticalAlignment = Alignment.Bottom,
            modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = "$label $score / 100" },
        ) {
            Text(
                shown.toString(), // Western digits in both languages
                style = MaterialTheme.typography.displaySmall.tabular().copy(fontSize = 52.sp, lineHeight = 56.sp),
                color = c.ink,
                softWrap = false,
            )
            Text(
                " / 100",
                style = MaterialTheme.typography.titleMedium.tabular(),
                color = c.inkSoft,
                softWrap = false,
                modifier = Modifier.padding(bottom = 8.dp),
            )
        }
        VerdictChip(bilingualVerdict(verdict), verdict)
        RiskMeter(shown, verdict)
    }
}

@Composable
private fun Field(label: String, value: String, ltr: Boolean = false) {
    val c = SaqrTheme.colors
    Column(verticalArrangement = Arrangement.spacedBy(2.dp), modifier = Modifier.fillMaxWidth()) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = c.inkSoft)
        Text(
            value,
            style = MaterialTheme.typography.bodyLarge.copy(
                fontWeight = FontWeight.SemiBold,
                textDirection = if (ltr) TextDirection.Ltr else TextDirection.Content,
            ),
            color = c.ink,
        )
    }
}
