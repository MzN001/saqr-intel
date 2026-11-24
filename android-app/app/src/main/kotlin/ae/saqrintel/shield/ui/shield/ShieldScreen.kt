package ae.saqrintel.shield.ui.shield

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.guard.AlertNotifier
import ae.saqrintel.shield.guard.SaqrBrowserGuardService
import ae.saqrintel.shield.guard.SaqrNotificationListenerService
import ae.saqrintel.shield.ui.common.FalconMark
import ae.saqrintel.shield.ui.common.SaqrCard
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.theme.SaqrPalette
import ae.saqrintel.shield.ui.theme.SaqrTheme
import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@Composable
fun ShieldScreen(padding: PaddingValues) {
    val context = LocalContext.current
    val graph = remember { context.appGraph }
    val c = SaqrTheme.colors
    val scope = rememberCoroutineScope()

    var notificationsOn by remember { mutableStateOf(AlertNotifier.canNotify(context)) }
    var listenerOn by remember { mutableStateOf(SaqrNotificationListenerService.isEnabled(context)) }
    var a11yOn by remember { mutableStateOf(SaqrBrowserGuardService.isEnabled(context)) }
    LifecycleResumeEffect(Unit) {
        notificationsOn = AlertNotifier.canNotify(context)
        listenerOn = SaqrNotificationListenerService.isEnabled(context)
        a11yOn = SaqrBrowserGuardService.isEnabled(context)
        onPauseOrDispose { }
    }
    val consent by remember { graph?.settings?.guardConsent ?: flowOf(false) }.collectAsStateWithLifecycle(initialValue = false)
    val webConsent by remember { graph?.settings?.webConsent ?: flowOf(false) }.collectAsStateWithLifecycle(initialValue = false)
    val webOn = a11yOn && webConsent
    var showWebConsent by remember { mutableStateOf(false) }
    var showManageWeb by remember { mutableStateOf(false) }
    val blocked by remember { graph?.alertStore?.blockedToday ?: flowOf(0) }.collectAsStateWithLifecycle(initialValue = 0)
    val checked by remember { graph?.settings?.checkedToday ?: flowOf(0) }.collectAsStateWithLifecycle(initialValue = 0)
    val guardOn = listenerOn && consent
    val protected = notificationsOn && guardOn

    var showConsent by remember { mutableStateOf(false) }
    var showManageGuard by remember { mutableStateOf(false) }

    // After a second "Don't allow" Android stops showing the prompt: then open the app's settings.
    var denials by rememberSaveable { mutableIntStateOf(0) }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationsOn = AlertNotifier.canNotify(context)
        if (!granted && ++denials >= 2) openAppNotificationSettings(context)
    }

    // "Protected" needs steps 1-2; the web blocker is recommended, not required.
    val guardsOff = listOf(notificationsOn, guardOn).count { !it }
    val askNotifications = {
        if (Build.VERSION.SDK_INT >= 33) {
            permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            openAppNotificationSettings(context)
        }
    }

    ScreenColumn(padding) {
        // Status card -----------------------------------------------------------------------------
        SaqrCard(padding = 20.dp) {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                val ring = if (protected) SaqrPalette.SafeFill else SaqrPalette.SuspiciousFill
                Box(contentAlignment = Alignment.Center, modifier = Modifier.size(112.dp)) {
                    Canvas(Modifier.size(112.dp)) {
                        val w = 5.dp.toPx()
                        val arc = Size(size.width - w, size.height - w)
                        val topLeft = Offset(w / 2f, w / 2f)
                        drawArc(c.muted, 0f, 360f, false, topLeft, arc, style = Stroke(w))
                        // Full ring when protected; otherwise the share of required steps that are done.
                        val sweep = if (protected) 360f else 360f * (2 - guardsOff).coerceAtLeast(0) / 2f
                        if (sweep > 0f) {
                            drawArc(ring, -90f, sweep, false, topLeft, arc, style = Stroke(w, cap = StrokeCap.Round))
                        }
                    }
                    Box(
                        Modifier
                            .size(84.dp)
                            .background(c.muted, CircleShape),
                    )
                    FalconMark(52.dp)
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    if (protected) {
                        stringResource(R.string.status_protected)
                    } else {
                        pluralStringResource(R.plurals.status_guards_off, guardsOff, guardsOff)
                    },
                    style = MaterialTheme.typography.titleLarge,
                    color = if (protected) c.safeInk else c.suspiciousInk,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.semantics {
                        heading()
                        liveRegion = LiveRegionMode.Polite
                    },
                )
            }
            HorizontalDivider(color = c.line)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Metric(blocked, stringResource(R.string.metric_blocked), Modifier.weight(1f))
                Box(
                    Modifier
                        .width(1.dp)
                        .height(36.dp)
                        .background(c.line),
                )
                Metric(checked, stringResource(R.string.metric_checked), Modifier.weight(1f))
            }
        }

        // Setup steps: one line each, gone once done --------------------------------------------
        val pending = buildList {
            if (!notificationsOn) add(Step(1, R.string.step1_title, R.string.step_allow, askNotifications))
            if (!guardOn) add(Step(2, R.string.step2_title, R.string.step_turn_on) { showConsent = true })
            if (!webOn) add(Step(3, R.string.step3_title, R.string.step_turn_on) { showWebConsent = true })
        }
        pending.forEachIndexed { i, step -> StepPill(step, primary = i == 0) }

        val done = buildList {
            if (notificationsOn) add(R.string.step1_short to { openAppNotificationSettings(context) })
            if (guardOn) add(R.string.step2_short to { showManageGuard = true })
            if (webOn) add(R.string.step3_short to { showManageWeb = true })
        }
        if (done.isNotEmpty()) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.CenterHorizontally),
                modifier = Modifier.fillMaxWidth(),
            ) {
                done.forEach { (label, onClick) -> DoneChip(stringResource(label), onClick) }
            }
        }

        Text(
            stringResource(R.string.aman_footer),
            style = MaterialTheme.typography.labelLarge.tabular(),
            color = c.inkSoft,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            textAlign = TextAlign.Center,
        )
    }

    if (showConsent) {
        AlertDialog(
            onDismissRequest = { showConsent = false },
            title = { Text(stringResource(R.string.consent_title)) },
            text = { Text(stringResource(R.string.consent_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    showConsent = false
                    scope.launch {
                        graph?.settings?.setGuardConsent(true)
                        if (!SaqrNotificationListenerService.isEnabled(context)) openListenerSettings(context)
                    }
                }) { Text(stringResource(R.string.consent_accept)) }
            },
            dismissButton = {
                TextButton(onClick = { showConsent = false }) { Text(stringResource(R.string.consent_decline)) }
            },
            containerColor = c.surface,
        )
    }
    if (showManageGuard) {
        AlertDialog(
            onDismissRequest = { showManageGuard = false },
            title = { Text(stringResource(R.string.guard_manage_title)) },
            text = { Text(stringResource(R.string.guard_manage_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    showManageGuard = false
                    scope.launch { graph?.settings?.setGuardConsent(false) }
                    openListenerSettings(context)
                }) { Text(stringResource(R.string.guard_turn_off)) }
            },
            dismissButton = {
                TextButton(onClick = { showManageGuard = false }) { Text(stringResource(R.string.action_close)) }
            },
            containerColor = c.surface,
        )
    }
    if (showWebConsent) {
        AlertDialog(
            onDismissRequest = { showWebConsent = false },
            title = { Text(stringResource(R.string.web_consent_title)) },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    Text(stringResource(R.string.web_consent_body), style = MaterialTheme.typography.bodyMedium)
                    if (Build.VERSION.SDK_INT >= 33) {
                        Spacer(Modifier.height(12.dp))
                        Text(
                            stringResource(R.string.step3_restricted),
                            style = MaterialTheme.typography.bodySmall,
                            color = c.inkSoft,
                        )
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showWebConsent = false
                    scope.launch {
                        graph?.settings?.setWebConsent(true)
                        if (!SaqrBrowserGuardService.isEnabled(context)) openAccessibilitySettings(context)
                    }
                }) { Text(stringResource(R.string.consent_accept)) }
            },
            dismissButton = {
                TextButton(onClick = { showWebConsent = false }) { Text(stringResource(R.string.consent_decline)) }
            },
            containerColor = c.surface,
        )
    }
    if (showManageWeb) {
        AlertDialog(
            onDismissRequest = { showManageWeb = false },
            title = { Text(stringResource(R.string.web_manage_title)) },
            text = { Text(stringResource(R.string.web_manage_body), style = MaterialTheme.typography.bodyMedium) },
            confirmButton = {
                TextButton(onClick = {
                    showManageWeb = false
                    scope.launch { graph?.settings?.setWebConsent(false) }
                    openAccessibilitySettings(context)
                }) { Text(stringResource(R.string.guard_turn_off)) }
            },
            dismissButton = {
                TextButton(onClick = { showManageWeb = false }) { Text(stringResource(R.string.action_close)) }
            },
            containerColor = c.surface,
        )
    }
}

fun openAccessibilitySettings(context: Context) {
    startSafely(context, Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
}

private class Step(val number: Int, val title: Int, val action: Int, val onClick: () -> Unit)

@Composable
private fun Metric(value: Int, label: String, modifier: Modifier) {
    val c = SaqrTheme.colors
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), style = MaterialTheme.typography.headlineSmall.tabular(), color = c.ink)
        Text(label, style = MaterialTheme.typography.labelMedium, color = c.inkSoft, textAlign = TextAlign.Center)
    }
}

/** One pending setup step on one line: number, title, a single action. */
@Composable
private fun StepPill(step: Step, primary: Boolean) {
    val c = SaqrTheme.colors
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .background(c.surface, SaqrTheme.shapes.pill)
            .border(1.dp, c.line, SaqrTheme.shapes.pill)
            .padding(start = 8.dp, end = 6.dp, top = 6.dp, bottom = 6.dp),
    ) {
        Box(
            Modifier
                .size(32.dp)
                .background(c.suspiciousSoft, CircleShape),
            contentAlignment = Alignment.Center,
        ) {
            Text(step.number.toString(), style = MaterialTheme.typography.labelLarge.tabular(), color = c.suspiciousInk)
        }
        Spacer(Modifier.width(12.dp))
        Text(
            stringResource(step.title),
            style = MaterialTheme.typography.titleSmall,
            color = c.ink,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        Spacer(Modifier.width(8.dp))
        Surface(
            onClick = step.onClick,
            shape = SaqrTheme.shapes.pill,
            color = if (primary) c.primary else c.surface,
            contentColor = if (primary) c.onPrimary else c.ink,
            border = if (primary) null else BorderStroke(1.dp, c.line),
            modifier = Modifier.heightIn(min = 40.dp),
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp)) {
                Text(stringResource(step.action), style = MaterialTheme.typography.labelLarge, maxLines = 1)
            }
        }
    }
}

/** A finished step, collapsed to a small chip; tap to manage / turn off. */
@Composable
private fun DoneChip(text: String, onClick: () -> Unit) {
    val c = SaqrTheme.colors
    val description = stringResource(R.string.cd_step_done, text)
    Surface(
        onClick = onClick,
        shape = SaqrTheme.shapes.pill,
        color = c.surface,
        contentColor = c.ink,
        border = BorderStroke(1.dp, c.line),
        modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = description },
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            // Drawn check (a font glyph renders as a "V" in IBM Plex Sans Arabic).
            Canvas(Modifier.size(16.dp)) {
                drawCircle(SaqrPalette.SafeFill)
                val s = size.width
                val check = androidx.compose.ui.graphics.Path().apply {
                    moveTo(s * 0.28f, s * 0.52f)
                    lineTo(s * 0.44f, s * 0.67f)
                    lineTo(s * 0.73f, s * 0.36f)
                }
                drawPath(
                    check,
                    SaqrPalette.Obsidian,
                    style = Stroke(1.8.dp.toPx(), cap = StrokeCap.Round, join = androidx.compose.ui.graphics.StrokeJoin.Round),
                )
            }
            Spacer(Modifier.width(6.dp))
            Text(text, style = MaterialTheme.typography.labelMedium, color = c.ink)
        }
    }
}

private fun startSafely(context: Context, intent: Intent): Boolean = try {
    if (context !is Activity) intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    context.startActivity(intent)
    true
} catch (_: ActivityNotFoundException) {
    false
} catch (_: SecurityException) {
    false
}

fun openAppNotificationSettings(context: Context) {
    val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
        .putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
    if (!startSafely(context, intent)) {
        startSafely(context, Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null)))
    }
}

fun openListenerSettings(context: Context) {
    if (Build.VERSION.SDK_INT >= 30) {
        val detail = Intent(Settings.ACTION_NOTIFICATION_LISTENER_DETAIL_SETTINGS)
            .putExtra(
                Settings.EXTRA_NOTIFICATION_LISTENER_COMPONENT_NAME,
                SaqrNotificationListenerService.component(context).flattenToString(),
            )
        if (startSafely(context, detail)) return
    }
    startSafely(context, Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS))
}
