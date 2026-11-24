package ae.saqrintel.shield.ui.shield

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.guard.AlertNotifier
import ae.saqrintel.shield.guard.SaqrBrowserGuardService
import ae.saqrintel.shield.guard.SaqrNotificationListenerService
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.Tile
import ae.saqrintel.shield.ui.common.tabular
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
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
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
    var showApi by remember { mutableStateOf(false) }

    // After a second "Don't allow" Android stops showing the prompt: then open the app's settings.
    var denials by rememberSaveable { mutableIntStateOf(0) }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        notificationsOn = AlertNotifier.canNotify(context)
        if (!granted && ++denials >= 2) openAppNotificationSettings(context)
    }

    ScreenColumn(padding) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                stringResource(R.string.shield_heading),
                style = MaterialTheme.typography.headlineSmall,
                color = c.ink,
                modifier = Modifier
                    .weight(1f)
                    .semantics { heading() },
            )
            Surface(
                onClick = { showApi = true },
                shape = SaqrTheme.shapes.pill,
                color = c.muted,
                contentColor = c.ink,
                modifier = Modifier.border(1.dp, c.line, SaqrTheme.shapes.pill),
            ) {
                Text(
                    stringResource(R.string.api_pill),
                    style = MaterialTheme.typography.labelMedium,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                )
            }
        }

        // Hero status ring -------------------------------------------------------------------------
        Tile {
            Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                val ring = if (protected) c.shield else c.caution
                Box(contentAlignment = Alignment.Center, modifier = Modifier.size(148.dp)) {
                    Canvas(Modifier.size(148.dp)) {
                        val w = 10.dp.toPx()
                        drawArc(c.muted, 0f, 360f, false, style = Stroke(w))
                        drawArc(
                            ring, -90f, if (protected) 360f else 240f, false,
                            style = Stroke(w, cap = StrokeCap.Round),
                        )
                    }
                    Icon(
                        painterResource(if (protected) R.drawable.ic_tab_shield else R.drawable.ic_shield_alert),
                        contentDescription = null,
                        tint = ring,
                        modifier = Modifier.size(48.dp),
                    )
                }
                Spacer(Modifier.size(12.dp))
                Text(
                    stringResource(if (protected) R.string.status_protected else R.string.status_action_needed),
                    style = MaterialTheme.typography.titleLarge,
                    color = ring,
                )
                Text(
                    stringResource(if (protected) R.string.status_protected_sub else R.string.status_action_sub),
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.inkSoft,
                    textAlign = TextAlign.Center,
                )
            }
            Row(Modifier.fillMaxWidth().padding(top = 8.dp)) {
                Metric(blocked, stringResource(R.string.metric_blocked), Modifier.weight(1f))
                Metric(checked, stringResource(R.string.metric_checked), Modifier.weight(1f))
            }
        }

        Text(
            stringResource(R.string.steps_title),
            style = MaterialTheme.typography.titleMedium,
            color = c.ink,
            modifier = Modifier.semantics { heading() },
        )

        // Step 1: notifications -----------------------------------------------------------------
        if (notificationsOn) {
            DonePill(stringResource(R.string.step1_done)) { openAppNotificationSettings(context) }
        } else {
            StepCard(1, R.string.step1_title, R.string.step1_body) {
                PrimaryButton(stringResource(R.string.step1_button), onClick = {
                    if (Build.VERSION.SDK_INT >= 33) {
                        permissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        openAppNotificationSettings(context)
                    }
                })
            }
        }

        // Step 2: message guard -------------------------------------------------------------------
        if (guardOn) {
            DonePill(stringResource(R.string.step2_done)) { showManageGuard = true }
        } else {
            StepCard(2, R.string.step2_title, R.string.step2_body) {
                PrimaryButton(stringResource(R.string.step2_button), onClick = { showConsent = true })
            }
        }

        // Step 3: web blocker (recommended; "Protected" needs steps 1-2 only) -----------------------
        if (webOn) {
            DonePill(stringResource(R.string.step3_done)) { showManageWeb = true }
        } else {
            StepCard(3, R.string.step3_title, R.string.step3_body, badge = R.string.step3_recommended) {
                PrimaryButton(stringResource(R.string.step3_button), onClick = { showWebConsent = true })
                if (Build.VERSION.SDK_INT >= 33) {
                    Text(
                        stringResource(R.string.step3_restricted),
                        style = MaterialTheme.typography.labelMedium,
                        color = c.inkSoft,
                    )
                }
            }
        }

        Text(
            stringResource(R.string.aman_footer),
            style = MaterialTheme.typography.labelLarge,
            color = c.inkSoft,
            modifier = Modifier.fillMaxWidth(),
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
                Text(
                    stringResource(R.string.web_consent_body),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                )
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
    if (showApi) {
        ApiServerDialog(onDismiss = { showApi = false })
    }
}

fun openAccessibilitySettings(context: Context) {
    startSafely(context, Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
}

@Composable
private fun Metric(value: Int, label: String, modifier: Modifier) {
    val c = SaqrTheme.colors
    Column(modifier, horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value.toString(), style = MaterialTheme.typography.headlineSmall.tabular(), color = c.ink)
        Text(label, style = MaterialTheme.typography.labelMedium, color = c.inkSoft, textAlign = TextAlign.Center)
    }
}

@Composable
private fun DonePill(text: String, onClick: () -> Unit) {
    val c = SaqrTheme.colors
    Surface(
        onClick = onClick,
        shape = SaqrTheme.shapes.pill,
        color = c.surface,
        contentColor = c.shield,
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, c.shield.copy(alpha = 0.5f), SaqrTheme.shapes.pill),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
            Box(
                Modifier
                    .size(22.dp)
                    .background(c.shield, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Text("✓", color = c.surface, style = MaterialTheme.typography.labelLarge)
            }
            Spacer(Modifier.width(10.dp))
            Text(text, style = MaterialTheme.typography.labelLarge, color = c.ink)
        }
    }
}

@Composable
private fun StepCard(
    number: Int,
    title: Int,
    body: Int,
    enabled: Boolean = true,
    badge: Int? = null,
    action: @Composable () -> Unit,
) {
    val c = SaqrTheme.colors
    Tile {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Box(
                Modifier
                    .size(28.dp)
                    .background(if (enabled) c.caution.copy(alpha = 0.18f) else c.muted, CircleShape),
                contentAlignment = Alignment.Center,
            ) {
                Text(number.toString(), style = MaterialTheme.typography.labelLarge.tabular(), color = if (enabled) c.caution else c.inkSoft)
            }
            Spacer(Modifier.width(12.dp))
            Text(
                stringResource(title),
                style = MaterialTheme.typography.titleMedium,
                color = if (enabled) c.ink else c.inkSoft,
                modifier = Modifier.weight(1f),
            )
            if (badge != null) {
                Text(
                    stringResource(badge),
                    style = MaterialTheme.typography.labelMedium,
                    color = c.inkSoft,
                    modifier = Modifier
                        .border(1.dp, c.line, SaqrTheme.shapes.pill)
                        .padding(horizontal = 10.dp, vertical = 4.dp),
                )
            }
        }
        Text(stringResource(body), style = MaterialTheme.typography.bodyMedium, color = c.inkSoft)
        action()
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
