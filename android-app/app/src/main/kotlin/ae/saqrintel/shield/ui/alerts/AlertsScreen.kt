package ae.saqrintel.shield.ui.alerts

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.common.FalconMark
import ae.saqrintel.shield.ui.common.NeutralChip
import ae.saqrintel.shield.ui.common.SaqrCard
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.common.VerdictChip
import ae.saqrintel.shield.ui.theme.SaqrTheme
import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.launch

@Composable
fun AlertsScreen(padding: PaddingValues, onOpen: (VerdictInfo) -> Unit) {
    val context = LocalContext.current
    val graph = remember { context.appGraph }
    val c = SaqrTheme.colors
    val scope = rememberCoroutineScope()
    val alerts by remember { graph?.alertStore?.alerts ?: flowOf(emptyList()) }
        .collectAsStateWithLifecycle(initialValue = emptyList())
    var confirmClear by remember { mutableStateOf(false) }

    ScreenColumn(padding) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            Text(
                stringResource(R.string.alerts_title),
                style = MaterialTheme.typography.headlineSmall,
                color = c.ink,
                modifier = Modifier
                    .weight(1f)
                    .semantics { heading() },
            )
            if (alerts.isNotEmpty()) {
                TextButton(onClick = { confirmClear = true }) {
                    Text(stringResource(R.string.alerts_clear), style = MaterialTheme.typography.labelLarge, color = c.inkSoft)
                }
            }
        }

        if (alerts.isEmpty()) {
            SaqrCard(padding = 24.dp) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
                    Box(
                        Modifier
                            .size(72.dp)
                            .background(c.muted, CircleShape),
                        contentAlignment = Alignment.Center,
                    ) {
                        FalconMark(40.dp)
                    }
                    Spacer(Modifier.size(12.dp))
                    Text(
                        stringResource(R.string.alerts_empty),
                        style = MaterialTheme.typography.titleMedium,
                        color = c.ink,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.size(4.dp))
                    Text(
                        stringResource(R.string.alerts_body),
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.inkSoft,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                alerts.forEach { a -> AlertCard(a) { onOpen(a.toVerdictInfo()) } }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            containerColor = c.surface,
            title = { Text(stringResource(R.string.alerts_clear_title)) },
            text = { Text(stringResource(R.string.alerts_clear_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmClear = false
                    scope.launch { graph?.alertStore?.clear() }
                }) { Text(stringResource(R.string.alerts_clear)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }
}

/** One timeline card: channel, target, score badge, relative time and a single "Inspect" action. */
@Composable
private fun AlertCard(a: AlertRecord, onInspect: () -> Unit) {
    val c = SaqrTheme.colors
    val v = a.verdictValue
    SaqrCard(padding = 16.dp, spacing = 10.dp) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
            NeutralChip(stringResource(kindChip(a.kind)))
            Spacer(Modifier.width(8.dp))
            Text(
                DateUtils.getRelativeTimeSpanString(a.time, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString(),
                style = MaterialTheme.typography.labelMedium,
                color = c.inkSoft,
                maxLines = 1,
                modifier = Modifier.weight(1f),
            )
            VerdictChip(a.score?.let { "$it/100" } ?: "–", v)
        }
        val label = a.label
        if (label != null) {
            Text(
                label,
                style = MaterialTheme.typography.bodyLarge.copy(
                    fontFamily = FontFamily.Monospace,
                    fontSize = 15.sp,
                    textDirection = TextDirection.Ltr,
                ),
                color = c.ink,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        } else {
            Text(
                stringResource(R.string.alerts_text_message),
                style = MaterialTheme.typography.titleSmall,
                color = c.ink,
            )
        }
        TextButton(
            onClick = onInspect,
            contentPadding = PaddingValues(horizontal = 0.dp, vertical = 4.dp),
            modifier = Modifier.padding(0.dp),
        ) {
            Text(
                stringResource(R.string.alerts_inspect) + if (isArabic()) "  ←" else "  →",
                style = MaterialTheme.typography.labelLarge,
                color = c.ink,
            )
        }
    }
}

private fun kindChip(k: AlertKind) = when (k) {
    AlertKind.SMS -> R.string.chip_sms
    AlertKind.WHATSAPP -> R.string.chip_whatsapp
    AlertKind.EMAIL -> R.string.chip_email
    AlertKind.WEB -> R.string.chip_web
    AlertKind.MANUAL -> R.string.chip_manual
    AlertKind.MESSAGE -> R.string.chip_message
}
