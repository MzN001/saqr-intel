package ae.saqrintel.shield.ui.alerts

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.Tile
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.common.verdictInk
import ae.saqrintel.shield.ui.common.verdictLabel
import ae.saqrintel.shield.ui.theme.SaqrTheme
import android.text.format.DateUtils
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
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
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
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
                    Text(stringResource(R.string.alerts_clear), color = c.inkSoft)
                }
            }
        }

        if (alerts.isEmpty()) {
            Tile {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .size(40.dp)
                            .background(c.muted, SaqrTheme.shapes.control),
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(painterResource(R.drawable.ic_tab_shield), contentDescription = null, tint = c.shield)
                    }
                    Spacer(Modifier.width(12.dp))
                    Text(stringResource(R.string.alerts_empty), style = MaterialTheme.typography.titleMedium, color = c.ink)
                }
                Text(stringResource(R.string.alerts_body), style = MaterialTheme.typography.bodyMedium, color = c.inkSoft)
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                alerts.forEach { a -> AlertRow(a) { onOpen(a.toVerdictInfo()) } }
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

@Composable
private fun AlertRow(a: AlertRecord, onClick: () -> Unit) {
    val c = SaqrTheme.colors
    val arabic = isArabic()
    val v = a.verdictValue
    Surface(
        onClick = onClick,
        shape = SaqrTheme.shapes.tile,
        color = c.surface,
        contentColor = c.ink,
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, c.line, SaqrTheme.shapes.tile),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(16.dp)) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        stringResource(kindChip(a.kind)),
                        style = MaterialTheme.typography.labelSmall,
                        color = c.ink,
                        modifier = Modifier
                            .background(c.muted, SaqrTheme.shapes.stamp)
                            .padding(horizontal = 8.dp, vertical = 3.dp),
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        DateUtils.getRelativeTimeSpanString(a.time, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString(),
                        style = MaterialTheme.typography.labelMedium,
                        color = c.inkSoft,
                    )
                }
                val entity = if (arabic) a.entityAr ?: a.entityEn else a.entityEn
                val title = a.label ?: entity?.let { stringResource(R.string.alerts_fake_entity, it) }
                    ?: stringResource(R.string.alerts_text_message)
                Text(
                    title,
                    style = MaterialTheme.typography.titleSmall.copy(
                        textDirection = if (a.label != null) TextDirection.Ltr else TextDirection.Content,
                    ),
                    color = c.ink,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                if (a.label != null && entity != null) {
                    Text(
                        stringResource(R.string.alerts_fake_entity, entity),
                        style = MaterialTheme.typography.bodySmall,
                        color = c.inkSoft,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    a.score?.toString() ?: "–",
                    style = MaterialTheme.typography.titleLarge.tabular(),
                    color = verdictInk(v),
                )
                Text(verdictLabel(v), style = MaterialTheme.typography.labelSmall, color = verdictInk(v))
            }
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
