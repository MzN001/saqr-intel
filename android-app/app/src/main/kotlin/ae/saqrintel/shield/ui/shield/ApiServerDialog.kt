package ae.saqrintel.shield.ui.shield

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.ApiClient
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.Settings
import ae.saqrintel.shield.ui.theme.SaqrTheme
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

private sealed interface PingState {
    data object Idle : PingState
    data object Running : PingState
    data class Ok(val ms: Long) : PingState
    data object Waking : PingState
    data object Failed : PingState
}

/** Edit the API base URL, ping /health, reset to the default. */
@Composable
fun ApiServerDialog(onDismiss: () -> Unit) {
    val context = LocalContext.current
    val graph = remember { context.appGraph }
    val scope = rememberCoroutineScope()
    val c = SaqrTheme.colors
    val debug = graph?.settings?.isDebugBuild == true

    var url by remember { mutableStateOf("") }
    var invalid by remember { mutableStateOf(false) }
    var ping by remember { mutableStateOf<PingState>(PingState.Idle) }
    LaunchedEffect(Unit) { url = graph?.settings?.currentBaseUrl() ?: ApiClient.DEFAULT_BASE_URL }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = c.surface,
        title = { Text(stringResource(R.string.api_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    stringResource(if (debug) R.string.api_hint_debug else R.string.api_hint),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.inkSoft,
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = {
                        url = it.trim()
                        invalid = false
                        ping = PingState.Idle
                    },
                    singleLine = true,
                    isError = invalid,
                    label = { Text(stringResource(R.string.api_label)) },
                    supportingText = if (invalid) {
                        { Text(stringResource(R.string.api_invalid)) }
                    } else {
                        null
                    },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier = Modifier.fillMaxWidth(),
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    TextButton(
                        enabled = ping != PingState.Running,
                        onClick = {
                            val valid = Settings.validateBaseUrl(url, debug)
                            if (valid == null || graph == null) {
                                invalid = true
                                return@TextButton
                            }
                            ping = PingState.Running
                            scope.launch {
                                ping = when (val r = graph.api.health(valid)) {
                                    is ApiResult.Ok -> PingState.Ok(r.latencyMs)
                                    ApiResult.ServerWaking -> PingState.Waking
                                    else -> PingState.Failed
                                }
                            }
                        },
                    ) { Text(stringResource(R.string.api_ping)) }
                    Spacer(Modifier.width(8.dp))
                    PingBadge(ping)
                }
                TextButton(onClick = {
                    url = ApiClient.DEFAULT_BASE_URL
                    invalid = false
                    ping = PingState.Idle
                    scope.launch { graph?.settings?.resetApiBaseUrl() }
                }) { Text(stringResource(R.string.api_reset)) }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                scope.launch {
                    val saved = graph?.settings?.setApiBaseUrl(url)
                    if (saved == null) invalid = true else onDismiss()
                }
            }) { Text(stringResource(R.string.action_save)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
    )
}

@Composable
private fun PingBadge(state: PingState) {
    val c = SaqrTheme.colors
    val (color: Color, text: String) = when (state) {
        PingState.Idle -> return
        PingState.Running -> c.inkSoft to stringResource(R.string.api_ping_running)
        is PingState.Ok -> c.shield to stringResource(R.string.api_ping_ok, state.ms.toString())
        PingState.Waking -> c.caution to stringResource(R.string.api_ping_waking)
        PingState.Failed -> c.caution to stringResource(R.string.api_ping_failed)
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(8.dp).background(color, CircleShape))
        Spacer(Modifier.width(6.dp))
        Text(text, style = MaterialTheme.typography.labelMedium, color = color)
    }
}
