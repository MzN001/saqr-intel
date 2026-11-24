package ae.saqrintel.shield.ui.scanner

import ae.saqrintel.shield.R
import ae.saqrintel.shield.ui.common.Pill
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.Tile
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.common.verdictInk
import ae.saqrintel.shield.ui.common.verdictLabel
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.ui.verdict.VerdictSheet
import ae.saqrintel.shield.util.Defang
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

/** Sample scam SMS for the "Try a fake TAMM fine" chip. The domain is an invented look-alike. */
const val SAMPLE_TAMM_SMS =
    "TAMM: You have an unpaid traffic fine of AED 350. Pay within 24 hours to avoid a black point: " +
        "https://tamm-smart-pay.net/fine"

/** Sample spoofed bank email for the "Spoofed bank email" chip (invented look-alike domain). */
const val SAMPLE_BANK_EMAIL =
    "From: FAB Security <alerts@bankfab-secure-verify.com>\n" +
        "Subject: Your account has been suspended\n\n" +
        "Dear customer, we detected unusual activity. Verify your account within 12 hours at " +
        "https://bankfab-secure-verify.com/login and enter your card number and OTP to restore access."

const val SAMPLE_OFFICIAL = "https://www.adpolice.gov.ae"

@Composable
fun ScannerScreen(padding: PaddingValues, vm: ScannerViewModel = viewModel()) {
    val s by vm.state.collectAsStateWithLifecycle()
    val c = SaqrTheme.colors

    ScreenColumn(padding) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                stringResource(R.string.scan_title),
                style = MaterialTheme.typography.headlineSmall,
                color = c.ink,
                modifier = Modifier.semantics { heading() },
            )
            Text(stringResource(R.string.scan_hint), style = MaterialTheme.typography.bodyMedium, color = c.inkSoft)
        }

        Tile {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
            ) {
                ScanMode.entries.forEach { m ->
                    Pill(stringResource(modeLabel(m)), selected = s.mode == m, onClick = { vm.setMode(m) })
                }
            }

            OutlinedTextField(
                value = s.input,
                onValueChange = vm::setInput,
                placeholder = { Text(stringResource(placeholder(s.mode)), color = c.inkSoft) },
                label = { Text(stringResource(R.string.scan_input_label)) },
                minLines = if (s.mode == ScanMode.PHONE || s.mode == ScanMode.WEB) 1 else 4,
                maxLines = 10,
                keyboardOptions = KeyboardOptions(
                    keyboardType = when (s.mode) {
                        ScanMode.PHONE -> KeyboardType.Phone
                        ScanMode.WEB -> KeyboardType.Uri
                        else -> KeyboardType.Text
                    },
                ),
                colors = fieldColors(),
                shape = SaqrTheme.shapes.control,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp),
            )
            if (s.mode == ScanMode.MESSAGE) {
                SmallField(s.sender, vm::setSender, R.string.scan_sender, KeyboardType.Text)
            }
            if (s.mode == ScanMode.MAPS) {
                SmallField(s.mapsWebsite, vm::setMapsWebsite, R.string.scan_maps_website, KeyboardType.Uri)
                SmallField(s.mapsPhone, vm::setMapsPhone, R.string.scan_maps_phone, KeyboardType.Phone)
            }

            PrimaryButton(
                text = stringResource(if (s.loading) R.string.scan_checking else R.string.scan_check),
                onClick = vm::check,
                loading = s.loading,
            )

            val error = s.error
            val status = when {
                s.loading && s.slow -> stringResource(R.string.scan_waking)
                error != null -> errorText(error)
                else -> null
            }
            if (status != null) {
                Text(
                    status,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (error != null) c.caution else c.inkSoft,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }
        }

        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(R.string.scan_try), style = MaterialTheme.typography.labelLarge, color = c.inkSoft)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Pill(stringResource(R.string.sample_tamm), false, { vm.useSample(ScanMode.MESSAGE, SAMPLE_TAMM_SMS) })
                Pill(stringResource(R.string.sample_bank_email), false, { vm.useSample(ScanMode.EMAIL, SAMPLE_BANK_EMAIL) })
                Pill(stringResource(R.string.sample_official), false, { vm.useSample(ScanMode.WEB, SAMPLE_OFFICIAL) })
            }
        }

        val last = s.result
        if (last != null && !s.showSheet) {
            Tile(Modifier) {
                Text(stringResource(R.string.scan_last), style = MaterialTheme.typography.labelLarge, color = c.inkSoft)
                Row(verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                    Text(
                        last.score?.toString() ?: "–",
                        style = MaterialTheme.typography.headlineSmall.tabular(),
                        color = verdictInk(last.verdict),
                    )
                    Text(
                        "  " + verdictLabel(last.verdict) + (last.domain?.let { " · " + Defang.defang(it) }.orEmpty()),
                        style = MaterialTheme.typography.bodyMedium,
                        color = c.ink,
                        modifier = Modifier.weight(1f),
                    )
                }
                Pill(stringResource(R.string.scan_view_details), false, vm::reopenSheet)
            }
        }
    }

    val result = s.result
    if (s.showSheet && result != null) {
        VerdictSheet(result, onDismiss = vm::dismissSheet)
    }
}

@Composable
private fun SmallField(value: String, onChange: (String) -> Unit, label: Int, type: KeyboardType) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(stringResource(label)) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = type),
        colors = fieldColors(),
        shape = SaqrTheme.shapes.control,
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = SaqrTheme.colors.shield,
    unfocusedBorderColor = SaqrTheme.colors.line,
    focusedLabelColor = SaqrTheme.colors.shield,
    unfocusedLabelColor = SaqrTheme.colors.inkSoft,
    cursorColor = SaqrTheme.colors.shield,
    focusedTextColor = SaqrTheme.colors.ink,
    unfocusedTextColor = SaqrTheme.colors.ink,
    focusedContainerColor = SaqrTheme.colors.canvas,
    unfocusedContainerColor = SaqrTheme.colors.canvas,
)

@Composable
private fun errorText(e: ScanError): String = when (e) {
    ScanError.Empty -> stringResource(R.string.err_empty)
    ScanError.RateLimited -> stringResource(R.string.err_rate_limited)
    ScanError.Waking -> stringResource(R.string.err_waking)
    ScanError.Failed -> stringResource(R.string.err_failed)
    is ScanError.Invalid -> stringResource(R.string.err_invalid, e.message)
}

private fun modeLabel(m: ScanMode) = when (m) {
    ScanMode.AUTO -> R.string.mode_auto
    ScanMode.WEB -> R.string.mode_web
    ScanMode.MESSAGE -> R.string.mode_message
    ScanMode.EMAIL -> R.string.mode_email
    ScanMode.PHONE -> R.string.mode_phone
    ScanMode.MAPS -> R.string.mode_maps
}

private fun placeholder(m: ScanMode) = when (m) {
    ScanMode.AUTO -> R.string.ph_auto
    ScanMode.WEB -> R.string.ph_web
    ScanMode.MESSAGE -> R.string.ph_message
    ScanMode.EMAIL -> R.string.ph_email
    ScanMode.PHONE -> R.string.ph_phone
    ScanMode.MAPS -> R.string.ph_maps
}
