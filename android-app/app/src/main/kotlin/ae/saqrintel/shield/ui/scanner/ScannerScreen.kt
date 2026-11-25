package ae.saqrintel.shield.ui.scanner

import ae.saqrintel.shield.R
import ae.saqrintel.shield.ui.common.Pill
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.SecondaryButton
import android.content.ClipboardManager
import android.widget.Toast
import ae.saqrintel.shield.ui.common.ScreenColumn
import ae.saqrintel.shield.ui.common.SaqrCard
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.ui.verdict.VerdictCard
import ae.saqrintel.shield.ui.verdict.VerdictSheet
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel

/** Sample scam SMS for the "Fake TAMM fine" chip. The domain is an invented look-alike. */
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
fun ScannerScreen(
    padding: PaddingValues,
    incoming: String? = null,
    onIncomingUsed: () -> Unit = {},
    vm: ScannerViewModel = viewModel(),
) {
    val s by vm.state.collectAsStateWithLifecycle()
    val c = SaqrTheme.colors
    val context = LocalContext.current
    val nothingCopied = stringResource(R.string.scan_copied_empty)

    // Text shared to Saqr from another app: fill it in and check it straight away.
    LaunchedEffect(incoming) {
        if (incoming != null) {
            vm.useSample(ScanMode.AUTO, incoming)
            vm.check()
            onIncomingUsed()
        }
    }

    ScreenColumn(padding) {
        Text(
            stringResource(R.string.scan_title),
            style = MaterialTheme.typography.headlineSmall,
            color = c.ink,
            modifier = Modifier.semantics { heading() },
        )

        // Input card (the web hero card) ------------------------------------------------------------
        SaqrCard {
            // Modes: quiet, Auto preselected, the rest scroll sideways.
            Row(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
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
                placeholder = { Text(stringResource(placeholder(s.mode)), color = c.inkSoft, fontSize = 16.sp) },
                textStyle = MaterialTheme.typography.bodyLarge.copy(fontSize = 16.sp),
                minLines = if (s.mode == ScanMode.PHONE || s.mode == ScanMode.WEB) 1 else 3,
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
            // The clipboard is read only when this is tapped (Android then shows its own "pasted" notice).
            if (s.input.isEmpty() && !s.loading) {
                SecondaryButton(
                    text = stringResource(R.string.scan_copied),
                    onClick = {
                        val clip = try {
                            context.getSystemService(ClipboardManager::class.java)?.primaryClip
                                ?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(context)?.toString()?.trim()
                        } catch (_: RuntimeException) {
                            null
                        }
                        if (clip.isNullOrEmpty()) {
                            Toast.makeText(context, nothingCopied, Toast.LENGTH_SHORT).show()
                        } else {
                            vm.useSample(ScanMode.AUTO, clip)
                            vm.check()
                        }
                    },
                )
            }

            val error = s.error
            val status = when {
                s.loading && s.slow -> stringResource(R.string.scan_waking)
                error != null -> errorText(error)
                else -> null
            }
            if (status != null) {
                Text(
                    status,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (error != null) c.suspiciousInk else c.inkSoft,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
            }

            FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                SampleChip(stringResource(R.string.sample_tamm)) { vm.useSample(ScanMode.MESSAGE, SAMPLE_TAMM_SMS) }
                SampleChip(stringResource(R.string.sample_bank_email)) { vm.useSample(ScanMode.EMAIL, SAMPLE_BANK_EMAIL) }
                SampleChip(stringResource(R.string.sample_official)) { vm.useSample(ScanMode.WEB, SAMPLE_OFFICIAL) }
            }
        }

        // Verdict card, inline -------------------------------------------------------------------
        val result = s.result
        if (result != null && !s.loading) {
            VerdictCard(result, onDetails = vm::reopenSheet)
        }
    }

    val result = s.result
    if (s.showSheet && result != null) {
        VerdictSheet(result, onDismiss = vm::dismissSheet)
    }
}

@Composable
private fun SampleChip(text: String, onClick: () -> Unit) {
    Pill(text, selected = false, onClick = onClick, role = Role.Button)
}

@Composable
private fun SmallField(value: String, onChange: (String) -> Unit, label: Int, type: KeyboardType) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(stringResource(label)) },
        textStyle = MaterialTheme.typography.bodyLarge.copy(fontSize = 16.sp),
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = type),
        colors = fieldColors(),
        shape = SaqrTheme.shapes.control,
        modifier = Modifier.fillMaxWidth(),
    )
}

/** Hairline field, ink focus ring (focus is ink, never a verdict colour). */
@Composable
private fun fieldColors() = OutlinedTextFieldDefaults.colors(
    focusedBorderColor = SaqrTheme.colors.ink,
    unfocusedBorderColor = SaqrTheme.colors.line,
    focusedLabelColor = SaqrTheme.colors.ink,
    unfocusedLabelColor = SaqrTheme.colors.inkSoft,
    cursorColor = SaqrTheme.colors.ink,
    focusedTextColor = SaqrTheme.colors.ink,
    unfocusedTextColor = SaqrTheme.colors.ink,
    focusedContainerColor = SaqrTheme.colors.surface,
    unfocusedContainerColor = SaqrTheme.colors.surface,
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
