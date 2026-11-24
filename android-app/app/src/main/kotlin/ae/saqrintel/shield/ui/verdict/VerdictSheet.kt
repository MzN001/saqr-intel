package ae.saqrintel.shield.ui.verdict

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.SecondaryButton
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.common.verdictFill
import ae.saqrintel.shield.ui.common.verdictInk
import ae.saqrintel.shield.ui.common.verdictLabel
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.util.Aman
import ae.saqrintel.shield.util.Defang
import ae.saqrintel.shield.util.XAlert
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private enum class FalseAlarmState { IDLE, SENDING, THANKS, FAILED }

/** Result sheet shared by the scanner, the alerts timeline and guard notifications. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerdictSheet(info: VerdictInfo, onDismiss: () -> Unit) {
    val c = SaqrTheme.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        containerColor = c.surface,
        contentColor = c.ink,
    ) {
        VerdictContent(info)
    }
}

@Composable
private fun VerdictContent(info: VerdictInfo) {
    val c = SaqrTheme.colors
    val context = LocalContext.current
    val arabic = isArabic()
    val scope = rememberCoroutineScope()
    var falseAlarm by remember(info.scanId) { mutableStateOf(FalseAlarmState.IDLE) }
    val copiedText = stringResource(R.string.toast_copied)
    val noAppText = stringResource(R.string.toast_no_app)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp)
            .padding(bottom = 24.dp)
            .navigationBarsPadding(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        // Score + verdict ---------------------------------------------------------------------
        val label = verdictLabel(info.verdict)
        Row(verticalAlignment = Alignment.Bottom, modifier = Modifier.semantics(mergeDescendants = true) { heading() }) {
            if (info.score != null) {
                Text(
                    text = info.score.toString(), // Western digits in both languages
                    style = MaterialTheme.typography.displaySmall.tabular().copy(fontSize = 56.sp, lineHeight = 60.sp),
                    color = verdictInk(info.verdict),
                    modifier = Modifier.semantics { contentDescription = "${info.score} / 100" },
                )
                Text(
                    text = "/100",
                    style = MaterialTheme.typography.titleMedium.tabular(),
                    color = c.inkSoft,
                    modifier = Modifier.padding(start = 4.dp, bottom = 10.dp),
                )
                Spacer(Modifier.width(16.dp))
            }
            Column(Modifier.padding(bottom = 8.dp)) {
                Text(
                    text = if (info.kind == ScanKind.PHONE) phoneLevelLabel(info) else label,
                    style = MaterialTheme.typography.titleLarge.copy(fontWeight = FontWeight.Bold),
                    color = verdictInk(info.verdict),
                )
                Text(
                    text = stringResource(kindLabel(info.kind)),
                    style = MaterialTheme.typography.labelMedium,
                    color = c.inkSoft,
                )
            }
        }
        Text(
            text = stringResource(instruction(info)),
            style = MaterialTheme.typography.titleMedium,
            color = c.ink,
        )

        Meter(info.verdict)

        // Who it pretends to be / verified -----------------------------------------------------
        val entity = if (arabic) XAlert.entityAr(info) ?: info.entityEn else info.entityEn
        if (info.verifiedOfficial) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(c.shield, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.verdict_verified),
                    style = MaterialTheme.typography.labelLarge,
                    color = c.shield,
                )
            }
        }
        if (entity != null && info.verdict != Verdict.SAFE) {
            Detail(stringResource(R.string.verdict_pretends), entity)
        }
        if (info.domain != null && info.kind != ScanKind.PHONE) {
            Detail(stringResource(R.string.verdict_address), Defang.defang(info.domain), ltr = true)
        }
        if (info.officialDomain != null && info.verdict != Verdict.SAFE) {
            Detail(stringResource(R.string.verdict_official_site), info.officialDomain, ltr = true)
        }

        // Reasons ------------------------------------------------------------------------------
        if (info.reasons.isNotEmpty()) {
            HorizontalDivider(color = c.line)
            Text(
                text = stringResource(if (info.verdict == Verdict.SAFE) R.string.verdict_notes else R.string.verdict_reasons),
                style = MaterialTheme.typography.labelLarge,
                color = c.inkSoft,
            )
            info.reasons.take(3).forEach { r ->
                Row {
                    Text("•", color = verdictInk(info.verdict), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.width(8.dp))
                    Text(if (arabic) r.ar else r.en, style = MaterialTheme.typography.bodyMedium, color = c.ink)
                }
            }
        }

        // Links / phones found in a message ------------------------------------------------------
        if ((info.kind == ScanKind.MESSAGE || info.kind == ScanKind.EMAIL) && (info.links.isNotEmpty() || info.phones.isNotEmpty())) {
            HorizontalDivider(color = c.line)
            Text(stringResource(R.string.verdict_found), style = MaterialTheme.typography.labelLarge, color = c.inkSoft)
            info.links.take(5).forEach { l ->
                val v = l.verdict ?: if (l.official) Verdict.SAFE else null
                FoundRow(
                    Defang.defang(l.domain),
                    when {
                        l.official -> stringResource(R.string.verdict_link_official)
                        v != null -> verdictLabel(v) + (l.score?.let { " · $it" }.orEmpty())
                        else -> stringResource(R.string.verdict_link_not_checked)
                    },
                    v,
                )
            }
            info.phones.take(5).forEach { p ->
                FoundRow(
                    p.masked,
                    when (p.level) {
                        "official" -> stringResource(R.string.phone_level_official)
                        "danger" -> stringResource(R.string.phone_level_danger)
                        "caution" -> stringResource(R.string.phone_level_caution)
                        else -> stringResource(R.string.phone_level_none)
                    },
                    when (p.level) {
                        "official" -> Verdict.SAFE
                        "danger" -> Verdict.SCAM
                        "caution" -> Verdict.SUSPICIOUS
                        else -> null
                    },
                )
            }
        }

        // Actions --------------------------------------------------------------------------------
        HorizontalDivider(color = c.line)
        if (info.xEligible) {
            PrimaryButton(
                text = stringResource(R.string.action_warn_x),
                onClick = {
                    if (!VerdictActions.warnOnX(context, info, arabic)) {
                        Toast.makeText(context, noAppText, Toast.LENGTH_SHORT).show()
                    }
                },
            )
        }
        if (info.verdict != Verdict.SAFE) {
            SecondaryButton(
                text = stringResource(R.string.action_call_aman),
                onClick = {
                    if (!Aman.dial(context)) Toast.makeText(context, noAppText, Toast.LENGTH_SHORT).show()
                },
            )
        }
        SecondaryButton(
            text = stringResource(R.string.action_copy_report),
            onClick = {
                if (Aman.copy(context, "SAQR report", Aman.reportText(info, arabic))) {
                    Toast.makeText(context, copiedText, Toast.LENGTH_SHORT).show()
                }
            },
        )
        if (info.verdict != Verdict.SAFE && info.scanId != null) {
            when (falseAlarm) {
                FalseAlarmState.THANKS -> Text(
                    stringResource(R.string.false_alarm_thanks),
                    style = MaterialTheme.typography.bodyMedium,
                    color = c.shield,
                )
                else -> TextButton(
                    enabled = falseAlarm != FalseAlarmState.SENDING,
                    onClick = {
                        val graph = context.appGraph ?: return@TextButton
                        val id = info.scanId
                        falseAlarm = FalseAlarmState.SENDING
                        scope.launch {
                            falseAlarm = when (graph.api.reportFalseAlarm(id)) {
                                is ApiResult.Ok -> FalseAlarmState.THANKS
                                else -> FalseAlarmState.FAILED
                            }
                        }
                    },
                ) {
                    Text(
                        stringResource(
                            when (falseAlarm) {
                                FalseAlarmState.SENDING -> R.string.false_alarm_sending
                                FalseAlarmState.FAILED -> R.string.false_alarm_retry
                                else -> R.string.action_false_alarm
                            },
                        ),
                        style = MaterialTheme.typography.labelLarge,
                        color = c.inkSoft,
                    )
                }
            }
        }
        Text(
            text = stringResource(privacyLine(info.kind)),
            style = MaterialTheme.typography.labelMedium,
            color = c.inkSoft,
        )
        Text(
            text = stringResource(R.string.aman_footer),
            style = MaterialTheme.typography.labelMedium,
            color = c.inkSoft,
        )
    }
}

/** Safe / Suspicious / Scam with only the active segment coloured. */
@Composable
private fun Meter(active: Verdict) {
    val c = SaqrTheme.colors
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.fillMaxWidth()) {
        Verdict.entries.forEach { v ->
            val on = v == active
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(8.dp)
                        .background(if (on) verdictFill(v) else c.muted, SaqrTheme.shapes.pill),
                )
                Text(
                    text = stringResource(
                        when (v) {
                            Verdict.SAFE -> R.string.meter_safe
                            Verdict.SUSPICIOUS -> R.string.meter_suspicious
                            Verdict.SCAM -> R.string.meter_scam
                        },
                    ),
                    style = MaterialTheme.typography.labelMedium,
                    color = if (on) verdictInk(v) else c.inkSoft,
                    fontWeight = if (on) FontWeight.Bold else FontWeight.Medium,
                )
            }
        }
    }
}

@Composable
private fun Detail(label: String, value: String, ltr: Boolean = false) {
    val c = SaqrTheme.colors
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
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

@Composable
private fun FoundRow(value: String, status: String, verdict: Verdict?) {
    val c = SaqrTheme.colors
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium.copy(textDirection = TextDirection.Ltr),
            color = c.ink,
            modifier = Modifier.weight(1f),
        )
        Text(
            status,
            style = MaterialTheme.typography.labelMedium.tabular(),
            color = verdict?.let { verdictInk(it) } ?: c.inkSoft,
        )
    }
}

@Composable
private fun phoneLevelLabel(info: VerdictInfo): String = stringResource(
    when (info.phoneLevel) {
        "official" -> R.string.phone_level_official
        "danger" -> R.string.phone_level_danger
        "caution" -> R.string.phone_level_caution
        else -> R.string.phone_level_none
    },
)

private fun kindLabel(kind: ScanKind) = when (kind) {
    ScanKind.WEB -> R.string.kind_web
    ScanKind.MAPS -> R.string.kind_maps
    ScanKind.MESSAGE -> R.string.kind_message
    ScanKind.EMAIL -> R.string.kind_email
    ScanKind.PHONE -> R.string.kind_phone
}

private fun instruction(info: VerdictInfo): Int = when (info.kind) {
    ScanKind.PHONE -> when (info.verdict) {
        Verdict.SAFE -> if (info.phoneLevel == "official") R.string.instr_phone_official else R.string.instr_phone_none
        Verdict.SUSPICIOUS -> R.string.instr_phone_caution
        Verdict.SCAM -> R.string.instr_phone_danger
    }
    ScanKind.MESSAGE, ScanKind.EMAIL -> when (info.verdict) {
        Verdict.SAFE -> R.string.instr_message_safe
        Verdict.SUSPICIOUS -> R.string.instr_message_suspicious
        Verdict.SCAM -> R.string.instr_message_scam
    }
    ScanKind.WEB, ScanKind.MAPS -> when (info.verdict) {
        Verdict.SAFE -> R.string.instr_web_safe
        Verdict.SUSPICIOUS -> R.string.instr_web_suspicious
        Verdict.SCAM -> R.string.instr_web_scam
    }
}

private fun privacyLine(kind: ScanKind) = when (kind) {
    ScanKind.MESSAGE -> R.string.privacy_message
    ScanKind.EMAIL -> R.string.privacy_email
    ScanKind.PHONE -> R.string.privacy_phone
    ScanKind.WEB, ScanKind.MAPS -> R.string.privacy_web
}
