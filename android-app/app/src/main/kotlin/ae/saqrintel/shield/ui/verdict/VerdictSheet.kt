package ae.saqrintel.shield.ui.verdict

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.common.PrimaryButton
import ae.saqrintel.shield.ui.common.RiskMeter
import ae.saqrintel.shield.ui.common.SaqrCard
import ae.saqrintel.shield.ui.common.SecondaryButton
import ae.saqrintel.shield.ui.common.VerdictChip
import ae.saqrintel.shield.ui.common.bilingualVerdict
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.common.tabular
import ae.saqrintel.shield.ui.common.verdictFill
import ae.saqrintel.shield.ui.common.verdictInk
import ae.saqrintel.shield.ui.common.verdictLabel
import ae.saqrintel.shield.ui.theme.SaqrPalette
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.util.Aman
import ae.saqrintel.shield.util.Defang
import ae.saqrintel.shield.util.XAlert
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.BottomSheetDefaults
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

private enum class FalseAlarmState { IDLE, SENDING, THANKS, FAILED }

/**
 * Inline verdict card (Scanner tab): defanged target, bold score / 100, EN + AR verdict, the
 * three-zone meter, up to three reasons in the current language, and the short actions.
 */
@Composable
fun VerdictCard(info: VerdictInfo, onDetails: () -> Unit, modifier: Modifier = Modifier) {
    val c = SaqrTheme.colors
    val context = LocalContext.current
    val arabic = isArabic()
    val noAppText = stringResource(R.string.toast_no_app)
    val copiedText = stringResource(R.string.toast_aman_copied)

    SaqrCard(modifier, spacing = 14.dp) {
        TargetLine(info)
        ScoreLine(info, big = 40)
        RiskMeter(info.score, info.verdict)
        Text(stringResource(instruction(info)), style = MaterialTheme.typography.titleSmall, color = c.ink)
        if (info.reasons.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                info.reasons.take(3).forEach { r -> ReasonRow(if (arabic) r.ar else r.en, info.verdict, maxLines = 2) }
            }
        }
        HorizontalDivider(color = c.line)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            if (info.xEligible) {
                SecondaryButton(
                    text = stringResource(R.string.notif_action_x),
                    fill = false,
                    onClick = {
                        if (!VerdictActions.warnOnX(context, info, arabic)) {
                            Toast.makeText(context, noAppText, Toast.LENGTH_SHORT).show()
                        }
                    },
                )
            }
            if (info.verdict != Verdict.SAFE) {
                SecondaryButton(
                    text = stringResource(R.string.action_copy_aman),
                    fill = false,
                    onClick = {
                        if (Aman.copy(context, "Saqr report", Aman.reportText(info, arabic))) {
                            Toast.makeText(context, copiedText, Toast.LENGTH_LONG).show()
                        }
                    },
                )
            }
        }
        TextButton(onClick = onDetails, contentPadding = PaddingValues(horizontal = 0.dp, vertical = 4.dp)) {
            Text(
                stringResource(R.string.action_full_details) + if (arabic) "  ←" else "  →",
                style = MaterialTheme.typography.labelLarge,
                color = c.ink,
            )
        }
    }
}

/** Result sheet shared by the scanner, the alerts timeline and guard notifications. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VerdictSheet(info: VerdictInfo, onDismiss: () -> Unit) {
    val c = SaqrTheme.colors
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        shape = RoundedCornerShape(topStart = 16.dp, topEnd = 16.dp),
        containerColor = c.surface,
        contentColor = c.ink,
        scrimColor = SaqrPalette.Obsidian.copy(alpha = 0.5f),
        tonalElevation = 0.dp,
        dragHandle = { BottomSheetDefaults.DragHandle(color = c.line) },
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
            .padding(horizontal = 20.dp)
            .padding(bottom = 20.dp)
            .navigationBarsPadding(),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text(
            text = stringResource(kindLabel(info.kind)),
            style = MaterialTheme.typography.labelMedium,
            color = c.inkSoft,
        )
        TargetLine(info)
        ScoreLine(info, big = 48)
        Text(
            text = stringResource(instruction(info)),
            style = MaterialTheme.typography.titleMedium,
            color = c.ink,
        )
        RiskMeter(info.score, info.verdict)

        // Who it pretends to be / verified -----------------------------------------------------
        val entity = if (arabic) XAlert.entityAr(info) ?: info.entityEn else info.entityEn
        val showEntity = entity != null && info.verdict != Verdict.SAFE
        val showOfficial = info.officialDomain != null && info.verdict != Verdict.SAFE
        if (info.verifiedOfficial || showEntity || showOfficial) {
            HorizontalDivider(color = c.line)
        }
        if (info.verifiedOfficial) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.size(10.dp).background(SaqrPalette.SafeFill, CircleShape))
                Spacer(Modifier.width(8.dp))
                Text(
                    text = stringResource(R.string.verdict_verified),
                    style = MaterialTheme.typography.labelLarge,
                    color = c.safeInk,
                )
            }
        }
        if (showEntity) Detail(stringResource(R.string.verdict_pretends), entity.orEmpty())
        if (showOfficial) Detail(stringResource(R.string.verdict_official_site), info.officialDomain.orEmpty(), ltr = true)

        // Reasons ------------------------------------------------------------------------------
        if (info.reasons.isNotEmpty()) {
            HorizontalDivider(color = c.line)
            Text(
                text = stringResource(if (info.verdict == Verdict.SAFE) R.string.verdict_notes else R.string.verdict_reasons),
                style = MaterialTheme.typography.labelMedium,
                color = c.inkSoft,
            )
            info.reasons.take(3).forEach { r -> ReasonRow(if (arabic) r.ar else r.en, info.verdict) }
        }

        // Links / phones found in a message ------------------------------------------------------
        if ((info.kind == ScanKind.MESSAGE || info.kind == ScanKind.EMAIL) && (info.links.isNotEmpty() || info.phones.isNotEmpty())) {
            HorizontalDivider(color = c.line)
            Text(stringResource(R.string.verdict_found), style = MaterialTheme.typography.labelMedium, color = c.inkSoft)
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

        // Actions: one primary, the rest secondary ------------------------------------------------
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
                if (Aman.copy(context, "Saqr report", Aman.reportText(info, arabic))) {
                    Toast.makeText(context, copiedText, Toast.LENGTH_SHORT).show()
                }
            },
        )
        if (info.verdict != Verdict.SAFE && info.scanId != null) {
            when (falseAlarm) {
                FalseAlarmState.THANKS -> Text(
                    stringResource(R.string.false_alarm_thanks),
                    style = MaterialTheme.typography.bodySmall,
                    color = c.inkSoft,
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
            style = MaterialTheme.typography.labelMedium.tabular(),
            color = c.inkSoft,
        )
    }
}

/** Defanged domain (LTR, mono) or what kind of thing was checked. */
@Composable
private fun TargetLine(info: VerdictInfo) {
    val c = SaqrTheme.colors
    val domain = info.domain
    if (domain != null && info.kind != ScanKind.PHONE) {
        Text(
            Defang.defang(domain),
            style = MaterialTheme.typography.bodyMedium.copy(
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
                textDirection = TextDirection.Ltr,
            ),
            color = c.ink,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    } else {
        Text(
            stringResource(if (info.kind == ScanKind.PHONE) R.string.kind_phone else R.string.scan_text_target),
            style = MaterialTheme.typography.bodyMedium,
            color = c.inkSoft,
        )
    }
}

/** Bold `92 / 100` plus the EN · AR verdict chip (phone checks: the level chip only). */
@Composable
private fun ScoreLine(info: VerdictInfo, big: Int) {
    val c = SaqrTheme.colors
    FlowRow(
        verticalArrangement = Arrangement.Center,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        itemVerticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .semantics(mergeDescendants = true) { heading() },
    ) {
        if (info.score != null) {
            Row(
                verticalAlignment = Alignment.Bottom,
                modifier = Modifier.semantics { contentDescription = "${info.score} / 100" },
            ) {
                Text(
                    text = info.score.toString(), // Western digits in both languages
                    style = MaterialTheme.typography.displaySmall.tabular().copy(fontSize = big.sp, lineHeight = (big + 4).sp),
                    color = c.ink,
                )
                Text(
                    text = " / 100",
                    style = MaterialTheme.typography.titleMedium.tabular(),
                    color = c.inkSoft,
                    softWrap = false,
                    modifier = Modifier.padding(bottom = (big / 8).dp),
                )
            }
        }
        VerdictChip(
            if (info.kind == ScanKind.PHONE) phoneLevelLabel(info) else bilingualVerdict(info.verdict),
            info.verdict,
        )
    }
}

@Composable
private fun ReasonRow(text: String, verdict: Verdict, maxLines: Int = Int.MAX_VALUE) {
    val c = SaqrTheme.colors
    Row(verticalAlignment = Alignment.Top) {
        Box(
            Modifier
                .padding(top = 8.dp)
                .size(6.dp)
                .background(verdictFill(verdict), CircleShape),
        )
        Spacer(Modifier.width(10.dp))
        Text(
            text,
            style = MaterialTheme.typography.bodyMedium,
            color = c.ink,
            maxLines = maxLines,
            overflow = TextOverflow.Ellipsis,
        )
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
