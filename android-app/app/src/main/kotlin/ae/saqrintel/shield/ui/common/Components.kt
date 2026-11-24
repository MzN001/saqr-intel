package ae.saqrintel.shield.ui.common

import ae.saqrintel.shield.R
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.ui.theme.SaqrPalette
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.ui.theme.WordmarkStyle
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** True when the app runs in Arabic. */
@Composable
fun isArabic(): Boolean = LocalConfiguration.current.locales[0].language == "ar"

/** Tabular numerals for scores, counters and phone numbers (digits line up). */
fun TextStyle.tabular(): TextStyle = copy(fontFeatureSettings = "tnum")

/** Scrollable tab body with the demo notice at the end. */
@Composable
fun ScreenColumn(padding: PaddingValues, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(padding)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        content()
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.notice_demo),
            style = MaterialTheme.typography.labelMedium,
            color = SaqrTheme.colors.inkSoft,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** A card on the canvas: white surface, 1dp hairline, 16dp radius. Never place a card inside a card. */
@Composable
fun SaqrCard(
    modifier: Modifier = Modifier,
    padding: Dp = 16.dp,
    spacing: Dp = 12.dp,
    content: @Composable ColumnScope.() -> Unit,
) {
    val c = SaqrTheme.colors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(c.surface, SaqrTheme.shapes.card)
            .border(1.dp, c.line, SaqrTheme.shapes.card)
            .padding(padding),
        verticalArrangement = Arrangement.spacedBy(spacing),
        content = content,
    )
}

/** Quiet selectable pill (scanner modes): muted ground when selected, hairline otherwise. */
@Composable
fun Pill(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    role: Role = Role.Tab,
) {
    val c = SaqrTheme.colors
    Surface(
        onClick = onClick,
        shape = SaqrTheme.shapes.pill,
        color = if (selected) c.muted else c.surface,
        contentColor = if (selected) c.ink else c.inkSoft,
        border = BorderStroke(1.dp, if (selected) c.ink.copy(alpha = 0.35f) else c.line),
        modifier = modifier
            .semantics {
                if (role == Role.Tab) this.selected = selected
                this.role = role
            },
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium.copy(
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Medium,
            ),
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
        )
    }
}

/** One verdict chip: soft ground + AA ink + a word (colour never works alone). */
@Composable
fun VerdictChip(text: String, verdict: Verdict, modifier: Modifier = Modifier) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
        color = verdictInk(verdict),
        maxLines = 1,
        modifier = modifier
            .background(verdictSoft(verdict), SaqrTheme.shapes.pill)
            .padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

/** Neutral tag (channel, kind). */
@Composable
fun NeutralChip(text: String, modifier: Modifier = Modifier) {
    val c = SaqrTheme.colors
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium.copy(fontWeight = FontWeight.SemiBold),
        color = c.ink,
        maxLines = 1,
        modifier = modifier
            .background(c.muted, SaqrTheme.shapes.pill)
            .padding(horizontal = 10.dp, vertical = 4.dp),
    )
}

/** Text colour for a verdict: emerald safe, amber suspicious, crimson scam (AA variants). */
@Composable
fun verdictInk(v: Verdict): Color = when (v) {
    Verdict.SAFE -> SaqrTheme.colors.safeInk
    Verdict.SUSPICIOUS -> SaqrTheme.colors.suspiciousInk
    Verdict.SCAM -> SaqrTheme.colors.scamInk
}

/** Fill colour for meters, dots and rings. Never for text. */
fun verdictFill(v: Verdict): Color = when (v) {
    Verdict.SAFE -> SaqrPalette.SafeFill
    Verdict.SUSPICIOUS -> SaqrPalette.SuspiciousFill
    Verdict.SCAM -> SaqrPalette.ScamFill
}

@Composable
fun verdictSoft(v: Verdict): Color = when (v) {
    Verdict.SAFE -> SaqrTheme.colors.safeSoft
    Verdict.SUSPICIOUS -> SaqrTheme.colors.suspiciousSoft
    Verdict.SCAM -> SaqrTheme.colors.scamSoft
}

@Composable
fun verdictLabel(v: Verdict): String = stringResource(
    when (v) {
        Verdict.SAFE -> R.string.verdict_safe
        Verdict.SUSPICIOUS -> R.string.verdict_suspicious
        Verdict.SCAM -> R.string.verdict_scam
    },
)

/** The verdict in both languages (EN · AR), same as the web verdict stamp. */
fun bilingualVerdict(v: Verdict): String = when (v) {
    Verdict.SAFE -> "Safe · آمن"
    Verdict.SUSPICIOUS -> "Suspicious · مشبوه"
    Verdict.SCAM -> "High-risk scam · احتيال عالي الخطورة"
}

/** Primary action: obsidian fill (ivory in dark), ivory text, pressed slate; shimmer while [loading]. */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    loading: Boolean = false,
    enabled: Boolean = true,
    minHeight: Dp = 48.dp,
) {
    val c = SaqrTheme.colors
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val active = enabled || loading
    Surface(
        onClick = onClick,
        enabled = enabled && !loading,
        shape = SaqrTheme.shapes.control,
        color = when {
            !active -> c.muted
            pressed -> c.primaryPressed
            else -> c.primary
        },
        contentColor = if (active) c.onPrimary else c.inkSoft,
        interactionSource = interaction,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = minHeight)
            .semantics { role = Role.Button },
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.clip(SaqrTheme.shapes.control)) {
            if (loading) Shimmer(Modifier.matchParentSize(), c.onPrimary)
            Text(
                text = text,
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(vertical = 13.dp, horizontal = 16.dp),
            )
        }
    }
}

@Composable
private fun Shimmer(modifier: Modifier, tint: Color) {
    val transition = rememberInfiniteTransition(label = "shimmer")
    val x by transition.animateFloat(
        initialValue = -1f,
        targetValue = 2f,
        animationSpec = infiniteRepeatable(tween(1200, easing = LinearEasing), RepeatMode.Restart),
        label = "shimmer-x",
    )
    Box(
        modifier = modifier.background(
            Brush.linearGradient(
                0f to Color.Transparent,
                0.5f to tint.copy(alpha = 0.18f),
                1f to Color.Transparent,
                start = Offset(x * 600f - 300f, 0f),
                end = Offset(x * 600f + 300f, 0f),
            ),
        ),
    )
}

/** Secondary action: surface, hairline, ink text. */
@Composable
fun SecondaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    fill: Boolean = true,
) {
    val c = SaqrTheme.colors
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = SaqrTheme.shapes.control,
        color = c.surface,
        contentColor = if (enabled) c.ink else c.inkSoft,
        border = BorderStroke(1.dp, c.line),
        modifier = modifier
            .then(if (fill) Modifier.fillMaxWidth() else Modifier)
            .heightIn(min = 48.dp)
            .semantics { role = Role.Button },
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(
                text,
                style = MaterialTheme.typography.labelLarge,
                maxLines = 1,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 12.dp),
            )
        }
    }
}

/** The falcon mark. Ink in light, ivory in dark; never a verdict colour. */
@Composable
fun FalconMark(size: Dp, modifier: Modifier = Modifier, tint: Color = SaqrTheme.colors.ink) {
    Icon(
        painter = painterResource(if (size < 24.dp) R.drawable.ic_saqr_falcon else R.drawable.ic_saqr_falcon_master),
        contentDescription = null,
        tint = tint,
        modifier = modifier.size(size),
    )
}

/**
 * Logo lockup: falcon → "Saqr" in Gloock, always left to right (also in Arabic), gap ≈ 0.2 × falcon
 * height, wordmark optically centred on the falcon.
 */
@Composable
fun SaqrLockup(modifier: Modifier = Modifier, falcon: Dp = 28.dp) {
    val c = SaqrTheme.colors
    val name = stringResource(R.string.brand_wordmark)
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = modifier.clearAndSetSemantics { contentDescription = name },
        ) {
            FalconMark(falcon)
            Spacer(Modifier.width(falcon * 0.22f))
            Text(
                text = name,
                style = WordmarkStyle.copy(fontSize = (falcon.value * 0.74f).sp, lineHeight = (falcon.value * 0.9f).sp),
                color = c.ink,
            )
        }
    }
}

/**
 * Safe | Suspicious | Scam meter: three zones (0-29 / 30-64 / 65-100) separated by 2dp of surface,
 * an ink marker at [score] (none for a phone check), and the zone words underneath.
 */
@Composable
fun RiskMeter(score: Int?, verdict: Verdict, modifier: Modifier = Modifier) {
    val c = SaqrTheme.colors
    val ltr = LocalLayoutDirection.current == LayoutDirection.Ltr
    Column(modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Canvas(
            Modifier
                .fillMaxWidth()
                .height(14.dp),
        ) {
            val trackH = 6.dp.toPx()
            val gap = 2.dp.toPx()
            val top = (size.height - trackH) / 2f
            val w = size.width
            val bounds = listOf(0f to 0.30f, 0.30f to 0.65f, 0.65f to 1f)
            val fills = listOf(SaqrPalette.SafeFill, SaqrPalette.SuspiciousFill, SaqrPalette.ScamFill)
            bounds.forEachIndexed { i, (a, b) ->
                val start = a * w + if (i == 0) 0f else gap / 2f
                val end = b * w - if (i == 2) 0f else gap / 2f
                val left = if (ltr) start else w - end
                drawRoundRect(
                    fills[i].copy(alpha = if (i == verdict.ordinal || score != null) 1f else 0.35f),
                    topLeft = Offset(left, top),
                    size = Size(end - start, trackH),
                    cornerRadius = CornerRadius(trackH / 2f),
                )
            }
            if (score != null) {
                val f = score.coerceIn(0, 100) / 100f
                val x = (if (ltr) f else 1f - f) * w
                val mw = 3.dp.toPx()
                drawRoundRect(
                    c.surface,
                    topLeft = Offset((x - mw / 2f - gap).coerceIn(0f, w - mw - 2 * gap), 0f),
                    size = Size(mw + 2 * gap, size.height),
                    cornerRadius = CornerRadius(mw),
                )
                drawRoundRect(
                    c.ink,
                    topLeft = Offset((x - mw / 2f).coerceIn(gap, w - mw - gap), 0f),
                    size = Size(mw, size.height),
                    cornerRadius = CornerRadius(mw / 2f),
                )
            }
        }
        val arabic = isArabic()
        Row(Modifier.fillMaxWidth()) {
            Verdict.entries.forEachIndexed { i, v ->
                val on = v == verdict
                val word = stringResource(
                    when (v) {
                        Verdict.SAFE -> R.string.meter_safe
                        Verdict.SUSPICIOUS -> R.string.meter_suspicious
                        Verdict.SCAM -> R.string.meter_scam
                    },
                )
                Text(
                    // Tracked caps in English; Arabic has no case and no letter-spacing.
                    text = if (arabic) word else word.uppercase(),
                    style = MaterialTheme.typography.labelSmall.copy(
                        fontWeight = if (on) FontWeight.Bold else FontWeight.SemiBold,
                    ),
                    color = if (on) verdictInk(v) else c.inkSoft,
                    textAlign = when (i) {
                        0 -> androidx.compose.ui.text.style.TextAlign.Start
                        1 -> androidx.compose.ui.text.style.TextAlign.Center
                        else -> androidx.compose.ui.text.style.TextAlign.End
                    },
                    modifier = Modifier.weight(if (i == 0) 0.30f else 0.35f),
                )
            }
        }
    }
}
