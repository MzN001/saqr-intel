package ae.saqrintel.shield.ui.common

import ae.saqrintel.shield.R
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.ui.theme.SaqrPalette
import ae.saqrintel.shield.ui.theme.SaqrTheme
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp

/** True when the app runs in Arabic. */
@Composable
fun isArabic(): Boolean = LocalConfiguration.current.locales[0].language == "ar"

/** Tabular numerals for scores and counters (digits line up). */
fun TextStyle.tabular(): TextStyle = copy(fontFeatureSettings = "tnum")

/** Scrollable tab body with the demo notice at the end. */
@Composable
fun ScreenColumn(padding: PaddingValues, content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(padding)
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        content()
        Spacer(Modifier.height(4.dp))
        Text(
            text = stringResource(R.string.notice_demo),
            style = MaterialTheme.typography.labelSmall,
            color = SaqrTheme.colors.inkSoft,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** A top-level tile on the canvas (radius 20, line border). Never place a tile inside a tile. */
@Composable
fun Tile(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    val c = SaqrTheme.colors
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(c.surface, SaqrTheme.shapes.tile)
            .border(1.dp, c.line, SaqrTheme.shapes.tile)
            .padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
        content = content,
    )
}

/** Selectable pill (mode switch, chips). */
@Composable
fun Pill(
    text: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    val c = SaqrTheme.colors
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = SaqrTheme.shapes.pill,
        color = if (selected) c.ink else c.muted,
        contentColor = if (selected) c.canvas else c.ink,
        modifier = modifier
            .border(1.dp, if (selected) c.ink else c.line, SaqrTheme.shapes.pill)
            .semantics {
                this.selected = selected
                role = Role.Tab
            },
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelLarge,
            modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
        )
    }
}

/** Text colour for a verdict: emerald safe, amber suspicious, crimson scam (scam only). */
@Composable
fun verdictInk(v: Verdict): Color = when (v) {
    Verdict.SAFE -> SaqrTheme.colors.shield
    Verdict.SUSPICIOUS -> SaqrTheme.colors.caution
    Verdict.SCAM -> SaqrTheme.colors.scamInk
}

@Composable
fun verdictFill(v: Verdict): Color = when (v) {
    Verdict.SAFE -> SaqrTheme.colors.shield
    Verdict.SUSPICIOUS -> SaqrTheme.colors.caution
    Verdict.SCAM -> SaqrPalette.ScamFill
}

@Composable
fun verdictLabel(v: Verdict): String = stringResource(
    when (v) {
        Verdict.SAFE -> R.string.verdict_safe
        Verdict.SUSPICIOUS -> R.string.verdict_suspicious
        Verdict.SCAM -> R.string.verdict_scam
    },
)

/** Primary action (emerald) with a moving shimmer while [loading]. */
@Composable
fun PrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    loading: Boolean = false,
    enabled: Boolean = true,
) {
    val c = SaqrTheme.colors
    val base = if (c.isDark) SaqrPalette.ShieldNight else SaqrPalette.ShieldEmerald
    val ink = if (c.isDark) SaqrPalette.Navy950 else Color.White
    Surface(
        onClick = onClick,
        enabled = enabled && !loading,
        shape = SaqrTheme.shapes.control,
        color = if (enabled || loading) base else c.muted,
        contentColor = if (enabled || loading) ink else c.inkSoft,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 52.dp)
            .semantics { role = Role.Button },
    ) {
        Box(contentAlignment = Alignment.Center, modifier = Modifier.clip(SaqrTheme.shapes.control)) {
            if (loading) Shimmer(Modifier.matchParentSize())
            Text(
                text = text,
                style = MaterialTheme.typography.titleSmall,
                modifier = Modifier.padding(vertical = 15.dp, horizontal = 16.dp),
            )
        }
    }
}

@Composable
private fun Shimmer(modifier: Modifier) {
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
                0.5f to Color.White.copy(alpha = 0.35f),
                1f to Color.Transparent,
                start = androidx.compose.ui.geometry.Offset(x * 600f - 300f, 0f),
                end = androidx.compose.ui.geometry.Offset(x * 600f + 300f, 0f),
            ),
        ),
    )
}

/** Secondary action: outlined, ink text. */
@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true) {
    val c = SaqrTheme.colors
    Surface(
        onClick = onClick,
        enabled = enabled,
        shape = SaqrTheme.shapes.control,
        color = c.muted,
        contentColor = if (enabled) c.ink else c.inkSoft,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .border(1.dp, c.line, SaqrTheme.shapes.control)
            .semantics { role = Role.Button },
    ) {
        Box(contentAlignment = Alignment.Center) {
            Text(text, style = MaterialTheme.typography.labelLarge, modifier = Modifier.padding(12.dp))
        }
    }
}
