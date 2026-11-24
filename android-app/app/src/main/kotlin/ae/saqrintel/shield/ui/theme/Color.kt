package ae.saqrintel.shield.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/*
 * Saqr design tokens, mirrored from the website (frontend/DESIGN.md, frontend/src/app/globals.css).
 *
 * Rules:
 *  - Crimson ONLY means "scam". Amber ONLY means "suspicious / action needed". Emerald ONLY means
 *    "safe / verified". Never use a verdict colour for decoration, focus, branding or emphasis.
 *  - Text is written in the `-Ink` token, never in a fill colour (raw emerald / amber fail AA as text).
 *  - Obsidian (ivory in dark) is the colour of the one primary action per screen.
 *  - No nested cards. Text is never smaller than 11sp.
 */

/** Theme-independent palette (fills and brand constants never flip). */
object SaqrPalette {
    val Obsidian = Color(0xFF111315)
    val Ivory = Color(0xFFFAF8F5)
    val Slate = Color(0xFF1E293B)
    val Sandstone = Color(0xFFF7F5F0)

    /** Verdict fills: meters, dots, rings, notification accents. Never text. */
    val SafeFill = Color(0xFF10B981)
    val SuspiciousFill = Color(0xFFF59E0B)
    val ScamFill = Color(0xFFDC2626)
}

/** Semantic colours that change between light and dark. */
@Immutable
data class SaqrColors(
    val canvas: Color,
    val surface: Color,
    val muted: Color,
    val line: Color,
    val ink: Color,
    val inkSoft: Color,
    /** Primary button fill (obsidian in light, ivory in dark). */
    val primary: Color,
    val primaryPressed: Color,
    val onPrimary: Color,
    /** Verdict text colours (AA on canvas, surface, muted and the soft chip). */
    val safeInk: Color,
    val suspiciousInk: Color,
    val scamInk: Color,
    /** Soft chip grounds. */
    val safeSoft: Color,
    val suspiciousSoft: Color,
    val scamSoft: Color,
    val isDark: Boolean,
)

val LightSaqrColors = SaqrColors(
    canvas = Color(0xFFF7F5F0),
    surface = Color(0xFFFFFFFF),
    muted = Color(0xFFF1EEE6),
    line = Color(0xFFE6E2D8),
    ink = Color(0xFF111315),
    inkSoft = Color(0xFF475569),
    primary = SaqrPalette.Obsidian,
    primaryPressed = SaqrPalette.Slate,
    onPrimary = SaqrPalette.Ivory,
    safeInk = Color(0xFF047857),
    suspiciousInk = Color(0xFF92400E),
    scamInk = Color(0xFFB91C1C),
    safeSoft = Color(0xFFE8F6EF),
    suspiciousSoft = Color(0xFFFDF3E1),
    scamSoft = Color(0xFFFCEBEB),
    isDark = false,
)

val DarkSaqrColors = SaqrColors(
    canvas = Color(0xFF0E1012),
    surface = Color(0xFF171A1F),
    muted = Color(0xFF1F232A),
    line = Color(0xFF2A2F37),
    ink = Color(0xFFFAF8F5),
    inkSoft = Color(0xFFA3ACB9),
    primary = SaqrPalette.Ivory,
    primaryPressed = Color(0xFFE7E3DA),
    onPrimary = SaqrPalette.Obsidian,
    safeInk = Color(0xFF34D399),
    suspiciousInk = Color(0xFFFBBF24),
    scamInk = Color(0xFFF87171),
    safeSoft = Color(0xFF0F2A21),
    suspiciousSoft = Color(0xFF2E2310),
    scamSoft = Color(0xFF311617),
    isDark = true,
)
