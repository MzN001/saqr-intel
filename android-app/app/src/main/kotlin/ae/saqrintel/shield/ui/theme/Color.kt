package ae.saqrintel.shield.ui.theme

import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/*
 * Night Grid design tokens, mirrored from the website (frontend/src/app/globals.css).
 *
 * Rules (same as the web app's DESIGN.md):
 *  - Crimson (scamFill / scamInk) ONLY ever means "scam". Never use it for errors,
 *    decoration, badges or emphasis that is not a scam verdict.
 *  - Gold (gold / goldInk) means a police action (official warning, takedown, report).
 *  - Amber (caution) means "suspicious, check first" or "action needed".
 *  - No nested cards: a tile sits on the canvas, never inside another tile.
 *  - Text is never smaller than 11sp.
 */

/** Theme-independent palette. */
object SaqrPalette {
    val ScamFill = Color(0xFFE11D48)
    val EmeraldBrand = Color(0xFF0E9F6E)
    val ShieldEmerald = Color(0xFF047857)
    val ShieldDeep = Color(0xFF065F46)
    val ShieldBright = Color(0xFF10B981)
    val ShieldNight = Color(0xFF34D399)
    val Gold = Color(0xFFC5A572)
    /** Amber: "check first" / "action needed". Never a scam, never a police action. */
    val Caution = Color(0xFFD97706)
    val Navy900 = Color(0xFF0B192C)
    val Navy950 = Color(0xFF060F1C)
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
    /** Text colour for scam verdicts only. */
    val scamInk: Color,
    /** Text colour for police actions only. */
    val goldInk: Color,
    /** Accent for "safe / protected" in this theme. */
    val shield: Color,
    /** Amber for "suspicious" and "action needed" (not crimson, not gold). */
    val caution: Color,
    val isDark: Boolean,
)

val LightSaqrColors = SaqrColors(
    canvas = Color(0xFFF3ECDF),
    surface = Color(0xFFFAF6EE),
    muted = Color(0xFFEEE5D5),
    line = Color(0xFFE0D4BF),
    ink = Color(0xFF0B192C),
    inkSoft = Color(0xFF2B4568),
    scamInk = Color(0xFFBE123C),
    goldInk = Color(0xFF7A5A1F),
    shield = SaqrPalette.ShieldEmerald,
    caution = Color(0xFFB45309),
    isDark = false,
)

val DarkSaqrColors = SaqrColors(
    canvas = Color(0xFF0A1220),
    surface = Color(0xFF111C2E),
    muted = Color(0xFF16243A),
    line = Color(0xFF1F2D45),
    ink = Color(0xFFE8EEF7),
    inkSoft = Color(0xFFA3B3C8),
    scamInk = Color(0xFFFB7185),
    goldInk = Color(0xFFD8BD8C),
    shield = SaqrPalette.ShieldNight,
    caution = Color(0xFFFBBF24),
    isDark = true,
)
