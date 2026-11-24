package ae.saqrintel.shield.ui.theme

import ae.saqrintel.shield.R
import androidx.compose.material3.Typography
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp

// FontVariation is still @ExperimentalTextApi in Compose UI 1.11.
@OptIn(ExperimentalTextApi::class)
private fun inter(weight: FontWeight) = Font(
    R.font.inter_variable,
    weight,
    variationSettings = FontVariation.Settings(FontVariation.weight(weight.weight)),
)

/** Inter (Latin UI), one variable TTF (opsz + wght axes), OFL. */
val Inter = FontFamily(
    inter(FontWeight.Normal),
    inter(FontWeight.Medium),
    inter(FontWeight.SemiBold),
    inter(FontWeight.Bold),
)

/** IBM Plex Sans Arabic, static TTFs 400/500/600/700, OFL. Used for the whole UI in Arabic. */
val PlexArabic = FontFamily(
    Font(R.font.plex_arabic_regular, FontWeight.Normal),
    Font(R.font.plex_arabic_medium, FontWeight.Medium),
    Font(R.font.plex_arabic_semibold, FontWeight.SemiBold),
    Font(R.font.plex_arabic_bold, FontWeight.Bold),
)

/** Gloock 400, OFL. The "Saqr" wordmark ONLY: never headings or UI text. */
val Gloock = FontFamily(Font(R.font.gloock_regular, FontWeight.Normal))

/** Wordmark style for the lockup (Latin, LTR in both languages). */
val WordmarkStyle = TextStyle(fontFamily = Gloock, fontWeight = FontWeight.Normal, fontSize = 24.sp, lineHeight = 28.sp)

/**
 * Type scale; every style is >= 11sp. The family follows the app locale. Arabic gets +1sp body and
 * no letter-spacing (DESIGN.md section 3).
 */
fun saqrTypography(family: FontFamily, arabic: Boolean): Typography {
    val bump = if (arabic) 1 else 0
    fun style(size: Int, line: Int, weight: FontWeight, tracking: Double = 0.0) = TextStyle(
        fontFamily = family,
        fontSize = size.sp,
        lineHeight = line.sp,
        fontWeight = weight,
        letterSpacing = if (arabic || tracking == 0.0) 0.em else tracking.em,
    )
    return Typography(
        displaySmall = style(32, 36, FontWeight.Bold, -0.02),
        headlineSmall = style(24, 30, FontWeight.Bold, -0.01),
        titleLarge = style(20, 26, FontWeight.SemiBold),
        titleMedium = style(17, 24, FontWeight.SemiBold),
        titleSmall = style(15, 20, FontWeight.SemiBold),
        bodyLarge = style(16 + bump, 24 + bump, FontWeight.Normal),
        bodyMedium = style(15 + bump, 22 + bump, FontWeight.Normal),
        bodySmall = style(13 + bump, 18 + bump, FontWeight.Normal),
        labelLarge = style(14, 18, FontWeight.SemiBold),
        labelMedium = style(13, 16, FontWeight.Medium),
        labelSmall = style(11, 14, FontWeight.SemiBold, 0.08),
    )
}
