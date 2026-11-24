package ae.saqrintel.shield.ui.theme

import ae.saqrintel.shield.R
import androidx.compose.material3.Typography
import androidx.compose.ui.text.ExperimentalTextApi
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontVariation
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/** Barlow (Latin), static TTFs 400/500/600/700, OFL. */
val Barlow = FontFamily(
    Font(R.font.barlow_regular, FontWeight.Normal),
    Font(R.font.barlow_medium, FontWeight.Medium),
    Font(R.font.barlow_semibold, FontWeight.SemiBold),
    Font(R.font.barlow_bold, FontWeight.Bold),
)

// FontVariation is still @ExperimentalTextApi in Compose UI 1.11.
@OptIn(ExperimentalTextApi::class)
private fun kufi(weight: FontWeight) = Font(
    R.font.noto_kufi_arabic,
    weight,
    variationSettings = FontVariation.Settings(FontVariation.weight(weight.weight)),
)

/** Noto Kufi Arabic, one variable TTF (wght axis), OFL. */
val NotoKufiArabic = FontFamily(
    kufi(FontWeight.Normal),
    kufi(FontWeight.Medium),
    kufi(FontWeight.SemiBold),
    kufi(FontWeight.Bold),
)

/** Type scale; every style is >= 11sp. The family follows the app locale. */
fun saqrTypography(family: FontFamily): Typography {
    fun style(size: Int, line: Int, weight: FontWeight) =
        TextStyle(fontFamily = family, fontSize = size.sp, lineHeight = line.sp, fontWeight = weight)
    return Typography(
        displaySmall = style(34, 40, FontWeight.Bold),
        headlineSmall = style(24, 30, FontWeight.Bold),
        titleLarge = style(20, 26, FontWeight.SemiBold),
        titleMedium = style(17, 24, FontWeight.SemiBold),
        titleSmall = style(15, 20, FontWeight.SemiBold),
        bodyLarge = style(16, 24, FontWeight.Normal),
        bodyMedium = style(14, 21, FontWeight.Normal),
        bodySmall = style(12, 17, FontWeight.Normal),
        labelLarge = style(14, 18, FontWeight.SemiBold),
        labelMedium = style(12, 16, FontWeight.Medium),
        labelSmall = style(11, 14, FontWeight.Medium),
    )
}
