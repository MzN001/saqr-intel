package ae.saqrintel.shield.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalConfiguration

val LocalSaqrColors = staticCompositionLocalOf { DarkSaqrColors }
val LocalSaqrShapes = staticCompositionLocalOf { SaqrShapes() }

/** Access point for Night Grid tokens: `SaqrTheme.colors.ink`, `SaqrTheme.shapes.tile`. */
object SaqrTheme {
    val colors: SaqrColors
        @Composable @ReadOnlyComposable get() = LocalSaqrColors.current
    val shapes: SaqrShapes
        @Composable @ReadOnlyComposable get() = LocalSaqrShapes.current
}

/**
 * Night Grid theme. Dark is the default; [darkTheme] comes from ThemeController.
 * Material 3 colour roles are mapped so stock components look right, but app UI
 * should prefer the semantic SaqrTheme.colors.
 * Note: Material's `error` role is NOT mapped to crimson; crimson means scam only.
 */
@Composable
fun SaqrShieldTheme(darkTheme: Boolean = true, content: @Composable () -> Unit) {
    val colors = if (darkTheme) DarkSaqrColors else LightSaqrColors
    val scheme = if (darkTheme) {
        darkColorScheme(
            primary = SaqrPalette.ShieldNight,
            onPrimary = SaqrPalette.Navy950,
            secondary = SaqrPalette.Gold,
            onSecondary = SaqrPalette.Navy950,
            background = colors.canvas,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            surfaceVariant = colors.muted,
            onSurfaceVariant = colors.inkSoft,
            surfaceContainer = colors.surface,
            secondaryContainer = colors.muted,
            onSecondaryContainer = colors.ink,
            outline = colors.line,
            outlineVariant = colors.line,
        )
    } else {
        lightColorScheme(
            primary = SaqrPalette.ShieldEmerald,
            onPrimary = colors.surface,
            secondary = colors.goldInk,
            onSecondary = colors.surface,
            background = colors.canvas,
            onBackground = colors.ink,
            surface = colors.surface,
            onSurface = colors.ink,
            surfaceVariant = colors.muted,
            onSurfaceVariant = colors.inkSoft,
            surfaceContainer = colors.surface,
            secondaryContainer = colors.muted,
            onSecondaryContainer = colors.ink,
            outline = colors.line,
            outlineVariant = colors.line,
        )
    }
    val isArabic = LocalConfiguration.current.locales[0].language == "ar"
    val typography = remember(isArabic) { saqrTypography(if (isArabic) NotoKufiArabic else Barlow) }

    CompositionLocalProvider(
        LocalSaqrColors provides colors,
        LocalSaqrShapes provides SaqrShapes(),
    ) {
        MaterialTheme(colorScheme = scheme, typography = typography, content = content)
    }
}
