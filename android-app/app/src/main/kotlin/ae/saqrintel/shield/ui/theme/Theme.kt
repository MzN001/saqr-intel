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

val LocalSaqrColors = staticCompositionLocalOf { LightSaqrColors }
val LocalSaqrShapes = staticCompositionLocalOf { SaqrShapes() }

/** Access point for Saqr tokens: `SaqrTheme.colors.ink`, `SaqrTheme.shapes.card`. */
object SaqrTheme {
    val colors: SaqrColors
        @Composable @ReadOnlyComposable get() = LocalSaqrColors.current
    val shapes: SaqrShapes
        @Composable @ReadOnlyComposable get() = LocalSaqrShapes.current
}

/**
 * Saqr theme. Light is the default; [darkTheme] comes from ThemeController (a saved choice wins).
 *
 * Dynamic colour is OFF on purpose: the brand colours carry meaning (crimson = scam, amber =
 * suspicious, emerald = safe) and must never be replaced by wallpaper colours. Never call
 * dynamicLightColorScheme / dynamicDarkColorScheme here.
 *
 * Material 3 roles are mapped so stock components (dialogs, sheets, text fields) look right; app UI
 * should prefer the semantic SaqrTheme.colors. Material's `error` role is NOT crimson: crimson means
 * scam only, so field errors use the suspicious (amber) ink.
 */
@Suppress("UNUSED_PARAMETER")
@Composable
fun SaqrShieldTheme(
    darkTheme: Boolean = false,
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val c = if (darkTheme) DarkSaqrColors else LightSaqrColors
    val scheme = if (darkTheme) {
        darkColorScheme(
            primary = c.primary,
            onPrimary = c.onPrimary,
            primaryContainer = c.muted,
            onPrimaryContainer = c.ink,
            secondary = c.ink,
            onSecondary = c.canvas,
            secondaryContainer = c.muted,
            onSecondaryContainer = c.ink,
            tertiary = c.ink,
            onTertiary = c.canvas,
            background = c.canvas,
            onBackground = c.ink,
            surface = c.surface,
            onSurface = c.ink,
            surfaceVariant = c.muted,
            onSurfaceVariant = c.inkSoft,
            surfaceContainerLowest = c.canvas,
            surfaceContainerLow = c.surface,
            surfaceContainer = c.surface,
            surfaceContainerHigh = c.surface,
            surfaceContainerHighest = c.muted,
            surfaceTint = c.surface,
            inverseSurface = c.ink,
            inverseOnSurface = c.canvas,
            error = c.suspiciousInk,
            onError = c.canvas,
            outline = c.line,
            outlineVariant = c.line,
            scrim = SaqrPalette.Obsidian,
        )
    } else {
        lightColorScheme(
            primary = c.primary,
            onPrimary = c.onPrimary,
            primaryContainer = c.muted,
            onPrimaryContainer = c.ink,
            secondary = c.ink,
            onSecondary = c.surface,
            secondaryContainer = c.muted,
            onSecondaryContainer = c.ink,
            tertiary = c.ink,
            onTertiary = c.surface,
            background = c.canvas,
            onBackground = c.ink,
            surface = c.surface,
            onSurface = c.ink,
            surfaceVariant = c.muted,
            onSurfaceVariant = c.inkSoft,
            surfaceContainerLowest = c.surface,
            surfaceContainerLow = c.surface,
            surfaceContainer = c.surface,
            surfaceContainerHigh = c.surface,
            surfaceContainerHighest = c.muted,
            surfaceTint = c.surface,
            inverseSurface = c.ink,
            inverseOnSurface = c.canvas,
            error = c.suspiciousInk,
            onError = c.surface,
            outline = c.line,
            outlineVariant = c.line,
            scrim = SaqrPalette.Obsidian,
        )
    }
    val isArabic = LocalConfiguration.current.locales[0].language == "ar"
    val typography = remember(isArabic) { saqrTypography(if (isArabic) PlexArabic else Inter, isArabic) }

    CompositionLocalProvider(
        LocalSaqrColors provides c,
        LocalSaqrShapes provides SaqrShapes(),
    ) {
        MaterialTheme(colorScheme = scheme, typography = typography, content = content)
    }
}
