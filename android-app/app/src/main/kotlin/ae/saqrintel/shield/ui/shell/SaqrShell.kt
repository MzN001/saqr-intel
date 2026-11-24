package ae.saqrintel.shield.ui.shell

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.alerts.AlertsScreen
import ae.saqrintel.shield.ui.scanner.ScannerScreen
import ae.saqrintel.shield.ui.shield.ShieldScreen
import ae.saqrintel.shield.ui.verdict.VerdictSheet
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import ae.saqrintel.shield.ui.theme.SaqrShieldTheme
import ae.saqrintel.shield.ui.theme.SaqrTheme
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp

enum class ShellTab(@param:StringRes val label: Int, @param:DrawableRes val icon: Int) {
    Shield(R.string.tab_shield, R.drawable.ic_tab_shield),
    Scanner(R.string.tab_scanner, R.drawable.ic_tab_scanner),
    Alerts(R.string.tab_alerts, R.drawable.ic_tab_alerts),
}

/** App frame: top bar, animated tab content, bottom navigation, shared verdict sheet. */
@Composable
fun SaqrShell(
    isDark: Boolean,
    onToggleTheme: () -> Unit,
    onToggleLanguage: () -> Unit,
    openAlertId: String? = null,
    onAlertOpened: () -> Unit = {},
) {
    var tab by rememberSaveable { mutableStateOf(ShellTab.Shield) }
    var sheet by remember { mutableStateOf<VerdictInfo?>(null) }
    val c = SaqrTheme.colors
    val context = LocalContext.current

    // A tapped guard notification: show its alert on the Alerts tab.
    LaunchedEffect(openAlertId) {
        val id = openAlertId ?: return@LaunchedEffect
        val record = context.appGraph?.alertStore?.find(id)
        if (record != null) {
            tab = ShellTab.Alerts
            sheet = record.toVerdictInfo()
        }
        onAlertOpened() // last: it changes this effect's key
    }

    Scaffold(
        containerColor = c.canvas,
        contentWindowInsets = WindowInsets.safeDrawing,
        topBar = { TopBar(isDark, onToggleTheme, onToggleLanguage) },
        bottomBar = {
            NavigationBar(containerColor = c.surface) {
                ShellTab.entries.forEach { item ->
                    NavigationBarItem(
                        selected = tab == item,
                        onClick = { tab = item },
                        icon = { Icon(painterResource(item.icon), contentDescription = null) },
                        label = { Text(stringResource(item.label), style = MaterialTheme.typography.labelMedium) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = c.ink,
                            selectedTextColor = c.ink,
                            indicatorColor = c.muted,
                            unselectedIconColor = c.inkSoft,
                            unselectedTextColor = c.inkSoft,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        AnimatedContent(
            targetState = tab,
            modifier = Modifier.fillMaxSize(),
            transitionSpec = {
                // Slide in the reading direction of the tab order; mirrored automatically in RTL.
                val forward = targetState.ordinal > initialState.ordinal
                val sign = if (forward) 1 else -1
                (slideInHorizontally(tween(260)) { sign * it / 6 } + fadeIn(tween(220)))
                    .togetherWith(slideOutHorizontally(tween(260)) { -sign * it / 6 } + fadeOut(tween(160)))
            },
            label = "tab",
        ) { current ->
            when (current) {
                ShellTab.Shield -> ShieldScreen(padding)
                ShellTab.Scanner -> ScannerScreen(padding)
                ShellTab.Alerts -> AlertsScreen(padding, onOpen = { sheet = it })
            }
        }
    }

    sheet?.let { VerdictSheet(it, onDismiss = { sheet = null }) }
}

@Composable
private fun TopBar(isDark: Boolean, onToggleTheme: () -> Unit, onToggleLanguage: () -> Unit) {
    val c = SaqrTheme.colors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.canvas)
            .statusBarsPadding()
            .padding(start = 20.dp, end = 8.dp, top = 8.dp, bottom = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = stringResource(R.string.brand_wordmark),
            style = MaterialTheme.typography.titleLarge,
            color = c.ink,
            modifier = Modifier.weight(1f),
        )
        // Language pill (placeholder look; wired to LocaleController).
        val languageLabel = stringResource(R.string.cd_language_switch)
        Surface(
            onClick = onToggleLanguage,
            shape = SaqrTheme.shapes.pill,
            color = c.muted,
            contentColor = c.ink,
            modifier = Modifier
                .border(1.dp, c.line, SaqrTheme.shapes.pill)
                .semantics { contentDescription = languageLabel },
        ) {
            Text(
                text = stringResource(R.string.language_pill),
                style = MaterialTheme.typography.labelLarge,
                modifier = Modifier.padding(horizontal = 14.dp, vertical = 8.dp),
            )
        }
        IconButton(onClick = onToggleTheme) {
            Icon(
                painter = painterResource(if (isDark) R.drawable.ic_theme_light else R.drawable.ic_theme_dark),
                contentDescription = stringResource(if (isDark) R.string.cd_theme_to_light else R.string.cd_theme_to_dark),
                tint = c.ink,
            )
        }
    }
}

@Preview(name = "Dark", showBackground = true)
@Composable
private fun ShellDarkPreview() {
    SaqrShieldTheme(darkTheme = true) { SaqrShell(isDark = true, onToggleTheme = {}, onToggleLanguage = {}) }
}

@Preview(name = "Light", showBackground = true)
@Composable
private fun ShellLightPreview() {
    SaqrShieldTheme(darkTheme = false) { SaqrShell(isDark = false, onToggleTheme = {}, onToggleLanguage = {}) }
}
