package ae.saqrintel.shield.ui.shell

import ae.saqrintel.shield.R
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.ui.alerts.AlertsScreen
import ae.saqrintel.shield.ui.common.ApiHealth
import ae.saqrintel.shield.ui.common.ApiStatus
import ae.saqrintel.shield.ui.common.SaqrLockup
import ae.saqrintel.shield.ui.common.isArabic
import ae.saqrintel.shield.ui.scanner.ScannerScreen
import ae.saqrintel.shield.ui.shield.ApiServerDialog
import ae.saqrintel.shield.ui.shield.ShieldScreen
import ae.saqrintel.shield.ui.theme.SaqrPalette
import ae.saqrintel.shield.ui.theme.SaqrShieldTheme
import ae.saqrintel.shield.ui.theme.SaqrTheme
import ae.saqrintel.shield.ui.verdict.VerdictSheet
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

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
    var showApi by remember { mutableStateOf(false) }
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
        topBar = { TopBar(isDark, onToggleTheme, onToggleLanguage, onApi = { showApi = true }) },
        bottomBar = {
            Column {
                HorizontalDivider(color = c.line, thickness = 1.dp)
                NavigationBar(containerColor = c.surface, tonalElevation = 0.dp) {
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
                (slideInHorizontally(tween(200)) { sign * it / 8 } + fadeIn(tween(180)))
                    .togetherWith(slideOutHorizontally(tween(200)) { -sign * it / 8 } + fadeOut(tween(120)))
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
    if (showApi) ApiServerDialog(onDismiss = { showApi = false })
}

@Composable
private fun TopBar(isDark: Boolean, onToggleTheme: () -> Unit, onToggleLanguage: () -> Unit, onApi: () -> Unit) {
    val c = SaqrTheme.colors
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(c.canvas)
            .statusBarsPadding()
            .padding(start = 16.dp, end = 4.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        SaqrLockup(falcon = 34.dp)
        Box(Modifier.weight(1f))
        LanguageToggle(onToggleLanguage)
        ApiDot(onApi)
        IconButton(onClick = onToggleTheme) {
            Icon(
                painter = painterResource(if (isDark) R.drawable.ic_theme_light else R.drawable.ic_theme_dark),
                contentDescription = stringResource(if (isDark) R.string.cd_theme_to_light else R.string.cd_theme_to_dark),
                tint = c.ink,
                modifier = Modifier.size(22.dp),
            )
        }
    }
}

/** Compact `EN | عربي`: the active language in ink, the other one soft; one tap switches. */
@Composable
private fun LanguageToggle(onToggle: () -> Unit) {
    val c = SaqrTheme.colors
    val arabic = isArabic()
    val label = stringResource(R.string.cd_language_switch)
    Surface(
        onClick = onToggle,
        shape = SaqrTheme.shapes.pill,
        color = c.surface,
        border = BorderStroke(1.dp, c.line),
        modifier = Modifier
            .semantics(mergeDescendants = true) {
                contentDescription = label
                role = Role.Button
            },
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        ) {
            val style = MaterialTheme.typography.labelMedium
            // Order stays "EN | عربي" in both directions.
            androidx.compose.runtime.CompositionLocalProvider(
                androidx.compose.ui.platform.LocalLayoutDirection provides androidx.compose.ui.unit.LayoutDirection.Ltr,
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "EN",
                        style = style.copy(fontWeight = if (!arabic) FontWeight.Bold else FontWeight.Medium),
                        color = if (!arabic) c.ink else c.inkSoft,
                    )
                    Text("  |  ", style = style, color = c.line)
                    Text(
                        "عربي",
                        style = style.copy(fontWeight = if (arabic) FontWeight.Bold else FontWeight.Medium),
                        color = if (arabic) c.ink else c.inkSoft,
                    )
                }
            }
        }
    }
}

/** API status dot: emerald = last call OK, amber = waking / unknown, grey = never checked. */
@Composable
private fun ApiDot(onClick: () -> Unit) {
    val c = SaqrTheme.colors
    val health by ApiStatus.health.collectAsStateWithLifecycle()
    val (color, state) = when (health) {
        ApiHealth.OK -> SaqrPalette.SafeFill to stringResource(R.string.api_status_ok)
        ApiHealth.WAKING -> SaqrPalette.SuspiciousFill to stringResource(R.string.api_status_waking)
        ApiHealth.NEVER -> c.inkSoft.copy(alpha = 0.6f) to stringResource(R.string.api_status_never)
    }
    val description = stringResource(R.string.cd_api_status, state)
    IconButton(onClick = onClick, modifier = Modifier.semantics { contentDescription = description }) {
        Box(
            Modifier
                .size(10.dp)
                .background(color, CircleShape)
                .border(1.dp, c.surface, CircleShape),
        )
    }
}

@Preview(name = "Light", showBackground = true)
@Composable
private fun ShellLightPreview() {
    SaqrShieldTheme(darkTheme = false) { SaqrShell(isDark = false, onToggleTheme = {}, onToggleLanguage = {}) }
}

@Preview(name = "Dark", showBackground = true)
@Composable
private fun ShellDarkPreview() {
    SaqrShieldTheme(darkTheme = true) { SaqrShell(isDark = true, onToggleTheme = {}, onToggleLanguage = {}) }
}
