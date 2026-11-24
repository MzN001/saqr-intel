package ae.saqrintel.shield.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** App-wide settings store (one DataStore file for the whole app). */
val Context.settingsStore: DataStore<Preferences> by preferencesDataStore(name = "saqr_settings")

enum class ThemeMode { DARK, LIGHT }

/** Light / dark choice. Saqr is light by default (same as the website); a saved choice still wins. */
class ThemeController(private val context: Context) {
    private val key = stringPreferencesKey("theme")

    val mode: Flow<ThemeMode> = context.settingsStore.data.map { prefs ->
        if (prefs[key] == ThemeMode.DARK.name) ThemeMode.DARK else ThemeMode.LIGHT
    }

    suspend fun set(mode: ThemeMode) {
        context.settingsStore.edit { it[key] = mode.name }
    }
}
