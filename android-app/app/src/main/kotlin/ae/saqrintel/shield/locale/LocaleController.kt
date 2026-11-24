package ae.saqrintel.shield.locale

import android.app.Activity
import android.app.LocaleManager
import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.os.LocaleList
import androidx.core.content.edit
import java.util.Locale

/**
 * Runtime app language (EN | AR) without appcompat.
 *
 * - API 33+: the platform per-app language API ([LocaleManager.setApplicationLocales]).
 *   The system stores the choice, shows it in Settings > Apps > Language and recreates
 *   the activity itself. Supported tags are declared in res/xml/locales_config.xml.
 * - API 26-32: the tag is kept in SharedPreferences (read synchronously, which
 *   attachBaseContext needs; DataStore is async) and every Activity wraps its base
 *   context with [wrap], then [set] calls recreate().
 *
 * Every Activity MUST override attachBaseContext: `super.attachBaseContext(LocaleController.wrap(base))`.
 */
object LocaleController {
    const val ENGLISH = "en"
    const val ARABIC = "ar"
    private val SUPPORTED = setOf(ENGLISH, ARABIC)

    private const val PREFS = "saqr_locale"
    private const val KEY_TAG = "app_locale"

    /** The language currently used by the app: "en" or "ar". */
    fun current(context: Context): String {
        val tag = if (Build.VERSION.SDK_INT >= 33) {
            val locales = context.getSystemService(LocaleManager::class.java).applicationLocales
            if (locales.isEmpty) null else locales[0].language
        } else {
            prefs(context).getString(KEY_TAG, null)
        }
        return normalise(tag ?: context.resources.configuration.locales[0].language)
    }

    /** Switches the app language and refreshes the UI. */
    fun set(activity: Activity, tag: String) {
        val lang = normalise(tag)
        if (Build.VERSION.SDK_INT >= 33) {
            // The system recreates the activity with the new configuration.
            activity.getSystemService(LocaleManager::class.java).applicationLocales =
                LocaleList.forLanguageTags(lang)
        } else {
            prefs(activity).edit { putString(KEY_TAG, lang) }
            activity.recreate()
        }
    }

    fun toggle(activity: Activity) =
        set(activity, if (current(activity) == ARABIC) ENGLISH else ARABIC)

    /** Pre-33 fallback: returns a context whose configuration uses the stored language. */
    fun wrap(base: Context): Context {
        if (Build.VERSION.SDK_INT >= 33) return base
        val tag = prefs(base).getString(KEY_TAG, null) ?: return base
        val locale = Locale.forLanguageTag(normalise(tag))
        Locale.setDefault(locale)
        val config = Configuration(base.resources.configuration).apply {
            setLocales(LocaleList(locale))
            setLayoutDirection(locale)
        }
        return base.createConfigurationContext(config)
    }

    private fun normalise(tag: String?): String {
        val lang = tag?.substringBefore('-')?.lowercase(Locale.ROOT)
        return if (lang in SUPPORTED) lang!! else ENGLISH
    }

    private fun prefs(context: Context) =
        context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
