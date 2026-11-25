package ae.saqrintel.shield

import ae.saqrintel.shield.data.AlertStore
import ae.saqrintel.shield.data.ApiClient
import ae.saqrintel.shield.data.Blocklist
import ae.saqrintel.shield.data.ScanCache
import ae.saqrintel.shield.data.Settings
import ae.saqrintel.shield.guard.AlertNotifier
import android.app.Application
import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

/** Process-wide singletons (no DI library). */
class AppGraph(context: Context) {
    val settings = Settings(context)
    val alertStore = AlertStore(context)
    val cache = ScanCache()
    val blocklist = Blocklist(context)
    val api = ApiClient { settings.currentBaseUrl() }

    /** For fire-and-forget work that must outlive a screen (e.g. logging an X alert). */
    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
}

class SaqrApp : Application() {
    val graph: AppGraph by lazy { AppGraph(this) }

    override fun onCreate() {
        super.onCreate()
        AlertNotifier.createChannels(this)
    }
}

/** The app graph from any context (null only in odd test / instrumentation setups). */
val Context.appGraph: AppGraph?
    get() = (applicationContext as? SaqrApp)?.graph
