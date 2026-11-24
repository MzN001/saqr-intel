package ae.saqrintel.shield.guard

import ae.saqrintel.shield.AppGraph
import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.ApiResult
import ae.saqrintel.shield.data.Interception
import ae.saqrintel.shield.data.ScanCache
import ae.saqrintel.shield.data.ScanKind
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.data.toVerdictInfo
import ae.saqrintel.shield.locale.LocaleController
import ae.saqrintel.shield.ui.BlockAlertActivity
import android.accessibilityservice.AccessibilityService
import android.content.ActivityNotFoundException
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Browser
import android.provider.Settings
import android.util.Log
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.core.net.toUri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.lang.ref.WeakReference
import java.net.URI

/**
 * Web blocker. Reads ONLY the address bar of Chrome, Samsung Internet, Firefox and Edge (by view
 * id), never page content, passwords or typed text, and only after the user consented in the
 * Shield tab. A HIGH-RISK site opens [BlockAlertActivity]; a suspicious one gets the quieter
 * caution notification. Server asleep / unreachable = fail open, silently.
 */
class SaqrBrowserGuardService : AccessibilityService() {

    private var scope: CoroutineScope? = null
    private var consentJob: Job? = null
    private val main = Handler(Looper.getMainLooper())

    @Volatile
    private var consent = false

    /** Last key written to the debug log (so a page's event stream logs once). */
    @Volatile
    private var lastLogged: String? = null

    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(LocaleController.wrap(newBase))
    }

    override fun onServiceConnected() {
        super.onServiceConnected()
        instance = WeakReference(this)
        val s = scope ?: CoroutineScope(SupervisorJob() + Dispatchers.IO).also { scope = it }
        val graph = appGraph ?: return
        consentJob?.cancel()
        consentJob = s.launch {
            try {
                graph.settings.webConsent.collect { consent = it }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                consent = false
            }
        }
        debug(graph, "web blocker connected")
    }

    override fun onInterrupt() {
        // Nothing is spoken or vibrated; no feedback to interrupt.
    }

    override fun onUnbind(intent: Intent?): Boolean {
        stopWork()
        return super.onUnbind(intent)
    }

    override fun onDestroy() {
        stopWork()
        super.onDestroy()
    }

    private fun stopWork() {
        consent = false
        scope?.cancel()
        scope = null
        consentJob = null
        main.removeCallbacksAndMessages(null)
        if (instance?.get() === this) instance = null
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        try {
            val pkg = event?.packageName?.toString() ?: return
            if (pkg == packageName) return
            if (pkg !in WebGuardPolicy.URL_BAR_IDS) return
            if (!consent) return
            val raw = readUrlBar(pkg) ?: return
            onAddress(pkg, raw)
        } catch (_: Exception) {
            // OEM / browser quirks must never take the service down.
        }
    }

    /**
     * Text of [pkg]'s address bar, or null (not found, empty, or focused = the user is typing).
     * Looks nodes up by view id only; no other node's text is ever read.
     */
    private fun readUrlBar(pkg: String): String? {
        val ids = WebGuardPolicy.URL_BAR_IDS[pkg] ?: return null
        val root = try {
            rootInActiveWindow
        } catch (_: Exception) {
            null
        } ?: return null
        try {
            if (root.packageName?.toString() != pkg) return null
            for (id in ids) {
                val nodes = try {
                    root.findAccessibilityNodeInfosByViewId(id)
                } catch (_: Exception) {
                    null
                } ?: continue
                try {
                    val node = nodes.firstOrNull() ?: continue
                    if (node.isFocused) return null // being edited: never scan partial input
                    val text = node.text?.toString()?.trim()
                    if (!text.isNullOrEmpty()) return text
                } finally {
                    nodes.forEach(::recycle)
                }
            }
            return null
        } catch (_: Exception) {
            return null
        } finally {
            recycle(root)
        }
    }

    private fun onAddress(pkg: String, raw: String) {
        val target = WebGuardPolicy.normalise(raw) ?: return
        val graph = appGraph ?: return
        val s = scope ?: return
        s.launch {
            try {
                val apiHost = apiHostOf(graph.settings.currentBaseUrl())
                val skip = WebGuardPolicy.skipReason(target, apiHost, WebSession.allowList())
                if (skip != null) {
                    debugOnce(graph, target.key, "skip ${skip.name} ${target.host}")
                    return@launch
                }
                if (!WebSession.throttle.tryStart(target.key, target.host)) return@launch
                try {
                    check(graph, target, pkg)
                } finally {
                    WebSession.throttle.finish(target.host)
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                // Fail open, silently.
            }
        }
    }

    private suspend fun check(graph: AppGraph, t: WebGuardPolicy.Target, pkg: String) {
        val cacheKey = if (t.isMockScam) "h:${t.key}" else ScanCache.hostKey(t.host) ?: return
        graph.cache.get(cacheKey)?.let {
            act(graph, it, t, pkg, fresh = false)
            return
        }
        val reporter = try {
            graph.settings.reporterId()
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            null
        }
        debug(graph, "scan fast ${t.host}")
        val fast = scan(graph, t, reporter, deep = false)
        if (fast !is ApiResult.Ok) {
            debug(graph, "fail open ${t.host}: ${fast.javaClass.simpleName}")
            return
        }
        var info = fast.value.toVerdictInfo(ScanKind.WEB)
        if (WebGuardPolicy.wantsDeepScan(info.verdict, info.score)) {
            debug(graph, "scan deep ${t.host} (fast ${info.score})")
            val deep = scan(graph, t, reporter, deep = true)
            if (deep is ApiResult.Ok) info = deep.value.toVerdictInfo(ScanKind.WEB)
        }
        if (info.domain == null) info = info.copy(domain = t.host)
        graph.settings.incrementChecked()
        graph.cache.put(cacheKey, info)
        debug(graph, "verdict ${t.host}: ${info.verdict.wire} ${info.score}")
        act(graph, info, t, pkg, fresh = true)
    }

    private suspend fun scan(graph: AppGraph, t: WebGuardPolicy.Target, reporter: String?, deep: Boolean) =
        graph.api.analyzeUrl(
            url = t.url,
            messageText = null,
            reporterId = reporter,
            runSandbox = deep,
            useLlm = deep,
            interception = Interception.GUARD,
            channel = "web",
            timeoutMs = if (deep) WebGuardPolicy.DEEP_TIMEOUT_MS else WebGuardPolicy.FAST_TIMEOUT_MS,
        )

    private suspend fun act(graph: AppGraph, info: VerdictInfo, t: WebGuardPolicy.Target, pkg: String, fresh: Boolean) {
        when (WebGuardPolicy.action(info.verdict, info.score)) {
            WebGuardPolicy.Action.BLOCK -> {
                val record = AlertRecord.from(info, AlertKind.WEB)
                if (fresh) graph.alertStore.add(record)
                // A deep scan can take a minute: block only if the browser still shows that site.
                val stillThere = withContext(Dispatchers.Main) {
                    readUrlBar(pkg)?.let(WebGuardPolicy::normalise)?.host == t.host
                }
                if (!stillThere) {
                    if (fresh) AlertNotifier.notify(applicationContext, record, info.xEligible)
                    return
                }
                if (!WebSession.gate.tryLaunch(t.key, t.host)) return
                withContext(Dispatchers.Main) { launchBlock(graph, record, t, pkg) }
            }
            WebGuardPolicy.Action.CAUTION -> if (fresh) {
                val record = AlertRecord.from(info, AlertKind.WEB)
                graph.alertStore.add(record)
                AlertNotifier.notify(applicationContext, record, info.xEligible)
            }
            WebGuardPolicy.Action.NONE -> Unit
        }
    }

    private fun launchBlock(graph: AppGraph, record: AlertRecord, t: WebGuardPolicy.Target, pkg: String) {
        try {
            // An enabled AccessibilityService is exempt from Android 10+ background-activity limits.
            startActivity(BlockAlertActivity.intent(this, record, t.url, t.host, pkg))
            debug(graph, "block screen launched for ${t.host}")
        } catch (e: Exception) {
            debug(graph, "block launch failed: ${e.javaClass.simpleName}")
            AlertNotifier.notify(applicationContext, record, record.score?.let { it >= 60 } == true)
        }
    }

    /**
     * "Close & stay safe": after the block screen finished, press BACK in the browser; if it
     * still shows [host] a moment later (e.g. the tab had no history), open [safeUrl] in it.
     */
    fun leaveScamPage(host: String, browserPkg: String?, safeUrl: String) {
        main.postDelayed({
            try {
                performGlobalAction(GLOBAL_ACTION_BACK)
            } catch (_: Exception) {
                // Ignore: the fallback below still runs.
            }
        }, BACK_DELAY_MS)
        main.postDelayed({
            try {
                val pkg = browserPkg ?: return@postDelayed
                val now = readUrlBar(pkg)?.let(WebGuardPolicy::normalise)
                if (now?.host == host) openSafePage(this, safeUrl, pkg)
            } catch (_: Exception) {
                // Nothing more to do.
            }
        }, VERIFY_DELAY_MS)
    }

    private fun debug(graph: AppGraph, msg: String) {
        if (graph.settings.isDebugBuild) Log.i(TAG, msg)
    }

    private fun debugOnce(graph: AppGraph, key: String, msg: String) {
        if (lastLogged == key) return
        lastLogged = key
        debug(graph, msg)
    }

    companion object {
        private const val TAG = "SaqrWebGuard"
        private const val BACK_DELAY_MS = 350L
        private const val VERIFY_DELAY_MS = 1_800L

        @Volatile
        private var instance: WeakReference<SaqrBrowserGuardService>? = null

        /** The running service, if Android has it bound right now. */
        fun running(): SaqrBrowserGuardService? = instance?.get()

        fun component(context: Context) = ComponentName(context, SaqrBrowserGuardService::class.java)

        /** True when SAQR's web blocker is switched on in Settings > Accessibility. */
        fun isEnabled(context: Context): Boolean = try {
            val list = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            val me = component(context)
            !list.isNullOrEmpty() && list.split(':').any { ComponentName.unflattenFromString(it.trim()) == me }
        } catch (_: RuntimeException) {
            false
        }

        /** "host[:port]" of the API base URL, or null. */
        fun apiHostOf(base: String?): String? = try {
            val u = URI(base ?: return null)
            val h = u.host?.lowercase() ?: return null
            if (u.port > 0) "$h:${u.port}" else h
        } catch (_: Exception) {
            null
        }

        /** Opens [url] in [browserPkg] (or any browser), for leaving a scam page. */
        fun openSafePage(context: Context, url: String, browserPkg: String?): Boolean {
            val base = Intent(Intent.ACTION_VIEW, url.toUri())
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (browserPkg != null) {
                try {
                    context.startActivity(
                        Intent(base).setPackage(browserPkg).putExtra(Browser.EXTRA_APPLICATION_ID, browserPkg),
                    )
                    return true
                } catch (_: ActivityNotFoundException) {
                    // Fall through to any browser.
                } catch (_: SecurityException) {
                    // Fall through.
                }
            }
            return try {
                context.startActivity(base)
                true
            } catch (_: Exception) {
                false
            }
        }

        @Suppress("DEPRECATION")
        private fun recycle(node: AccessibilityNodeInfo?) {
            // recycle() is a no-op from API 33; before that, nodes are pooled and must be returned.
            if (node != null && Build.VERSION.SDK_INT < 33) {
                try {
                    node.recycle()
                } catch (_: IllegalStateException) {
                    // Already recycled.
                }
            }
        }
    }
}
