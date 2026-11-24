package ae.saqrintel.shield.ui.verdict

import ae.saqrintel.shield.appGraph
import ae.saqrintel.shield.data.VerdictInfo
import ae.saqrintel.shield.util.XAlert
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.launch

object VerdictActions {
    /**
     * Opens X with the warning draft, then logs it (POST /api/police/log-x-alert) in the app
     * scope. Returns false when nothing could open the link.
     */
    fun warnOnX(context: Context, info: VerdictInfo, arabic: Boolean): Boolean {
        if (!info.xEligible) return false
        val text = XAlert.buildDraft(info, arabic)
        try {
            context.startActivity(XAlert.intent(text).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        } catch (_: ActivityNotFoundException) {
            return false
        } catch (_: SecurityException) {
            return false
        }
        val domain = info.domain
        val graph = context.appGraph
        if (domain != null && graph != null) {
            graph.appScope.launch { graph.api.logXAlert(domain, info.entityEn) }
        }
        return true
    }
}
