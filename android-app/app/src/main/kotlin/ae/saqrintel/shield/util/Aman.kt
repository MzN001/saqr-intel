package ae.saqrintel.shield.util

import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.data.VerdictInfo
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import androidx.core.net.toUri
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Abu Dhabi Police Aman service: call 8002626 (dialer only, no CALL permission) or SMS 2828. */
object Aman {
    const val PHONE = "8002626"
    const val SMS = "2828"

    fun dialIntent(): Intent = Intent(Intent.ACTION_DIAL, "tel:$PHONE".toUri())

    /** Opens the dialer with 8002626 filled in; false if no dialer app exists (e.g. a tablet). */
    fun dial(context: Context): Boolean = try {
        context.startActivity(dialIntent().addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (_: ActivityNotFoundException) {
        false
    } catch (_: SecurityException) {
        false
    }

    /** Short report to paste into an Aman SMS / email (same fields as share.ts buildAmanReport). */
    fun reportText(info: VerdictInfo, arabic: Boolean): String {
        // Western digits in both languages, Gulf time.
        val fmt = DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm", if (arabic) Locale.forLanguageTag("ar-AE-u-nu-latn") else Locale.UK)
        val whenText = Instant.ofEpochMilli(info.detectedAt).atZone(ZoneId.of("Asia/Dubai")).format(fmt)
        val site = info.domain?.let(Defang::defang) ?: "—"
        val score = info.score?.let { " ($it/100)" }.orEmpty()
        val reasons = info.reasons.map { "- " + if (arabic) it.ar else it.en }
        val lines = if (arabic) {
            listOfNotNull(
                "بلاغ احتيال — صقر للاستخبارات → أمان $SMS",
                info.scanId?.let { "رقم الفحص: $it" },
                "الوقت: $whenText (توقيت الإمارات)",
                "النتيجة: ${verdictAr(info.verdict)}$score",
                XAlert.entityAr(info)?.let { "ينتحل صفة: $it" },
                "الموقع المشبوه (معطّل): $site",
                "طريقة الرصد: تطبيق درع صقر",
                if (reasons.isNotEmpty()) "علامات الخطر:\n" + reasons.joinToString("\n") else null,
            )
        } else {
            listOfNotNull(
                "SAQR-INTEL fraud report → Aman $SMS",
                info.scanId?.let { "Scan ID: $it" },
                "Time: $whenText (UAE)",
                "Verdict: ${info.verdict.wire}$score",
                info.entityEn?.let { "Impersonating: $it" },
                "Suspicious site (masked): $site",
                "Detected via: SAQR Shield app",
                if (reasons.isNotEmpty()) "Red flags:\n" + reasons.joinToString("\n") else null,
            )
        }
        return lines.joinToString("\n")
    }

    private fun verdictAr(v: Verdict) = when (v) {
        Verdict.SAFE -> "آمن"
        Verdict.SUSPICIOUS -> "مشبوه"
        Verdict.SCAM -> "احتيال عالي الخطورة"
    }

    fun copy(context: Context, label: String, text: String): Boolean = try {
        val cm = context.getSystemService(ClipboardManager::class.java)
        cm?.setPrimaryClip(ClipData.newPlainText(label, text))
        cm != null
    } catch (_: Exception) {
        false
    }
}
