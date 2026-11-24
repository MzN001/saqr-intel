package ae.saqrintel.shield.guard

import ae.saqrintel.shield.MainActivity
import ae.saqrintel.shield.R
import ae.saqrintel.shield.data.AlertKind
import ae.saqrintel.shield.data.AlertRecord
import ae.saqrintel.shield.data.Verdict
import ae.saqrintel.shield.locale.LocaleController
import ae.saqrintel.shield.ui.theme.SaqrPalette
import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.compose.ui.graphics.toArgb
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Minimal guard notifications, exactly two lines: title ("Scam SMS blocked · 96/100") and text
 * ("Fake TAMM (tamm-smart-pay[.]net) — Do not tap.", <= 65 chars), no BigTextStyle; crimson accent for
 * high-risk, amber for the caution channel; "View verdict" and (when eligible) "Warn on X".
 * Wording is honest: the app warns; it cannot delete the original message.
 */
object AlertNotifier {
    const val CHANNEL_ALERTS = "scam_alerts"
    const val CHANNEL_CAUTIONS = "cautions"
    const val MAX_TEXT = 65

    /** Short names so the one-line text fits. */
    private val SHORT_EN = mapOf(
        "TAMM Abu Dhabi" to "TAMM",
        "First Abu Dhabi Bank (FAB)" to "FAB",
        "e& (Etisalat)" to "e&",
    )

    fun createChannels(context: Context) {
        try {
            val res = LocaleController.wrap(context).resources
            val nm = context.getSystemService(NotificationManager::class.java) ?: return
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ALERTS, res.getString(R.string.notif_channel_alerts), NotificationManager.IMPORTANCE_HIGH)
                    .apply { description = res.getString(R.string.notif_channel_alerts_desc) },
            )
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_CAUTIONS, res.getString(R.string.notif_channel_cautions), NotificationManager.IMPORTANCE_DEFAULT)
                    .apply { description = res.getString(R.string.notif_channel_cautions_desc) },
            )
        } catch (_: RuntimeException) {
            // Never crash app start over a notification channel.
        }
    }

    fun canNotify(context: Context): Boolean {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    /** Pure: fits the one-line text (entity version first, then without entity, then ellipsized). */
    fun fitLine(preferred: String, fallback: String, max: Int = MAX_TEXT): String = when {
        preferred.length <= max -> preferred
        fallback.length <= max -> fallback
        else -> fallback.take(max - 1).trimEnd() + "…"
    }

    fun shortEntity(entityEn: String): String = SHORT_EN[entityEn] ?: entityEn

    private fun kindWord(context: Context, kind: AlertKind): String = context.getString(
        when (kind) {
            AlertKind.SMS -> R.string.notif_kind_sms
            AlertKind.WHATSAPP -> R.string.notif_kind_whatsapp
            AlertKind.EMAIL -> R.string.notif_kind_email
            AlertKind.WEB -> R.string.notif_kind_web
            else -> R.string.notif_kind_message
        },
    )

    fun title(context: Context, record: AlertRecord): String {
        val score = (record.score ?: 0).toString() // Western digits in both languages
        if (record.kind == AlertKind.WEB) {
            // Own strings: "website" changes the Arabic grammar of the shared template.
            return context.getString(
                if (record.verdictValue == Verdict.SCAM) R.string.notif_title_web_scam else R.string.notif_title_web_caution,
                score,
            )
        }
        val kind = kindWord(context, record.kind)
        return if (record.verdictValue == Verdict.SCAM) {
            context.getString(R.string.notif_title_scam, kind, score)
        } else {
            context.getString(R.string.notif_title_caution, kind, score)
        }
    }

    fun text(context: Context, record: AlertRecord): String {
        val arabic = LocaleController.current(context) == LocaleController.ARABIC
        val entity = if (arabic) record.entityAr ?: record.entityEn else record.entityEn?.let(::shortEntity)
        val scam = record.verdictValue == Verdict.SCAM
        val domain = record.label
        val generic = when {
            domain != null -> context.getString(if (scam) R.string.notif_text_link_scam else R.string.notif_text_link_caution, domain)
            record.credentialRequest -> context.getString(R.string.notif_text_code)
            else -> context.getString(if (scam) R.string.notif_text_generic_scam else R.string.notif_text_generic_caution)
        }
        val withEntity = when {
            entity == null -> generic
            domain != null -> context.getString(R.string.notif_text_entity_link, entity, domain)
            record.credentialRequest -> context.getString(R.string.notif_text_entity_code, entity)
            else -> context.getString(R.string.notif_text_entity, entity)
        }
        return fitLine(withEntity, generic)
    }

    /** Posts the alert. Silently does nothing without notification permission. */
    fun notify(context: Context, record: AlertRecord, xEligible: Boolean) {
        val ctx = LocaleController.wrap(context)
        if (!canNotify(ctx)) return
        val scam = record.verdictValue == Verdict.SCAM
        val requestBase = record.id.hashCode()
        val view = PendingIntent.getActivity(
            ctx, requestBase,
            MainActivity.alertIntent(ctx, record.id, warnOnX = false),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = NotificationCompat.Builder(ctx, if (scam) CHANNEL_ALERTS else CHANNEL_CAUTIONS)
            .setSmallIcon(R.drawable.ic_shield_alert)
            .setColor(if (scam) SaqrPalette.ScamFill.toArgb() else SaqrPalette.SuspiciousFill.toArgb())
            .setContentTitle(title(ctx, record))
            .setContentText(text(ctx, record))
            .setContentIntent(view)
            .setAutoCancel(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(if (scam) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(0, ctx.getString(R.string.notif_action_view), view)
        if (xEligible) {
            val warn = PendingIntent.getActivity(
                ctx, requestBase + 1,
                MainActivity.alertIntent(ctx, record.id, warnOnX = true),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            builder.addAction(0, ctx.getString(R.string.notif_action_x), warn)
        }
        try {
            if (Build.VERSION.SDK_INT < 33 ||
                ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            ) {
                NotificationManagerCompat.from(ctx).notify(record.id, NOTIFICATION_ID, builder.build())
            }
        } catch (_: SecurityException) {
            // Permission revoked between the check and the post.
        }
    }

    private const val NOTIFICATION_ID = 1

    fun cancel(context: Context, alertId: String) {
        try {
            NotificationManagerCompat.from(context).cancel(alertId, NOTIFICATION_ID)
        } catch (_: RuntimeException) {
            // Nothing to cancel.
        }
    }
}
