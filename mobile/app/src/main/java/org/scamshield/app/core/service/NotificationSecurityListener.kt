package org.scamshield.app.core.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.scamshield.app.MainActivity
import org.scamshield.app.ScamShieldApp
import java.util.Locale
import java.util.regex.Pattern

class NotificationSecurityListener : NotificationListenerService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val CHANNEL_ID = "scamshield_mail_chat_alerts"
    }

    override fun onNotificationPosted(sbn: StatusBarNotification?) {
        super.onNotificationPosted(sbn)
        if (sbn == null) return

        val pkg = sbn.packageName ?: ""
        // Do not inspect our own notifications
        if (pkg == packageName) return

        val extras = sbn.notification?.extras ?: return
        val title = extras.getCharSequence("android.title")?.toString() ?: ""
        val text = extras.getCharSequence("android.text")?.toString() ?: ""
        val bigText = extras.getCharSequence("android.bigText")?.toString() ?: ""

        val combinedContent = "$title $text $bigText".trim()
        if (combinedContent.length < 10) return

        val lower = combinedContent.lowercase(Locale.ROOT)

        // Check for common mail / chat phishing triggers
        val isMailOrChat = pkg.contains("gmail") || pkg.contains("mail") || pkg.contains("whatsapp") ||
                pkg.contains("telegram") || pkg.contains("mms") || pkg.contains("messaging")

        // Extract any URLs inside the notification
        val urlPattern = Pattern.compile("https?://[a-zA-Z0-9.-]+(?:/[^\\s]*)?", Pattern.CASE_INSENSITIVE)
        val matcher = urlPattern.matcher(combinedContent)
        var extractedUrl: String? = null
        if (matcher.find()) {
            extractedUrl = matcher.group()
        }

        val hasUrgentThreat = (lower.contains("block") || lower.contains("suspend") || lower.contains("disconnect") ||
                lower.contains("pan card") || lower.contains("kyc") || lower.contains("lottery") || lower.contains("won rs")) &&
                (extractedUrl != null || lower.contains("click here") || lower.contains("update immediate"))

        if (hasUrgentThreat || (isMailOrChat && extractedUrl != null && (extractedUrl.contains(".ru") || extractedUrl.contains(".top") || extractedUrl.contains(".xyz")))) {
            triggerMailThreatAlert(
                sourceApp = getSourceAppName(pkg),
                warning = "Suspicious phishing notification detected with urgency triggers.",
                content = combinedContent,
                url = extractedUrl
            )

            // Deep background scan with ScamShield backend
            scope.launch {
                try {
                    val app = applicationContext as? ScamShieldApp ?: return@launch
                    if (extractedUrl != null) {
                        app.repository.analyzeUrl(extractedUrl, combinedContent)
                    } else {
                        app.repository.analyzeText(combinedContent)
                    }
                } catch (e: Exception) {}
            }
        }
    }

    private fun getSourceAppName(pkg: String): String {
        return when {
            pkg.contains("gmail") -> "Gmail"
            pkg.contains("whatsapp") -> "WhatsApp"
            pkg.contains("telegram") -> "Telegram"
            pkg.contains("outlook") -> "Outlook"
            else -> "Mail / Chat App"
        }
    }

    private fun triggerMailThreatAlert(sourceApp: String, warning: String, content: String, url: String?) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mail & Chat Phishing Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts for detected email, chat, and notification phishing attempts"
                enableVibration(true)
            }
            nm.createNotificationChannel(channel)
        }

        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingOpen = PendingIntent.getActivity(this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("🚨 $sourceApp Phishing Alert!")
            .setContentText(warning)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$warning\n\nNotification: \"$content\"${if (url != null) "\nLink: $url" else ""}"))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setAutoCancel(true)
            .setContentIntent(pendingOpen)
            .build()

        nm.notify((System.currentTimeMillis() % 10000).toInt(), notification)
    }
}
