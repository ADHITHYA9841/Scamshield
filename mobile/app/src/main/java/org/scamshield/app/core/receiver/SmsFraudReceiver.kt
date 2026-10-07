package org.scamshield.app.core.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Telephony
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.scamshield.app.MainActivity
import org.scamshield.app.ScamShieldApp
import java.util.Locale

class SmsFraudReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val SMS_ALERT_CHANNEL = "scamshield_sms_alerts"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val fullTextBuilder = StringBuilder()
        var sender = "Unknown Sender"

        for (sms in messages) {
            sender = sms.displayOriginatingAddress ?: sms.originatingAddress ?: "Unknown"
            fullTextBuilder.append(sms.displayMessageBody ?: sms.messageBody ?: "")
        }

        val messageText = fullTextBuilder.toString()
        if (messageText.isBlank()) return

        // 1. Instant local heuristic scan for common Indian & global cyber fraud patterns
        val fraudResult = evaluateSmsHeuristics(messageText, sender)
        if (fraudResult != null) {
            triggerFraudNotification(context, fraudResult.first, fraudResult.second, messageText)
        }

        // 2. Also send to ScamShield backend in background for deep neural NLP analysis
        scope.launch {
            try {
                val app = context.applicationContext as? ScamShieldApp ?: return@launch
                val result = app.repository.analyzeText(messageText)
                result.onSuccess { res ->
                    if (res.verdict == "SCAM" && fraudResult == null) {
                        triggerFraudNotification(
                            context,
                            title = "🚨 Scam SMS Detected (${res.scamType})",
                            warning = res.explanation,
                            fullMessage = messageText
                        )
                    }
                }
            } catch (e: Exception) {
                // Ignore network errors in broadcast receiver
            }
        }
    }

    private fun evaluateSmsHeuristics(text: String, sender: String): Pair<String, String>? {
        val lower = text.lowercase(Locale.ROOT)

        // Pattern 1: Electricity Cutoff Scam (Very prevalent: "Electricity power will be disconnected tonight...")
        val isElectricityScam = (lower.contains("electricity") || lower.contains("bijli") || lower.contains("power")) &&
                (lower.contains("disconnect") || lower.contains("cut off") || lower.contains("bill update") || lower.contains("tonight at 9:30"))
        if (isElectricityScam) {
            return Pair(
                "🚨 Fake Electricity Disconnection Scam!",
                "Urgent threat claiming electricity will be disconnected. Power departments never send personal mobile numbers for bill payments."
            )
        }

        // Pattern 2: Bank KYC / Account Blocked Scam (SBI YONO, HDFC, PAN linking)
        val isKycScam = (lower.contains("sbi") || lower.contains("yono") || lower.contains("hdfc") || lower.contains("icici") || lower.contains("pnb") || lower.contains("bank")) &&
                (lower.contains("block") || lower.contains("suspend") || lower.contains("pan") || lower.contains("kyc") || lower.contains("update immediate"))
        if (isKycScam) {
            return Pair(
                "🚨 Banking KYC Phishing Alert!",
                "Message claims your bank account or YONO is blocked. Banks NEVER ask to update KYC or PAN via SMS links."
            )
        }

        // Pattern 3: Part-Time Job / Telegram Task Scam ("Earn 5000/day", "Like YouTube videos")
        val isJobScam = (lower.contains("part time") || lower.contains("earn daily") || lower.contains("per day") || lower.contains("youtube like")) &&
                (lower.contains("telegram") || lower.contains("whatsapp") || lower.contains("salary"))
        if (isJobScam) {
            return Pair(
                "⚠️ Part-Time Job / Task Scam Alert",
                "Promises unrealistic daily income for simple tasks. These lead to financial deposit traps."
            )
        }

        // Pattern 4: Fake Courier / India Post Delivery Fee
        val isCourierScam = (lower.contains("india post") || lower.contains("courier") || lower.contains("delivery") || lower.contains("packet")) &&
                (lower.contains("address wrong") || lower.contains("update address") || lower.contains("fee") || lower.contains("pending"))
        if (isCourierScam) {
            return Pair(
                "⚠️ Fake Delivery / Courier Phishing Alert",
                "Claims package cannot be delivered due to incomplete address. Do NOT click provided links."
            )
        }

        // Pattern 5: OTP / PIN Harvesting Request
        val isOtpTheft = (lower.contains("otp") || lower.contains("pin") || lower.contains("password")) &&
                (lower.contains("share") || lower.contains("send to") || lower.contains("claim reward") || lower.contains("verification code"))
        if (isOtpTheft) {
            return Pair(
                "🚨 CRITICAL: OTP Theft Attempt!",
                "Never share your OTP with anyone. ScamShield detected an attempt to solicit your one-time password."
            )
        }

        return null
    }

    private fun triggerFraudNotification(context: Context, title: String, warning: String, fullMessage: String) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                SMS_ALERT_CHANNEL,
                "Fraud & Scam SMS Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Immediate alerts for detected phishing, KYC, and financial fraud messages"
                enableVibration(true)
            }
            nm.createNotificationChannel(channel)
        }

        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("shared_text", fullMessage)
        }
        val pendingIntent = PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(context, SMS_ALERT_CHANNEL)
            .setContentTitle(title)
            .setContentText(warning)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$warning\n\nSMS Content: \"$fullMessage\""))
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        nm.notify((System.currentTimeMillis() % 10000).toInt(), notification)
    }
}
