package org.scamshield.app.core.receiver

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import org.scamshield.app.MainActivity

class PackageAddedReceiver : BroadcastReceiver() {

    companion object {
        private const val CHANNEL_ID = "scamshield_app_audit"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_PACKAGE_ADDED) return

        val uri = intent.data ?: return
        val packageName = uri.schemeSpecificPart ?: return

        try {
            val pm = context.packageManager
            val flags = PackageManager.GET_PERMISSIONS

            val pkgInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, flags)
            }

            val appName = pkgInfo.applicationInfo?.loadLabel(pm)?.toString() ?: packageName
            val requestedPerms = pkgInfo.requestedPermissions?.toList() ?: emptyList()

            val dangerousDetected = mutableListOf<String>()
            var riskScore = 0

            if (requestedPerms.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                dangerousDetected.add("Accessibility Abuse (Keylogging / Auto-Click)")
                riskScore += 50
            }
            if (requestedPerms.contains("android.permission.RECEIVE_SMS") || requestedPerms.contains("android.permission.READ_SMS")) {
                dangerousDetected.add("SMS 2FA / OTP Interception")
                riskScore += 35
            }
            if (requestedPerms.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
                dangerousDetected.add("Screen Overlay (Fake Phishing Forms)")
                riskScore += 25
            }

            if (riskScore >= 50) {
                triggerAppWarning(context, appName, packageName, dangerousDetected, riskScore)
            }
        } catch (e: Exception) {
            // Package info retrieval error
        }
    }

    private fun triggerAppWarning(
        context: Context,
        appName: String,
        packageName: String,
        dangerousPermissions: List<String>,
        score: Int
    ) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Installed App Risk Auditor",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when newly installed apps request dangerous banking trojan permissions"
                enableVibration(true)
            }
            nm.createNotificationChannel(channel)
        }

        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingOpen = PendingIntent.getActivity(context, 0, openIntent, PendingIntent.FLAG_IMMUTABLE)

        val warningText = "Newly installed app '$appName' ($packageName) requested high-risk permissions:\n${dangerousPermissions.joinToString("\n• ", prefix = "• ")}\n\nRisk Score: $score/100"

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("🚨 High-Risk App Installed!")
            .setContentText("'$appName' has banking trojan permission indicators (Score: $score/100).")
            .setStyle(NotificationCompat.BigTextStyle().bigText(warningText))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setAutoCancel(true)
            .setContentIntent(pendingOpen)
            .build()

        nm.notify((packageName.hashCode() % 10000), notification)
    }
}
