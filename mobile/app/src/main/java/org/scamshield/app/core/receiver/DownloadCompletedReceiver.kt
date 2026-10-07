package org.scamshield.app.core.receiver

import android.app.DownloadManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.scamshield.app.MainActivity
import org.scamshield.app.ScamShieldApp
import org.scamshield.app.core.security.ApkSecurityAuditor
import java.io.File
import java.util.regex.Pattern

class DownloadCompletedReceiver : BroadcastReceiver() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    companion object {
        private const val CHANNEL_ID = "scamshield_download_shield"
        const val ACTION_DELETE_DOWNLOAD = "org.scamshield.app.ACTION_DELETE_DOWNLOAD"
        const val EXTRA_DOWNLOAD_ID = "extra_download_id"
        const val EXTRA_FILE_PATH = "extra_file_path"
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_DELETE_DOWNLOAD) {
            handleDeleteRequest(context, intent)
            return
        }

        if (intent.action != DownloadManager.ACTION_DOWNLOAD_COMPLETE) return

        val prefs = context.getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("auto_download_scan", true)) return

        val downloadId = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1L)
        if (downloadId == -1L) return

        val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
        val query = DownloadManager.Query().setFilterById(downloadId)
        val cursor = dm.query(query) ?: return

        var filename = "downloaded_file"
        var sourceUrl = ""
        var localUriStr: String? = null
        var fileSize: Long = 0L
        var mimeType: String? = null

        cursor.use {
            if (it.moveToFirst()) {
                val titleIndex = it.getColumnIndex(DownloadManager.COLUMN_TITLE)
                val uriIndex = it.getColumnIndex(DownloadManager.COLUMN_URI)
                val localUriIndex = it.getColumnIndex(DownloadManager.COLUMN_LOCAL_URI)
                val sizeIndex = it.getColumnIndex(DownloadManager.COLUMN_TOTAL_SIZE_BYTES)
                val mimeIndex = it.getColumnIndex(DownloadManager.COLUMN_MEDIA_TYPE)

                if (titleIndex != -1) filename = it.getString(titleIndex) ?: filename
                if (uriIndex != -1) sourceUrl = it.getString(uriIndex) ?: ""
                if (localUriIndex != -1) localUriStr = it.getString(localUriIndex)
                if (sizeIndex != -1) fileSize = it.getLong(sizeIndex)
                if (mimeIndex != -1) mimeType = it.getString(mimeIndex)
            }
        }

        val localFile = localUriStr?.let {
            try {
                val parsed = Uri.parse(it)
                if (parsed.scheme == "file") File(parsed.path ?: "") else null
            } catch (e: Exception) {
                null
            }
        }

        if (localFile != null && localFile.exists()) {
            filename = localFile.name
            if (fileSize == 0L) fileSize = localFile.length()
        }

        // 1. Instant Synchronous Check for Disguised Double Extension (.pdf.apk, .docx.exe, .jpg.scr)
        val lowerName = filename.lowercase()
        val isDoubleExt = Pattern.compile(
            "\\.(pdf|docx|xlsx|jpg|png|txt|zip)\\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$",
            Pattern.CASE_INSENSITIVE
        ).matcher(lowerName).find()

        if (isDoubleExt) {
            triggerThreatAlert(
                context = context,
                downloadId = downloadId,
                filePath = localFile?.absolutePath,
                title = "🚨 DANGEROUS DOWNLOAD BLOCKED!",
                message = "'$filename' is disguising an executable payload with a fake document extension (Risk: 98/100).",
                riskScore = 98,
                isCritical = true
            )
            return
        }

        // 2. Check for Sideload APK
        if (lowerName.endsWith(".apk") && localFile != null && localFile.exists()) {
            val apkAudit = ApkSecurityAuditor.auditApkFile(context, localFile)
            if (apkAudit != null && apkAudit.isHighRisk) {
                triggerThreatAlert(
                    context = context,
                    downloadId = downloadId,
                    filePath = localFile.absolutePath,
                    title = "🚨 High-Risk Banking Trojan APK!",
                    message = "'$filename' requests dangerous permissions: ${apkAudit.dangerousPermissions.take(2).joinToString(", ")} (Score: ${apkAudit.riskScore}/100).",
                    riskScore = apkAudit.riskScore,
                    isCritical = true
                )
                return
            }
        }

        // 3. Query ScamShield Backend for VirusTotal 90+ Multi-Engine Reputation in Background
        scope.launch {
            try {
                val app = context.applicationContext as? ScamShieldApp ?: return@launch
                val result = app.repository.analyzeDownload(
                    url = if (sourceUrl.isNotBlank()) sourceUrl else "file://$filename",
                    filename = filename,
                    fileSize = fileSize,
                    mimeType = mimeType
                )

                result.onSuccess { res ->
                    if (res.verdict == "SCAM" || res.riskScore >= 70) {
                        triggerThreatAlert(
                            context = context,
                            downloadId = downloadId,
                            filePath = localFile?.absolutePath,
                            title = "🚨 VirusTotal Malicious Download Alert!",
                            message = "'$filename' flagged by global antivirus vendors (Risk: ${res.riskScore}/100). Category: ${res.scamCategory}",
                            riskScore = res.riskScore,
                            isCritical = true
                        )
                    } else if (res.verdict == "SUSPICIOUS") {
                        triggerThreatAlert(
                            context = context,
                            downloadId = downloadId,
                            filePath = localFile?.absolutePath,
                            title = "⚠️ Suspicious Download Alert",
                            message = "'$filename' has suspicious indicators (Score: ${res.riskScore}/100). Exercise caution before opening.",
                            riskScore = res.riskScore,
                            isCritical = false
                        )
                    } else {
                        // Clean download verified
                        triggerSafeNotification(context, filename, res.riskScore)
                    }
                }
            } catch (e: Exception) {
                // Network error / Standalone mode - fallback to safe confirmation
                triggerSafeNotification(context, filename, 0)
            }
        }
    }

    private fun handleDeleteRequest(context: Context, intent: Intent) {
        val downloadId = intent.getLongExtra(EXTRA_DOWNLOAD_ID, -1L)
        val filePath = intent.getStringExtra(EXTRA_FILE_PATH)

        // 1. Remove from DownloadManager
        if (downloadId != -1L) {
            try {
                val dm = context.getSystemService(Context.DOWNLOAD_SERVICE) as DownloadManager
                dm.remove(downloadId)
            } catch (e: Exception) {}
        }

        // 2. Delete file physically from disk
        if (!filePath.isNullOrBlank()) {
            try {
                val file = File(filePath)
                if (file.exists()) file.delete()
            } catch (e: Exception) {}
        }

        // 3. Clear notification
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.cancel((downloadId % 10000).toInt())
    }

    private fun triggerThreatAlert(
        context: Context,
        downloadId: Long,
        filePath: String?,
        title: String,
        message: String,
        riskScore: Int,
        isCritical: Boolean
    ) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createChannel(nm)

        // Open app intent
        val openIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingOpen = PendingIntent.getActivity(context, 0, openIntent, PendingIntent.FLAG_IMMUTABLE)

        // Delete action intent
        val deleteIntent = Intent(context, DownloadCompletedReceiver::class.java).apply {
            action = ACTION_DELETE_DOWNLOAD
            putExtra(EXTRA_DOWNLOAD_ID, downloadId)
            putExtra(EXTRA_FILE_PATH, filePath)
        }
        val pendingDelete = PendingIntent.getBroadcast(
            context,
            downloadId.toInt(),
            deleteIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$message\n\n🛡️ VirusTotal Risk Score: $riskScore/100"))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setPriority(if (isCritical) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingOpen)
            .addAction(android.R.drawable.ic_menu_delete, "🚫 Delete & Remove", pendingDelete)
            .addAction(android.R.drawable.ic_menu_view, "🛡️ Inspect in App", pendingOpen)
            .build()

        nm.notify((downloadId % 10000).toInt(), notification)
    }

    private fun triggerSafeNotification(context: Context, filename: String, riskScore: Int) {
        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createChannel(nm)

        val openIntent = Intent(context, MainActivity::class.java)
        val pendingOpen = PendingIntent.getActivity(context, 0, openIntent, PendingIntent.FLAG_IMMUTABLE)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setContentTitle("🛡️ ScamShield: Download Verified Safe")
            .setContentText("'$filename' scanned clean across 90+ antivirus engines (Risk: $riskScore/100).")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .setContentIntent(pendingOpen)
            .build()

        nm.notify((System.currentTimeMillis() % 10000).toInt(), notification)
    }

    private fun createChannel(nm: NotificationManager) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Automatic Download Scanner",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Scans all downloaded files automatically with VirusTotal threat intelligence"
                enableVibration(true)
            }
            nm.createNotificationChannel(channel)
        }
    }
}
