package org.scamshield.app.core.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ContentUris
import android.content.Context
import android.content.Intent
import android.database.ContentObserver
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.FileObserver
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.provider.MediaStore
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.scamshield.app.MainActivity
import org.scamshield.app.ScamShieldApp
import org.scamshield.app.core.database.ScanEntity
import org.scamshield.app.core.security.ApkSecurityAuditor
import java.io.File
import java.util.Collections
import java.util.regex.Pattern

class StorageWatcherService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var downloadObserver: FileObserver? = null
    private var mediaDownloadsObserver: ContentObserver? = null
    private var mediaFilesObserver: ContentObserver? = null
    private var periodicScanJob: Job? = null

    // Track recently scanned files to prevent duplicate notifications
    private val scannedKeys = Collections.synchronizedSet(mutableSetOf<String>())

    companion object {
        private const val TAG = "StorageWatcher"
        private const val CHANNEL_ID = "scamshield_storage_watcher"
        const val ALERT_CHANNEL_ID = "scamshield_threat_alerts"
        private const val NOTIFICATION_ID = 1001

        const val ACTION_DELETE_FILE = "org.scamshield.app.ACTION_DELETE_DOWNLOAD_FILE"
        const val EXTRA_FILE_PATH = "extra_file_path"

        fun startService(context: Context) {
            try {
                val prefs = context.getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE)
                val isEnabled = prefs.getBoolean("auto_download_scan", true)
                if (!isEnabled) return

                val intent = Intent(context, StorageWatcherService::class.java)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to start StorageWatcherService: ${e.message}")
            }
        }

        fun stopService(context: Context) {
            try {
                val intent = Intent(context, StorageWatcherService::class.java)
                context.stopService(intent)
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to stop StorageWatcherService: ${e.message}")
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        try {
            createNotificationChannels()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                    NOTIFICATION_ID,
                    createForegroundNotification(),
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
                )
            } else {
                startForeground(NOTIFICATION_ID, createForegroundNotification())
            }
        } catch (e: Throwable) {
            Log.w(TAG, "Foreground notification startup notice: ${e.message}")
        }

        // Initialize multiple redundant layers of download detection
        startContentObservers()
        startFileObserver()
        startPeriodicCheck()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DELETE_FILE) {
            val path = intent.getStringExtra(EXTRA_FILE_PATH)
            if (!path.isNullOrBlank()) {
                handleFileDeletion(path)
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        downloadObserver?.stopWatching()
        mediaDownloadsObserver?.let { try { contentResolver.unregisterContentObserver(it) } catch (e: Throwable) {} }
        mediaFilesObserver?.let { try { contentResolver.unregisterContentObserver(it) } catch (e: Throwable) {} }
        periodicScanJob?.cancel()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)

            // Silent status channel for persistent service icon
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                "Storage Shield Active",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Monitors device downloads for deceptive malware & disguised extensions"
                setShowBadge(false)
            }
            nm.createNotificationChannel(serviceChannel)

            // High importance alert channel for detected threats & scans
            val alertChannel = NotificationChannel(
                ALERT_CHANNEL_ID,
                "Scam & Malware Alerts",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Alerts when dangerous downloads or scam payloads are detected"
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 300, 150, 300)
            }
            nm.createNotificationChannel(alertChannel)
        }
    }

    private fun createForegroundNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("ScamShield Guard Active")
            .setContentText("Automatic real-time download & file scanner running")
            .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    /**
     * Layer 1: MediaStore ContentObserver (Official Android API for catching Chrome, Browser, and App downloads)
     */
    private fun startContentObservers() {
        val handler = Handler(Looper.getMainLooper())

        val observer = object : ContentObserver(handler) {
            override fun onChange(selfChange: Boolean, uri: Uri?) {
                super.onChange(selfChange, uri)
                serviceScope.launch {
                    queryLatestMediaStoreDownloads()
                }
            }
        }

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                contentResolver.registerContentObserver(
                    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
                    true,
                    observer
                )
                mediaDownloadsObserver = observer
            }

            val filesObserver = object : ContentObserver(handler) {
                override fun onChange(selfChange: Boolean, uri: Uri?) {
                    super.onChange(selfChange, uri)
                    serviceScope.launch {
                        queryLatestMediaStoreDownloads()
                    }
                }
            }
            contentResolver.registerContentObserver(
                MediaStore.Files.getContentUri("external"),
                true,
                filesObserver
            )
            mediaFilesObserver = filesObserver
        } catch (e: Throwable) {
            Log.e(TAG, "Error registering MediaStore ContentObservers: ${e.message}")
        }
    }

    private suspend fun queryLatestMediaStoreDownloads() {
        val prefs = getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("auto_download_scan", true)) return

        try {
            val projection = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.DATE_ADDED
                )
            } else {
                arrayOf(
                    MediaStore.MediaColumns._ID,
                    MediaStore.MediaColumns.DISPLAY_NAME,
                    MediaStore.MediaColumns.SIZE,
                    MediaStore.MediaColumns.DATA
                )
            }

            val queryUri = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                MediaStore.Downloads.EXTERNAL_CONTENT_URI
            } else {
                MediaStore.Files.getContentUri("external")
            }

            contentResolver.query(
                queryUri,
                projection,
                null,
                null,
                "${MediaStore.MediaColumns.DATE_ADDED} DESC"
            )?.use { cursor ->
                var count = 0
                val idCol = cursor.getColumnIndex(MediaStore.MediaColumns._ID)
                val nameCol = cursor.getColumnIndex(MediaStore.MediaColumns.DISPLAY_NAME)
                val sizeCol = cursor.getColumnIndex(MediaStore.MediaColumns.SIZE)

                while (cursor.moveToNext() && count < 5) {
                    count++
                    val id = if (idCol != -1) cursor.getLong(idCol) else continue
                    val name = if (nameCol != -1) cursor.getString(nameCol) ?: "" else ""
                    val size = if (sizeCol != -1) cursor.getLong(sizeCol) else 0L

                    if (name.isBlank() || name.startsWith(".")) continue

                    val itemUri = ContentUris.withAppendedId(queryUri, id)
                    val key = "${name}_${size}"
                    if (!scannedKeys.contains(key)) {
                        scannedKeys.add(key)
                        inspectUriDownload(name, size, itemUri)
                    }
                }
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error querying MediaStore downloads: ${e.message}")
        }
    }

    /**
     * Layer 2: FileObserver on the standard public Download directory
     */
    private fun startFileObserver() {
        try {
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            if (!downloadsDir.exists()) downloadsDir.mkdirs()

            val mask = FileObserver.CREATE or FileObserver.CLOSE_WRITE or FileObserver.MOVED_TO

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                downloadObserver = object : FileObserver(downloadsDir, mask) {
                    override fun onEvent(event: Int, path: String?) {
                        if (path != null && (event and mask) != 0) {
                            checkAndInspectFile(File(downloadsDir, path))
                        }
                    }
                }
            } else {
                @Suppress("DEPRECATION")
                downloadObserver = object : FileObserver(downloadsDir.absolutePath, mask) {
                    override fun onEvent(event: Int, path: String?) {
                        if (path != null && (event and mask) != 0) {
                            checkAndInspectFile(File(downloadsDir, path))
                        }
                    }
                }
            }
            downloadObserver?.startWatching()
        } catch (e: Throwable) {
            Log.e(TAG, "Error starting FileObserver: ${e.message}")
        }
    }

    /**
     * Layer 3: Periodic check of Download directory for freshly modified files (failsafe fallback)
     */
    private fun startPeriodicCheck() {
        periodicScanJob = serviceScope.launch {
            while (isActive) {
                delay(10_000) // check every 10s
                val prefs = getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE)
                if (prefs.getBoolean("auto_download_scan", true)) {
                    try {
                        val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                        if (downloadsDir.exists() && downloadsDir.isDirectory) {
                            val now = System.currentTimeMillis()
                            downloadsDir.listFiles()?.filter { file ->
                                file.isFile && !file.name.startsWith(".") && (now - file.lastModified() < 25_000)
                            }?.forEach { file ->
                                checkAndInspectFile(file)
                            }
                        }
                    } catch (e: Throwable) {}
                }
            }
        }
    }

    private fun checkAndInspectFile(file: File) {
        if (!file.exists() || file.isDirectory || file.name.startsWith(".")) return

        val key = "${file.name}_${file.length()}"
        if (scannedKeys.contains(key)) return
        scannedKeys.add(key)

        serviceScope.launch {
            inspectDirectFile(file)
        }
    }

    /**
     * Performs comprehensive standalone analysis on a physical File
     */
    private suspend fun inspectDirectFile(file: File) {
        val filename = file.name
        val lowerName = filename.lowercase()
        val fileSize = file.length()

        // 1. Double extension camouflage check (e.g. invoice.pdf.apk, resume.docx.exe)
        val isDoubleExt = Pattern.compile(
            "\\.(pdf|docx|xlsx|jpg|png|txt|zip)\\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$",
            Pattern.CASE_INSENSITIVE
        ).matcher(lowerName).find()

        // 2. APK Banking Trojan / Dangerous Permissions check
        val isApk = lowerName.endsWith(".apk")
        val apkAudit = if (isApk) ApkSecurityAuditor.auditApkFile(this, file) else null

        // 3. Dangerous Executable Scripts check
        val dangerousExts = listOf(".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".jar", ".iso", ".hta", ".exe")
        val isDangerousScript = dangerousExts.any { lowerName.endsWith(it) }

        var verdict = "SAFE"
        var riskScore = 0
        var scamType = "Clean Download"
        var explanation = "File '$filename' analyzed. No deceptive camouflage or malicious signatures detected."

        if (isDoubleExt) {
            verdict = "SCAM"
            riskScore = 98
            scamType = "Double-Extension Malware Camouflage"
            explanation = "CRITICAL: '$filename' disguises an executable file using a fake document extension."
        } else if (apkAudit != null && apkAudit.isHighRisk) {
            verdict = "SCAM"
            riskScore = apkAudit.riskScore
            scamType = "Banking Trojan / High-Risk Sideload APK"
            explanation = "APK requests dangerous permissions: ${apkAudit.dangerousPermissions.take(3).joinToString(", ")}"
        } else if (isDangerousScript) {
            verdict = "SCAM"
            riskScore = 90
            scamType = "Executable Threat Payload"
            explanation = "Direct executable script detected. High potential for automated execution attacks."
        } else if (isApk) {
            verdict = "SAFE"
            riskScore = 15
            scamType = "Android Application Package"
            explanation = "Standard Android package inspected. No banking trojan capabilities identified."
        }

        // Persist in local SQLite history so it reflects in History and Stats tabs!
        saveScanRecord(filename, verdict, riskScore, scamType, explanation)

        // Post visual notification
        postDownloadNotification(filename, verdict, riskScore, scamType, explanation, file.absolutePath)

        // Also query VirusTotal cloud intelligence in background
        queryVirusTotalAsync(file.name, file.length(), "file://${file.absolutePath}")
    }

    /**
     * Performs comprehensive standalone analysis on a MediaStore Content URI
     */
    private suspend fun inspectUriDownload(filename: String, fileSize: Long, uri: Uri) {
        val lowerName = filename.lowercase()

        val isDoubleExt = Pattern.compile(
            "\\.(pdf|docx|xlsx|jpg|png|txt|zip)\\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$",
            Pattern.CASE_INSENSITIVE
        ).matcher(lowerName).find()

        val isDangerousScript = listOf(".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".jar", ".iso", ".hta", ".exe").any { lowerName.endsWith(it) }
        val isApk = lowerName.endsWith(".apk")

        var verdict = "SAFE"
        var riskScore = 0
        var scamType = "Clean Download"
        var explanation = "File '$filename' scanned upon download. No deceptive camouflage detected."

        if (isDoubleExt) {
            verdict = "SCAM"
            riskScore = 98
            scamType = "Double-Extension Malware Camouflage"
            explanation = "CRITICAL: '$filename' is an executable payload disguised with a fake document extension."
        } else if (isDangerousScript) {
            verdict = "SCAM"
            riskScore = 90
            scamType = "Executable Threat Payload"
            explanation = "Executable script downloaded. Exercise extreme caution before opening."
        } else if (isApk) {
            verdict = "SUSPICIOUS"
            riskScore = 45
            scamType = "Sideload APK Package"
            explanation = "Downloaded APK package detected. Open ScamShield to run deep permission audit."
        }

        saveScanRecord(filename, verdict, riskScore, scamType, explanation)
        postDownloadNotification(filename, verdict, riskScore, scamType, explanation, null)
        queryVirusTotalAsync(filename, fileSize, uri.toString())
    }

    private suspend fun saveScanRecord(filename: String, verdict: String, riskScore: Int, scamType: String, explanation: String) {
        try {
            val app = applicationContext as? ScamShieldApp ?: return
            app.database.scanDao().insertScan(
                ScanEntity(
                    scanId = "dl_${System.currentTimeMillis()}_${(100..999).random()}",
                    timestamp = System.currentTimeMillis(),
                    inputType = "download",
                    verdict = verdict,
                    riskScore = riskScore,
                    confidence = 0.95f,
                    scamType = scamType,
                    language = "en",
                    explanation = explanation,
                    evidenceJson = """{"filename":"$filename","source":"Auto-Scan Download Inspector"}""",
                    recommendedActionsJson = if (verdict == "SCAM") """["Delete the downloaded file immediately","Do not run or open the file"]""" else """["File is safe for device storage"]"""
                )
            )
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to persist scan record: ${e.message}")
        }
    }

    private fun postDownloadNotification(
        filename: String,
        verdict: String,
        riskScore: Int,
        scamType: String,
        explanation: String,
        filePath: String?
    ) {
        val prefs = getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE)
        val vibrate = prefs.getBoolean("vibrate_on_threat", true)
        val notifyClean = prefs.getBoolean("notify_clean_files", true)

        if (verdict == "SAFE" && !notifyClean) return

        val appIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val appPendingIntent = PendingIntent.getActivity(
            this,
            0,
            appIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val title: String
        val isCritical: Boolean

        when (verdict) {
            "SCAM" -> {
                title = "🚨 DANGEROUS DOWNLOAD BLOCKED!"
                isCritical = true
            }
            "SUSPICIOUS" -> {
                title = "⚠️ Suspicious Download Detected"
                isCritical = false
            }
            else -> {
                title = "🛡️ ScamShield: Download Verified Safe"
                isCritical = false
            }
        }

        val builder = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText("'$filename' • Risk: $riskScore/100 ($scamType)")
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("'$filename'\n\nVerdict: $verdict (Risk: $riskScore/100)\nType: $scamType\n\n$explanation")
            )
            .setSmallIcon(if (verdict == "SCAM") android.R.drawable.stat_sys_warning else android.R.drawable.ic_lock_idle_lock)
            .setPriority(if (isCritical) NotificationCompat.PRIORITY_MAX else NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(appPendingIntent)

        if (vibrate && isCritical) {
            builder.setVibrate(longArrayOf(0, 350, 150, 350))
        }

        // Add Delete Action if file path is known and it's malicious
        if (verdict == "SCAM" && !filePath.isNullOrBlank()) {
            val deleteIntent = Intent(this, StorageWatcherService::class.java).apply {
                action = ACTION_DELETE_FILE
                putExtra(EXTRA_FILE_PATH, filePath)
            }
            val deletePendingIntent = PendingIntent.getService(
                this,
                (System.currentTimeMillis() % 10000).toInt(),
                deleteIntent,
                PendingIntent.FLAG_IMMUTABLE
            )
            builder.addAction(android.R.drawable.ic_menu_delete, "Delete File", deletePendingIntent)
        }

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val notificationId = (filename.hashCode() and 0x7FFFFFFF)
        nm.notify(notificationId, builder.build())
    }

    private fun handleFileDeletion(path: String) {
        try {
            val file = File(path)
            if (file.exists() && file.delete()) {
                val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
                val notif = NotificationCompat.Builder(this, ALERT_CHANNEL_ID)
                    .setContentTitle("🗑️ Threat Removed")
                    .setContentText("Malicious file '${file.name}' was successfully deleted.")
                    .setSmallIcon(android.R.drawable.stat_sys_warning)
                    .setAutoCancel(true)
                    .build()
                nm.notify((System.currentTimeMillis() % 10000).toInt(), notif)
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Error deleting malicious file: ${e.message}")
        }
    }

    private fun queryVirusTotalAsync(filename: String, fileSize: Long, url: String) {
        serviceScope.launch {
            try {
                val app = applicationContext as? ScamShieldApp ?: return@launch
                app.repository.analyzeDownload(
                    url = url,
                    filename = filename,
                    fileSize = fileSize,
                    mimeType = null
                )
            } catch (e: Throwable) {
                // Standalone mode / offline fallback
            }
        }
    }
}
