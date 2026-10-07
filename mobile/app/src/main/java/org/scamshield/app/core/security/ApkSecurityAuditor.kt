package org.scamshield.app.core.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.io.File

data class ApkAuditResult(
    val packageName: String,
    val versionName: String,
    val riskScore: Int,
    val isHighRisk: Boolean,
    val dangerousPermissions: List<String>,
    val riskFactors: List<String>
)

object ApkSecurityAuditor {

    fun auditApkFile(context: Context, apkFile: File): ApkAuditResult? {
        if (!apkFile.exists() || !apkFile.name.endsWith(".apk", ignoreCase = true)) return null

        try {
            val pm = context.packageManager
            val flags = PackageManager.GET_PERMISSIONS

            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageArchiveInfo(apkFile.absolutePath, PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageArchiveInfo(apkFile.absolutePath, flags)
            } ?: return null

            val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
            val dangerousList = mutableListOf<String>()
            val riskFactors = mutableListOf<String>()
            var calculatedScore = 10

            // Check for high-risk banking trojan capabilities
            if (requestedPermissions.contains("android.permission.BIND_ACCESSIBILITY_SERVICE")) {
                dangerousList.add("Accessibility Service (Keylogging & Auto-Click)")
                riskFactors.add("Requests Accessibility Service: High risk of automated screen scraping and OTP theft.")
                calculatedScore += 45
            }

            if (requestedPermissions.contains("android.permission.RECEIVE_SMS") || requestedPermissions.contains("android.permission.READ_SMS")) {
                dangerousList.add("SMS Interception (2FA / OTP Reading)")
                riskFactors.add("Requests SMS permissions: Can read bank OTPs and authentication codes.")
                calculatedScore += 30
            }

            if (requestedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")) {
                dangerousList.add("Overlay Window (Fake Phishing Screens)")
                riskFactors.add("Requests Overlay permission: Can display fake login forms over legitimate banking apps.")
                calculatedScore += 25
            }

            if (requestedPermissions.contains("android.permission.REQUEST_INSTALL_PACKAGES")) {
                dangerousList.add("Package Dropper (Sideloads Other Apps)")
                riskFactors.add("Requests Dropper permission: Can silently download and install secondary malware.")
                calculatedScore += 20
            }

            if (requestedPermissions.contains("android.permission.RECORD_AUDIO")) {
                dangerousList.add("Microphone Access (Eavesdropping)")
                calculatedScore += 15
            }

            if (requestedPermissions.contains("android.permission.READ_CONTACTS")) {
                dangerousList.add("Contacts Harvester (Blackmail)")
                calculatedScore += 10
            }

            val finalScore = calculatedScore.coerceIn(0, 100)
            val isHighRisk = finalScore >= 60

            return ApkAuditResult(
                packageName = packageInfo.packageName ?: "unknown.package",
                versionName = packageInfo.versionName ?: "1.0",
                riskScore = finalScore,
                isHighRisk = isHighRisk,
                dangerousPermissions = dangerousList,
                riskFactors = riskFactors
            )
        } catch (e: Exception) {
            return null
        }
    }
}
