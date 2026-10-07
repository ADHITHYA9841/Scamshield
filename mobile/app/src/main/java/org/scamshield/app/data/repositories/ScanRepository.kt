package org.scamshield.app.data.repositories

import android.content.Context
import com.google.gson.Gson
import kotlinx.coroutines.flow.Flow
import okhttp3.MultipartBody
import org.scamshield.app.core.database.ScanDao
import org.scamshield.app.core.database.ScanEntity
import org.scamshield.app.core.locale.AppLocaleManager
import org.scamshield.app.core.network.*
import org.scamshield.app.core.standalone.StandaloneEngine

class ScanRepository(
    private val api: ScamShieldApi,
    private val scanDao: ScanDao,
    private val appContext: Context? = null
) {
    private val gson = Gson()

    suspend fun analyzeText(text: String, language: String = preferredLanguage()): Result<StandardResultDto> {
        return try {
            val response = api.analyzeText(TextRequestDto(text, language))
            if (response.isSuccessful && response.body() != null) {
                val result = response.body()!!
                persistResult(result)
                Result.success(result)
            } else {
                val local = StandaloneEngine.analyzeTextLocally(text)
                persistResult(local)
                Result.success(local)
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzeTextLocally(text)
            persistResult(local)
            Result.success(local)
        }
    }

    private fun preferredLanguage(): String {
        return appContext?.let { AppLocaleManager.getLanguageCode(it) } ?: "auto"
    }

    suspend fun analyzeUrl(url: String, visibleText: String? = null): Result<StandardResultDto> {
        return try {
            val response = api.analyzeUrl(UrlRequestDto(url, visibleText))
            if (response.isSuccessful && response.body() != null) {
                val result = response.body()!!
                persistResult(result)
                Result.success(result)
            } else {
                val local = StandaloneEngine.analyzeUrlLocally(url)
                persistResult(local)
                Result.success(local)
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzeUrlLocally(url)
            persistResult(local)
            Result.success(local)
        }
    }

    suspend fun analyzeQr(qrContent: String): Result<StandardResultDto> {
        return try {
            val response = api.analyzeQr(QrRequestDto(qrContent))
            if (response.isSuccessful && response.body() != null) {
                val result = response.body()!!
                persistResult(result)
                Result.success(result)
            } else {
                val local = StandaloneEngine.analyzeQrLocally(qrContent)
                persistResult(local)
                Result.success(local)
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzeQrLocally(qrContent)
            persistResult(local)
            Result.success(local)
        }
    }

    suspend fun analyzePhone(phoneNumber: String, context: String? = null): Result<StandardResultDto> {
        return try {
            val response = api.analyzePhone(PhoneRequestDto(phoneNumber, context))
            if (response.isSuccessful && response.body() != null) {
                val result = response.body()!!
                persistResult(result)
                Result.success(result)
            } else {
                val local = StandaloneEngine.analyzePhoneLocally(phoneNumber, context)
                persistResult(local)
                Result.success(local)
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzePhoneLocally(phoneNumber, context)
            persistResult(local)
            Result.success(local)
        }
    }

    suspend fun analyzeFile(
        filePart: MultipartBody.Part,
        filename: String = "file",
        fileSize: Long = 0L,
        fileInputStream: java.io.InputStream? = null
    ): Result<StandardResultDto> {
        return try {
            val response = api.analyzeFile(filePart)
            if (response.isSuccessful && response.body() != null) {
                val result = response.body()!!
                persistResult(result)
                Result.success(result)
            } else {
                val local = StandaloneEngine.analyzeFileLocally(filename, fileSize, fileInputStream)
                persistResult(local)
                Result.success(local)
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzeFileLocally(filename, fileSize, fileInputStream)
            persistResult(local)
            Result.success(local)
        }
    }

    suspend fun analyzeDownload(
        url: String,
        filename: String,
        fileSize: Long? = null,
        mimeType: String? = null
    ): Result<DownloadAnalysisResponseDto> {
        return try {
            val response = api.analyzeDownload(DownloadAnalysisRequestDto(url, filename, null, fileSize, mimeType))
            if (response.isSuccessful && response.body() != null) {
                Result.success(response.body()!!)
            } else {
                val local = StandaloneEngine.analyzeFileLocally(filename, fileSize ?: 0L)
                val isDbl = filename.lowercase().matches(Regex(".*\\.(pdf|docx|xlsx|jpg|png|txt|zip)\\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$"))
                Result.success(
                    DownloadAnalysisResponseDto(
                        scanId = local.scanId,
                        filename = filename,
                        url = url,
                        verdict = local.verdict,
                        riskScore = local.riskScore,
                        shouldPause = local.verdict == "SCAM",
                        isDangerousExtension = filename.lowercase().endsWith(".apk") || filename.lowercase().endsWith(".exe"),
                        isDoubleExtension = isDbl,
                        scamCategory = local.scamType,
                        reasons = local.evidence.map { it.description },
                        notificationTitle = if (local.verdict == "SCAM") "🚨 Dangerous Download Blocked" else "🛡️ Download Safe",
                        notificationMessage = local.explanation,
                        fileSizeFormatted = null,
                        fileExtension = null,
                        mimeType = mimeType,
                        virustotal = local.virustotal,
                        timestamp = System.currentTimeMillis().toString()
                    )
                )
            }
        } catch (e: Exception) {
            val local = StandaloneEngine.analyzeFileLocally(filename, fileSize ?: 0L)
            val isDbl = filename.lowercase().matches(Regex(".*\\.(pdf|docx|xlsx|jpg|png|txt|zip)\\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$"))
            Result.success(
                DownloadAnalysisResponseDto(
                    scanId = local.scanId,
                    filename = filename,
                    url = url,
                    verdict = local.verdict,
                    riskScore = local.riskScore,
                    shouldPause = local.verdict == "SCAM",
                    isDangerousExtension = filename.lowercase().endsWith(".apk") || filename.lowercase().endsWith(".exe"),
                    isDoubleExtension = isDbl,
                    scamCategory = local.scamType,
                    reasons = local.evidence.map { it.description },
                    notificationTitle = if (local.verdict == "SCAM") "🚨 Dangerous Download Blocked" else "🛡️ Download Safe",
                    notificationMessage = local.explanation,
                    fileSizeFormatted = null,
                    fileExtension = null,
                    mimeType = mimeType,
                    virustotal = local.virustotal,
                    timestamp = System.currentTimeMillis().toString()
                )
            )
        }
    }

    suspend fun getRecoveryGuide(incidentType: String): Result<RecoveryGuideDto> {
        return try {
            val response = api.getRecoveryGuide(RecoveryRequestDto(incidentType))
            if (response.isSuccessful && response.body() != null) {
                Result.success(response.body()!!)
            } else {
                Result.success(getOfflineRecoveryGuide(incidentType))
            }
        } catch (e: Exception) {
            Result.success(getOfflineRecoveryGuide(incidentType))
        }
    }

    private fun getOfflineRecoveryGuide(incidentType: String): RecoveryGuideDto {
        return RecoveryGuideDto(
            incidentType = incidentType,
            urgencyLevel = "HIGH",
            immediateActions = listOf(
                "Freeze compromised bank cards immediately via your banking app or hotline",
                "Change passwords for your email and primary accounts from a secure device"
            ),
            secondaryActions = listOf(
                "Review recent app installs in Settings > Apps and delete suspicious files",
                "File an official fraud complaint on cybercrime.gov.in or call 1930"
            ),
            helplines = listOf(
                HelplineDto("National Cyber Crime Helpline", "1930", "24x7 Government Helpline"),
                HelplineDto("Indian Cybercrime Portal", "1930", "https://cybercrime.gov.in")
            ),
            preventionTips = listOf(
                "Never share OTPs or passwords with anyone over call or chat",
                "Always verify official caller IDs before transferring funds"
            ),
            disclaimer = "ScamShield provides immediate incident containment guidance. Always report financial loss to your bank and local cyber authorities."
        )
    }

    suspend fun getStatistics(): Result<StatisticsDto> {
        return try {
            val response = api.getStatistics()
            if (response.isSuccessful && response.body() != null) {
                Result.success(response.body()!!)
            } else {
                buildLocalStatistics()
            }
        } catch (e: Exception) {
            buildLocalStatistics()
        }
    }

    private suspend fun buildLocalStatistics(): Result<StatisticsDto> {
        val total = scanDao.getTotalCount()
        val scam = scanDao.getScamCount()
        val suspicious = scanDao.getSuspiciousCount()
        val safe = scanDao.getSafeCount()
        val localCategories = scanDao.getCategoryBreakdown()

        val finalCategories = if (localCategories.isNotEmpty()) {
            localCategories
        } else {
            mapOf(
                "KYC & Account Suspension" to 42,
                "UPI Reverse Payment" to 31,
                "Job & Investment Bait" to 19,
                "Delivery Phishing" to 12
            )
        }

        return Result.success(
            StatisticsDto(
                totalScans = total,
                scamCount = scam,
                suspiciousCount = suspicious,
                safeCount = safe,
                categories = finalCategories,
                languages = mapOf("en" to maxOf(1, total))
            )
        )
    }

    // Local Persistence
    private suspend fun persistResult(dto: StandardResultDto) {
        try {
            scanDao.insertScan(
                ScanEntity(
                    scanId = dto.scanId,
                    inputType = dto.inputType,
                    verdict = dto.verdict,
                    riskScore = dto.riskScore,
                    confidence = dto.confidence,
                    scamType = dto.scamType,
                    language = dto.language,
                    explanation = dto.explanation,
                    evidenceJson = gson.toJson(dto.evidence),
                    recommendedActionsJson = gson.toJson(dto.recommendedActions)
                )
            )
        } catch (e: Exception) {
            // Ignore database caching errors
        }
    }

    fun getAllScans(): Flow<List<ScanEntity>> = scanDao.getAllScans()

    fun getLocalHistory(): Flow<List<ScanEntity>> = scanDao.getAllScans()

    fun getScansByVerdict(verdict: String): Flow<List<ScanEntity>> = scanDao.getScansByVerdict(verdict)

    fun getHistoryByVerdict(verdict: String): Flow<List<ScanEntity>> = scanDao.getScansByVerdict(verdict)

    suspend fun deleteScan(scan: ScanEntity) {
        scanDao.deleteScan(scan)
    }

    suspend fun clearHistory() {
        scanDao.clearAllScans()
    }
}
