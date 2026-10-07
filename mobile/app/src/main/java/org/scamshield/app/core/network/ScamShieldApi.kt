package org.scamshield.app.core.network

import com.google.gson.annotations.SerializedName
import okhttp3.MultipartBody
import retrofit2.Response
import retrofit2.http.*

data class EvidenceItemDto(
    @SerializedName("type") val type: String,
    @SerializedName("severity") val severity: String,
    @SerializedName("source") val source: String,
    @SerializedName("description") val description: String,
    @SerializedName("evidence") val evidence: String,
    @SerializedName("location") val location: String? = null
)

data class VirusTotalDto(
    @SerializedName("source") val source: String? = null,
    @SerializedName("status") val status: String? = null,
    @SerializedName("malicious") val malicious: Int = 0,
    @SerializedName("suspicious") val suspicious: Int = 0,
    @SerializedName("harmless") val harmless: Int = 0,
    @SerializedName("undetected") val undetected: Int = 0,
    @SerializedName("reputation") val reputation: Int = 0,
    @SerializedName("flagging_vendors") val flaggingVendors: List<String> = emptyList(),
    @SerializedName("total_vendors") val totalVendors: Int = 70
)

data class StandardResultDto(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("timestamp") val timestamp: String,
    @SerializedName("input_type") val inputType: String,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("confidence") val confidence: Float,
    @SerializedName("scam_type") val scamType: String,
    @SerializedName("language") val language: String,
    @SerializedName("evidence") val evidence: List<EvidenceItemDto> = emptyList(),
    @SerializedName("explanation") val explanation: String,
    @SerializedName("recommended_actions") val recommendedActions: List<String> = emptyList(),
    @SerializedName("limitations") val limitations: List<String> = emptyList(),
    @SerializedName("multilingual_explanations") val multilingualExplanations: Map<String, String> = emptyMap(),
    @SerializedName("engine_results") val engineResults: Map<String, Any>? = null,
    @SerializedName("virustotal") val virustotal: VirusTotalDto? = null
)

data class TextRequestDto(
    @SerializedName("text") val text: String,
    @SerializedName("language") val language: String = "auto"
)

data class UrlRequestDto(
    @SerializedName("url") val url: String,
    @SerializedName("visible_text") val visibleText: String? = null
)

data class QrRequestDto(
    @SerializedName("qr_content") val qrContent: String
)

data class PhoneRequestDto(
    @SerializedName("phone_number") val phoneNumber: String,
    @SerializedName("context_text") val contextText: String? = null
)

data class DownloadAnalysisRequestDto(
    @SerializedName("url") val url: String,
    @SerializedName("filename") val filename: String,
    @SerializedName("referrer") val referrer: String? = null,
    @SerializedName("file_size") val fileSize: Long? = null,
    @SerializedName("mime_type") val mimeType: String? = null
)

data class DownloadAnalysisResponseDto(
    @SerializedName("scan_id") val scanId: String,
    @SerializedName("filename") val filename: String,
    @SerializedName("url") val url: String? = null,
    @SerializedName("verdict") val verdict: String,
    @SerializedName("risk_score") val riskScore: Int,
    @SerializedName("should_pause") val shouldPause: Boolean = false,
    @SerializedName("is_dangerous_extension") val isDangerousExtension: Boolean = false,
    @SerializedName("is_double_extension") val isDoubleExtension: Boolean = false,
    @SerializedName("scam_category") val scamCategory: String,
    @SerializedName("reasons") val reasons: List<String> = emptyList(),
    @SerializedName("notification_title") val notificationTitle: String = "",
    @SerializedName("notification_message") val notificationMessage: String = "",
    @SerializedName("file_size_formatted") val fileSizeFormatted: String? = null,
    @SerializedName("file_extension") val fileExtension: String? = null,
    @SerializedName("mime_type") val mimeType: String? = null,
    @SerializedName("virustotal") val virustotal: VirusTotalDto? = null,
    @SerializedName("timestamp") val timestamp: String? = null
)

data class RecoveryRequestDto(
    @SerializedName("incident_type") val incidentType: String
)

data class HelplineDto(
    @SerializedName("name") val name: String,
    @SerializedName("contact") val contact: String,
    @SerializedName("web") val web: String? = null
)

data class RecoveryGuideDto(
    @SerializedName("incident_type") val incidentType: String,
    @SerializedName("urgency_level") val urgencyLevel: String,
    @SerializedName("immediate_actions") val immediateActions: List<String> = emptyList(),
    @SerializedName("secondary_actions") val secondaryActions: List<String> = emptyList(),
    @SerializedName("helplines") val helplines: List<HelplineDto> = emptyList(),
    @SerializedName("prevention_tips") val preventionTips: List<String> = emptyList(),
    @SerializedName("disclaimer") val disclaimer: String
)

data class StatisticsDto(
    @SerializedName("total_scans") val totalScans: Int,
    @SerializedName("scam_count") val scamCount: Int,
    @SerializedName("suspicious_count") val suspiciousCount: Int,
    @SerializedName("safe_count") val safeCount: Int,
    @SerializedName("categories") val categories: Map<String, Int> = emptyMap(),
    @SerializedName("languages") val languages: Map<String, Int> = emptyMap()
)

interface ScamShieldApi {
    @POST("api/v1/analyze/text")
    suspend fun analyzeText(@Body request: TextRequestDto): Response<StandardResultDto>

    @POST("api/v1/analyze/url")
    suspend fun analyzeUrl(@Body request: UrlRequestDto): Response<StandardResultDto>

    @POST("api/v1/analyze/qr")
    suspend fun analyzeQr(@Body request: QrRequestDto): Response<StandardResultDto>

    @POST("api/v1/analyze/phone")
    suspend fun analyzePhone(@Body request: PhoneRequestDto): Response<StandardResultDto>

    @Multipart
    @POST("api/v1/analyze/file")
    suspend fun analyzeFile(@Part file: MultipartBody.Part): Response<StandardResultDto>

    @POST("api/v1/analyze/download")
    suspend fun analyzeDownload(@Body request: DownloadAnalysisRequestDto): Response<DownloadAnalysisResponseDto>

    @POST("api/v1/recovery-guide")
    suspend fun getRecoveryGuide(@Body request: RecoveryRequestDto): Response<RecoveryGuideDto>

    @GET("api/v1/statistics")
    suspend fun getStatistics(): Response<StatisticsDto>

    @GET("api/v1/health")
    suspend fun checkHealth(): Response<Map<String, String>>
}
