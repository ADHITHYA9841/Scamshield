package org.scamshield.app.core.database

data class ScanEntity(
    val scanId: String,
    val timestamp: Long = System.currentTimeMillis(),
    val inputType: String,
    val verdict: String,
    val riskScore: Int,
    val confidence: Float,
    val scamType: String,
    val language: String,
    val explanation: String,
    val evidenceJson: String,
    val recommendedActionsJson: String
)

fun ScanEntity.toStandardResultDto(): org.scamshield.app.core.network.StandardResultDto {
    val gson = com.google.gson.Gson()
    val evidenceList: List<org.scamshield.app.core.network.EvidenceItemDto> = try {
        val type = object : com.google.gson.reflect.TypeToken<List<org.scamshield.app.core.network.EvidenceItemDto>>() {}.type
        gson.fromJson(evidenceJson, type) ?: emptyList()
    } catch (e: Exception) {
        emptyList()
    }
    val actionsList: List<String> = try {
        val type = object : com.google.gson.reflect.TypeToken<List<String>>() {}.type
        gson.fromJson(recommendedActionsJson, type) ?: emptyList()
    } catch (e: Exception) {
        emptyList()
    }
    return org.scamshield.app.core.network.StandardResultDto(
        scanId = scanId,
        timestamp = timestamp.toString(),
        inputType = inputType,
        verdict = verdict,
        riskScore = riskScore,
        confidence = confidence,
        scamType = scamType,
        language = language,
        evidence = evidenceList,
        explanation = explanation,
        recommendedActions = actionsList
    )
}
