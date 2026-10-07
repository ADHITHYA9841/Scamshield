package org.scamshield.app.presentation.message

import android.content.Context
import android.net.Uri
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.scamshield.app.core.network.StandardResultDto
import org.scamshield.app.core.standalone.StandaloneEngine
import org.scamshield.app.data.repositories.ScanRepository

data class AnalyzedSmsItem(
    val id: String,
    val sender: String,
    val body: String,
    val date: Long,
    val result: StandardResultDto
)

class MessageViewModel(
    private val repository: ScanRepository
) : ViewModel() {

    var messageInput by mutableStateOf("")
    var isLoading by mutableStateOf(false)
        private set
    var scanResult by mutableStateOf<StandardResultDto?>(null)
        private set
    var errorMessage by mutableStateOf<String?>(null)
        private set

    var isScanningInbox by mutableStateOf(false)
        private set
    var analyzedInbox by mutableStateOf<List<AnalyzedSmsItem>>(emptyList())
        private set
    var inboxThreatCount by mutableStateOf(0)
        private set
    var inboxAuditCompleted by mutableStateOf(false)
        private set

    fun analyzeCurrentMessage() {
        val text = messageInput.trim()
        if (text.isBlank()) {
            errorMessage = "Please enter or paste a message to inspect."
            return
        }

        errorMessage = null
        isLoading = true

        viewModelScope.launch {
            try {
                // Instant on-device local heuristic scan for zero lag
                val localResult = StandaloneEngine.analyzeTextLocally(text)
                scanResult = localResult
                isLoading = false

                // Also persist to local database via repository in background
                withContext(Dispatchers.IO) {
                    try {
                        repository.analyzeText(text)
                    } catch (e: Exception) {
                        // Background persistence fallback
                    }
                }
            } catch (e: Exception) {
                isLoading = false
                errorMessage = "Analysis error: ${e.localizedMessage ?: "Unknown error"}"
            }
        }
    }

    fun loadSampleScam(sampleText: String) {
        messageInput = sampleText
        analyzeCurrentMessage()
    }

    fun clearInput() {
        messageInput = ""
        scanResult = null
        errorMessage = null
    }

    fun scanEntireInbox(context: Context) {
        isScanningInbox = true
        errorMessage = null

        viewModelScope.launch {
            val list = mutableListOf<AnalyzedSmsItem>()
            var threats = 0

            withContext(Dispatchers.IO) {
                try {
                    val uri = Uri.parse("content://sms/inbox")
                    val cursor = context.contentResolver.query(
                        uri,
                        arrayOf("_id", "address", "body", "date"),
                        null,
                        null,
                        "date DESC LIMIT 25"
                    )

                    cursor?.use {
                        val idCol = it.getColumnIndex("_id")
                        val addrCol = it.getColumnIndex("address")
                        val bodyCol = it.getColumnIndex("body")
                        val dateCol = it.getColumnIndex("date")

                        while (it.moveToNext()) {
                            val id = if (idCol != -1) it.getString(idCol) ?: "" else ""
                            val addr = if (addrCol != -1) it.getString(addrCol) ?: "Unknown" else "Unknown"
                            val body = if (bodyCol != -1) it.getString(bodyCol) ?: "" else ""
                            val date = if (dateCol != -1) it.getLong(dateCol) else 0L

                            if (body.isNotBlank()) {
                                val analysis = StandaloneEngine.analyzeTextLocally(body)
                                if (analysis.verdict == "SCAM" || analysis.verdict == "SUSPICIOUS") {
                                    threats++
                                }
                                list.add(AnalyzedSmsItem(id, addr, body, date, analysis))
                            }
                        }
                    }
                } catch (e: SecurityException) {
                    withContext(Dispatchers.Main) {
                        errorMessage = "SMS permission required to scan device inbox."
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        errorMessage = "Unable to read inbox: ${e.localizedMessage}"
                    }
                }
            }

            // Sort so high-risk scams are at the top
            analyzedInbox = list.sortedByDescending { it.result.riskScore }
            inboxThreatCount = threats
            inboxAuditCompleted = true
            isScanningInbox = false
        }
    }
}
