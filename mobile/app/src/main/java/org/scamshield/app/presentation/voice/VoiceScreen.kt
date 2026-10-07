package org.scamshield.app.presentation.voice

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material.icons.filled.Mic
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VoiceScreen(
    onNavigateBack: () -> Unit,
    onAnalyzeTranscript: (String) -> Unit
) {
    var isRecording by remember { mutableStateOf(false) }
    var transcriptText by remember {
        mutableStateOf("Police officer: Your mobile number was used in extortion call. To avoid immediate arrest at your residence, share your bank account verification OTP right now.")
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Voice Scam Analysis", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DarkBackground)
            )
        },
        containerColor = DarkBackground
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(20.dp))

            // Animated Mic Button
            Box(
                modifier = Modifier
                    .size(110.dp)
                    .clip(CircleShape)
                    .background(if (isRecording) ScamRed else AccentBlue),
                contentAlignment = Alignment.Center
            ) {
                IconButton(
                    onClick = { isRecording = !isRecording },
                    modifier = Modifier.size(90.dp)
                ) {
                    Icon(
                        imageVector = if (isRecording) Icons.Default.Stop else Icons.Default.Mic,
                        contentDescription = "Record",
                        tint = TextPrimary,
                        modifier = Modifier.size(44.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            Text(
                text = if (isRecording) "Listening & Transcribing Call..." else "Tap to Record Suspicious Call",
                fontSize = 13.sp,
                color = if (isRecording) ScamRed else TextSecondary,
                fontWeight = FontWeight.SemiBold
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Live Speech-to-Text Transcription Box
            Text(
                text = "SPEECH-TO-TEXT TRANSCRIPT",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = TextMuted,
                modifier = Modifier.align(Alignment.Start)
            )
            Spacer(modifier = Modifier.height(6.dp))

            OutlinedTextField(
                value = transcriptText,
                onValueChange = { transcriptText = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(130.dp),
                colors = OutlinedTextFieldDefaults.colors(focusedTextColor = TextPrimary, unfocusedTextColor = TextPrimary)
            )

            Spacer(modifier = Modifier.height(16.dp))

            Button(
                onClick = { onAnalyzeTranscript(transcriptText) },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp),
                enabled = transcriptText.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue),
                shape = RoundedCornerShape(8.dp)
            ) {
                Text("Analyze Call Transcript for Social Engineering", fontWeight = FontWeight.Bold)
            }
        }
    }
}
