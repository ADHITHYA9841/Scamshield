package org.scamshield.app.presentation.message

import android.Manifest
import android.content.ClipboardManager
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MessageScannerScreen(
    viewModel: MessageViewModel,
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    var hasSmsPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.READ_SMS) == PackageManager.PERMISSION_GRANTED
        )
    }

    val smsPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { perms ->
        val granted = perms[Manifest.permission.READ_SMS] == true
        hasSmsPermission = granted
        if (granted) {
            viewModel.scanEntireInbox(context)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "Scam & SMS Shield",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp
                        )
                        Text(
                            text = "Autonomous Message Threat Intelligence",
                            color = AccentCyan,
                            fontSize = 11.sp,
                            letterSpacing = 0.5.sp
                        )
                    }
                },
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
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(12.dp))

            // 1. Text & Message Inspection Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Default.Shield,
                                contentDescription = null,
                                tint = AccentCyan,
                                modifier = Modifier.size(16.dp)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                            Text(
                                "INSPECT MESSAGE OR SMS",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                letterSpacing = 0.5.sp
                            )
                        }

                        Row {
                            TextButton(
                                onClick = {
                                    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = cm.primaryClip?.getItemAt(0)?.text?.toString()
                                    if (!clip.isNullOrBlank()) {
                                        viewModel.messageInput = clip
                                    }
                                },
                                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                            ) {
                                Icon(Icons.Default.ContentPaste, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(14.dp))
                                Spacer(modifier = Modifier.width(4.dp))
                                Text("Paste", fontSize = 11.sp, color = AccentCyan)
                            }

                            if (viewModel.messageInput.isNotEmpty()) {
                                TextButton(
                                    onClick = { viewModel.clearInput() },
                                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 2.dp)
                                ) {
                                    Text("Clear", fontSize = 11.sp, color = TextMuted)
                                }
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    OutlinedTextField(
                        value = viewModel.messageInput,
                        onValueChange = { viewModel.messageInput = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(115.dp),
                        placeholder = {
                            Text(
                                "Paste suspicious SMS, KYC notice, WhatsApp forward, or OTP verification lure...",
                                fontSize = 12.sp,
                                color = TextMuted,
                                lineHeight = 16.sp
                            )
                        },
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = AccentBlue,
                            unfocusedBorderColor = BorderColor,
                            focusedTextColor = TextPrimary,
                            unfocusedTextColor = TextPrimary,
                            cursorColor = AccentCyan
                        ),
                        shape = RoundedCornerShape(8.dp)
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = { viewModel.analyzeCurrentMessage() },
                        colors = ButtonDefaults.buttonColors(containerColor = AccentBlue),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !viewModel.isLoading && viewModel.messageInput.isNotBlank()
                    ) {
                        if (viewModel.isLoading) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), color = TextPrimary, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Analyzing Heuristics...", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        } else {
                            Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Analyze Threat", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                    }

                    // Error Message
                    viewModel.errorMessage?.let { err ->
                        Spacer(modifier = Modifier.height(10.dp))
                        Surface(
                            color = ScamRed.copy(alpha = 0.15f),
                            shape = RoundedCornerShape(6.dp),
                            border = androidx.compose.foundation.BorderStroke(1.dp, ScamRed.copy(alpha = 0.4f)),
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(
                                text = err,
                                color = ScamRed,
                                fontSize = 11.sp,
                                modifier = Modifier.padding(10.dp)
                            )
                        }
                    }
                }
            }

            // 2. Instant Analysis Result Card
            viewModel.scanResult?.let { res ->
                Spacer(modifier = Modifier.height(14.dp))

                val isScam = res.verdict == "SCAM"
                val isSuspicious = res.verdict == "SUSPICIOUS"
                val themeColor = if (isScam) ScamRed else if (isSuspicious) SuspiciousAmber else SafeGreen

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, themeColor.copy(alpha = 0.6f))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(
                                    modifier = Modifier
                                        .size(44.dp)
                                        .background(themeColor.copy(alpha = 0.15f), CircleShape)
                                        .border(2.dp, themeColor, CircleShape),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Text(
                                        "${res.riskScore}",
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 15.sp,
                                        color = TextPrimary
                                    )
                                }

                                Spacer(modifier = Modifier.width(12.dp))

                                Column {
                                    Text(
                                        text = if (isScam) "THREAT DETECTED" else if (isSuspicious) "SUSPICIOUS CONTENT" else "CLEAN MESSAGE",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 14.sp,
                                        color = themeColor
                                    )
                                    Text(
                                        text = res.scamType,
                                        fontSize = 11.sp,
                                        color = TextSecondary
                                    )
                                }
                            }

                            Surface(
                                color = themeColor.copy(alpha = 0.2f),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = res.verdict,
                                    color = themeColor,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))
                        Text(
                            text = res.explanation,
                            fontSize = 12.sp,
                            color = TextPrimary,
                            lineHeight = 16.sp
                        )

                        if (res.evidence.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(10.dp))
                            Text(
                                text = "DETECTED FORENSIC INDICATORS",
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextMuted,
                                letterSpacing = 1.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            res.evidence.forEach { ev ->
                                Surface(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 2.dp),
                                    shape = RoundedCornerShape(6.dp),
                                    color = DarkSurfaceVariant
                                ) {
                                    Text(
                                        text = "• ${ev.description}",
                                        fontSize = 11.sp,
                                        color = if (ev.severity == "critical") ScamRed else TextSecondary,
                                        modifier = Modifier.padding(8.dp)
                                    )
                                }
                            }
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 3. Quick Test Fraud Scenarios
            Text(
                text = "TEST SIMULATED ATTACKS",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = TextMuted,
                letterSpacing = 1.sp
            )
            Spacer(modifier = Modifier.height(8.dp))

            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    AttackChip("Digital Arrest (CBI)") {
                        viewModel.loadSampleScam("CBI Notice: A courier parcel sent under your Aadhaar number was intercepted containing illegal narcotics. You are under digital arrest. Connect to Skype video interrogation immediately to avoid non-bailable warrant.")
                    }
                }
                item {
                    AttackChip("Electricity Disconnection") {
                        viewModel.loadSampleScam("Dear Customer, Your electricity connection will be disconnected tonight at 9.30 PM due to pending bill. Update your bill immediately: https://tneb-billpay.xyz/pay or call 9876543210.")
                    }
                }
                item {
                    AttackChip("SBI YONO KYC Blocked") {
                        viewModel.loadSampleScam("Dear SBI User, your YONO banking account has been suspended today due to pending PAN KYC. Update immediately to prevent permanent account deactivation: http://sbi-kyc-verify.com/login")
                    }
                }
                item {
                    AttackChip("Part-Time Job Trap") {
                        viewModel.loadSampleScam("Earn Rs 3000 to Rs 8000 daily from home just by liking YouTube videos and Telegram crypto rating tasks. Guaranteed daily withdrawal. Contact HR on WhatsApp: +923001234567")
                    }
                }
                item {
                    AttackChip("India Post Parcel Customs") {
                        viewModel.loadSampleScam("India Post: Your package cannot be delivered due to an incomplete address. Pay ₹25 customs re-delivery fee at http://indiapost-parcel.top to release your parcel.")
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // 4. Batch SMS Inbox Threat Auditor Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.AllInbox, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(18.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                "DEVICE SMS INBOX AUDITOR",
                                fontSize = 11.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary,
                                letterSpacing = 0.5.sp
                            )
                        }

                        if (viewModel.inboxAuditCompleted) {
                            Surface(
                                color = if (viewModel.inboxThreatCount > 0) ScamRed.copy(alpha = 0.2f) else SafeGreen.copy(alpha = 0.2f),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = if (viewModel.inboxThreatCount > 0) "${viewModel.inboxThreatCount} THREATS FOUND" else "CLEAN INBOX",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (viewModel.inboxThreatCount > 0) ScamRed else SafeGreen,
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Scan all recent incoming SMS messages stored on your device and instantly detect phishing, banking fraud, and extortion traps.",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        lineHeight = 15.sp
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    Button(
                        onClick = {
                            if (!hasSmsPermission) {
                                smsPermissionLauncher.launch(
                                    arrayOf(Manifest.permission.READ_SMS, Manifest.permission.RECEIVE_SMS)
                                )
                            } else {
                                viewModel.scanEntireInbox(context)
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = DarkSurfaceVariant),
                        border = androidx.compose.foundation.BorderStroke(1.dp, AccentCyan.copy(alpha = 0.5f)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !viewModel.isScanningInbox
                    ) {
                        if (viewModel.isScanningInbox) {
                            CircularProgressIndicator(modifier = Modifier.size(16.dp), color = AccentCyan, strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(8.dp))
                            Text("Auditing Messages...", fontSize = 12.sp, color = TextPrimary)
                        } else {
                            Icon(Icons.Default.Security, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(
                                if (!hasSmsPermission) "Grant Permission & Scan Inbox" else "Scan SMS Inbox Now",
                                fontSize = 12.sp,
                                color = TextPrimary,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }

                    // List of Analyzed SMS Messages
                    if (viewModel.analyzedInbox.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(14.dp))
                        Text(
                            text = "AUDITED INBOX MESSAGES (${viewModel.analyzedInbox.size})",
                            fontSize = 9.sp,
                            fontWeight = FontWeight.Bold,
                            color = TextMuted,
                            letterSpacing = 1.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))

                        viewModel.analyzedInbox.forEach { sms ->
                            val isMsgScam = sms.result.verdict == "SCAM"
                            val isMsgSuspicious = sms.result.verdict == "SUSPICIOUS"
                            val cardColor = if (isMsgScam) ScamRed else if (isMsgSuspicious) SuspiciousAmber else SafeGreen

                            Surface(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp)
                                    .clip(RoundedCornerShape(8.dp))
                                    .clickable {
                                        viewModel.messageInput = sms.body
                                        viewModel.analyzeCurrentMessage()
                                    },
                                shape = RoundedCornerShape(8.dp),
                                color = DarkBackground,
                                border = androidx.compose.foundation.BorderStroke(1.dp, cardColor.copy(alpha = 0.4f))
                            ) {
                                Column(modifier = Modifier.padding(10.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = sms.sender,
                                            fontWeight = FontWeight.Bold,
                                            fontSize = 12.sp,
                                            color = TextPrimary
                                        )
                                        Surface(
                                            color = cardColor.copy(alpha = 0.2f),
                                            shape = RoundedCornerShape(4.dp)
                                        ) {
                                            Text(
                                                text = if (isMsgScam) "SCAM" else if (isMsgSuspicious) "SUSPICIOUS" else "SAFE",
                                                color = cardColor,
                                                fontSize = 8.sp,
                                                fontWeight = FontWeight.Bold,
                                                modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp)
                                            )
                                        }
                                    }
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = sms.body,
                                        fontSize = 10.sp,
                                        color = TextSecondary,
                                        maxLines = 2
                                    )
                                    Spacer(modifier = Modifier.height(4.dp))
                                    Text(
                                        text = "Tap to inspect full forensic breakdown",
                                        fontSize = 9.sp,
                                        color = AccentCyan
                                    )
                                }
                            }
                        }
                    } else if (viewModel.inboxAuditCompleted && viewModel.analyzedInbox.isEmpty()) {
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = "No messages found in device inbox.",
                            fontSize = 11.sp,
                            color = TextMuted
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun AttackChip(label: String, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = DarkSurface,
        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor),
        modifier = Modifier.clickable { onClick() }
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            fontWeight = FontWeight.Medium,
            color = TextPrimary,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
        )
    }
}
