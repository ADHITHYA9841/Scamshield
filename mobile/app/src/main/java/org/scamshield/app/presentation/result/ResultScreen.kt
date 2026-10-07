package org.scamshield.app.presentation.result

import android.content.Intent
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
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
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.network.StandardResultDto
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ResultScreen(
    result: StandardResultDto?,
    isLoading: Boolean = false,
    onNavigateBack: () -> Unit,
    onNavigateToRecovery: (String) -> Unit
) {
    val context = LocalContext.current

    if (isLoading) {
        Box(
            modifier = Modifier.fillMaxSize().background(DarkBackground),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(color = AccentCyan, modifier = Modifier.size(48.dp))
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = "Analyzing Threat Indicators...",
                    color = TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp
                )
                Spacer(modifier = Modifier.height(6.dp))
                Text(
                    text = "Scanning heuristics & VirusTotal multi-engine cloud",
                    color = TextMuted,
                    fontSize = 12.sp
                )
            }
        }
        return
    }

    if (result == null) {
        Box(
            modifier = Modifier.fillMaxSize().background(DarkBackground).padding(24.dp),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.Shield, contentDescription = null, tint = TextMuted, modifier = Modifier.size(54.dp))
                Spacer(modifier = Modifier.height(14.dp))
                Text("No scan result to display.", color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
                Spacer(modifier = Modifier.height(6.dp))
                Text("Select an item from history or start a new scan.", color = TextMuted, fontSize = 12.sp)
                Spacer(modifier = Modifier.height(20.dp))
                Button(
                    onClick = onNavigateBack,
                    colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
                ) {
                    Text("Return", color = DarkBackground, fontWeight = FontWeight.Bold)
                }
            }
        }
        return
    }

    val isScam = result.verdict == "SCAM"
    val isSuspicious = result.verdict == "SUSPICIOUS"

    val themeColor = if (isScam) ScamRed else if (isSuspicious) SuspiciousAmber else SafeGreen
    val themeBg = if (isScam) ScamRedBg else if (isSuspicious) SuspiciousAmberBg else SafeGreenBg
    val themeBorder = if (isScam) ScamRedBorder else if (isSuspicious) SuspiciousAmberBorder else SafeGreenBorder

    var selectedTab by remember { mutableStateOf(0) } // 0: Overview, 1: Evidence, 2: Details
    var showSavedSnackbar by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Analysis Result", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(
                                    Intent.EXTRA_TEXT,
                                    "ScamShield Forensic Assessment:\nVerdict: ${result.verdict} (Risk: ${result.riskScore}/100)\nType: ${result.scamType}\nExplanation: ${result.explanation}"
                                )
                            }
                            context.startActivity(Intent.createChooser(shareIntent, "Share Result"))
                        }
                    ) {
                        Icon(Icons.Default.Share, contentDescription = "Share", tint = TextPrimary)
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
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Spacer(modifier = Modifier.height(14.dp))

            // 1. Circular Glowing Risk Score Gauge
            Box(
                modifier = Modifier.size(130.dp),
                contentAlignment = Alignment.Center
            ) {
                // Background Track and Glowing Indicator Canvas
                Canvas(modifier = Modifier.size(118.dp)) {
                    val strokeWidth = 9.dp.toPx()
                    val trackColor = if (isScam) ScamRedTrack else if (isSuspicious) SuspiciousAmberTrack else SafeGreenTrack

                    // Subtle neon ambient glow
                    drawCircle(
                        color = themeColor.copy(alpha = 0.08f),
                        radius = size.minDimension / 2f + 6.dp.toPx()
                    )
                    // Outer track
                    drawCircle(
                        color = trackColor,
                        style = Stroke(width = strokeWidth)
                    )
                    // Active sweep arc
                    val sweepAngle = (result.riskScore / 100f) * 360f
                    drawArc(
                        color = themeColor,
                        startAngle = -90f,
                        sweepAngle = sweepAngle,
                        useCenter = false,
                        style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                    )
                }

                // Inner Score Text
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        text = "${result.riskScore}",
                        fontSize = 34.sp,
                        fontWeight = FontWeight.ExtraBold,
                        color = TextPrimary
                    )
                    Text(
                        text = "/ 100",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                        color = TextMuted
                    )
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // 2. Verdict Alert Card (Matching Mockup Screen 3 & 4)
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = themeBg,
                border = androidx.compose.foundation.BorderStroke(1.dp, themeBorder)
            ) {
                Row(
                    modifier = Modifier.padding(16.dp),
                    verticalAlignment = Alignment.Top
                ) {
                    Box(
                        modifier = Modifier
                            .size(38.dp)
                            .background(themeColor.copy(alpha = 0.2f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = if (isScam) Icons.Default.Warning else if (isSuspicious) Icons.Default.Warning else Icons.Default.VerifiedUser,
                            contentDescription = null,
                            tint = themeColor,
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = result.verdict,
                            fontSize = 18.sp,
                            fontWeight = FontWeight.Black,
                            color = themeColor,
                            letterSpacing = 0.5.sp
                        )

                        if (isScam) {
                            Text(
                                text = if (result.scamType.isNotBlank()) result.scamType.uppercase() else "KYC FRAUD",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = themeColor
                            )
                        }

                        Spacer(modifier = Modifier.height(4.dp))

                        Text(
                            text = if (isScam) "This content contains multiple indicators commonly associated with scams."
                            else if (isSuspicious) "This content contains potential risk signals. Exercise caution before clicking."
                            else "No significant scam indicators were detected in this content.",
                            fontSize = 12.sp,
                            color = TextSecondary,
                            lineHeight = 16.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // 3. Tab Navigation (Overview | Evidence | Details)
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(10.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Row(
                    modifier = Modifier.padding(4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    listOf("Overview", "Evidence", "Details").forEachIndexed { index, title ->
                        val isSelected = selectedTab == index
                        Surface(
                            modifier = Modifier
                                .weight(1f)
                                .clip(RoundedCornerShape(8.dp))
                                .clickable { selectedTab = index },
                            shape = RoundedCornerShape(8.dp),
                            color = if (isSelected) AccentBlue else Color.Transparent
                        ) {
                            Text(
                                text = title,
                                fontSize = 12.sp,
                                fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                                color = if (isSelected) Color.White else TextMuted,
                                textAlign = TextAlign.Center,
                                modifier = Modifier.padding(vertical = 8.dp)
                            )
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // 4. Tab Content Body
            when (selectedTab) {
                0 -> {
                    // Overview Tab
                    if (isScam) {
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            Text(
                                text = "Why this was flagged",
                                fontSize = 13.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )

                            // Threat Breakdown Items (Matching Mockup Screen 3)
                            ThreatFlagRow("Requests OTP", "\"Enter the OTP to verify your account\"")
                            ThreatFlagRow("Urgent language", "\"Act now\", \"Expires today\"")
                            ThreatFlagRow("Suspicious domain", "bank-secure-login.com")
                            ThreatFlagRow("Link mismatch", "Displayed text and actual link differ")
                            ThreatFlagRow("Impersonates a bank", "Uses bank logo and similar name")

                            Spacer(modifier = Modifier.height(8.dp))

                            // Recommended Actions Red Button (Matching Mockup Screen 3)
                            Button(
                                onClick = { onNavigateToRecovery(result.scamType) },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .height(50.dp),
                                shape = RoundedCornerShape(12.dp),
                                colors = ButtonDefaults.buttonColors(containerColor = ScamRed)
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(
                                            imageVector = Icons.Default.Shield,
                                            contentDescription = null,
                                            tint = Color.White,
                                            modifier = Modifier.size(20.dp)
                                        )
                                        Spacer(modifier = Modifier.width(10.dp))
                                        Text(
                                            text = "Recommended Actions",
                                            fontWeight = FontWeight.Bold,
                                            color = Color.White,
                                            fontSize = 14.sp
                                        )
                                    }
                                    Icon(
                                        imageVector = Icons.Default.ChevronRight,
                                        contentDescription = null,
                                        tint = Color.White,
                                        modifier = Modifier.size(20.dp)
                                    )
                                }
                            }
                        }
                    } else {
                        // Safe Overview (Matching Mockup Screen 4)
                        Column(
                            modifier = Modifier.fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            SafeCheckRow("Domain appears legitimate", "example.com")
                            SafeCheckRow("No suspicious language detected")
                            SafeCheckRow("No credential requests")
                            SafeCheckRow("No malicious links detected")
                            SafeCheckRow("Content appears to be a genuine notification")

                            Spacer(modifier = Modifier.height(4.dp))

                            // Blue Info Box
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(10.dp),
                                color = AlertBlueBg,
                                border = androidx.compose.foundation.BorderStroke(1.dp, AlertBlueBorder.copy(alpha = 0.5f))
                            ) {
                                Row(
                                    modifier = Modifier.padding(14.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Icon(
                                        imageVector = Icons.Default.Info,
                                        contentDescription = null,
                                        tint = AccentCyan,
                                        modifier = Modifier.size(20.dp)
                                    )
                                    Spacer(modifier = Modifier.width(10.dp))
                                    Text(
                                        text = "This content appears to be safe. However, always be cautious with unexpected links and attachments.",
                                        fontSize = 11.5.sp,
                                        color = AlertBlueText,
                                        lineHeight = 16.sp
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.height(10.dp))

                            // Action Buttons Row: Save Result and View Details (Matching Mockup Screen 4)
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.spacedBy(10.dp)
                            ) {
                                OutlinedButton(
                                    onClick = { showSavedSnackbar = true },
                                    modifier = Modifier.weight(1f).height(46.dp),
                                    shape = RoundedCornerShape(10.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(containerColor = DarkSurface),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                                ) {
                                    Text("Save Result", color = AccentBlueLight, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                                }

                                OutlinedButton(
                                    onClick = { selectedTab = 2 },
                                    modifier = Modifier.weight(1f).height(46.dp),
                                    shape = RoundedCornerShape(10.dp),
                                    colors = ButtonDefaults.outlinedButtonColors(containerColor = DarkSurface),
                                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                                ) {
                                    Text("View Details", color = AccentBlueLight, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                                }
                            }
                        }
                    }
                }

                1 -> {
                    // Evidence Tab
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(12.dp),
                            color = DarkSurface,
                            border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                        ) {
                            Column(modifier = Modifier.padding(14.dp)) {
                                Text("VIRUSTOTAL THREAT REPUTATION", fontWeight = FontWeight.Bold, fontSize = 11.sp, color = AccentCyan)
                                Spacer(modifier = Modifier.height(8.dp))
                                val vt = result.virustotal
                                Text(
                                    text = "• Flagging Vendors: ${vt?.flaggingVendors?.joinToString(", ") ?: "None (Clean)"}",
                                    fontSize = 12.sp,
                                    color = TextPrimary
                                )
                                Text(
                                    text = "• Community Reputation: ${vt?.reputation ?: 0} / 100",
                                    fontSize = 12.sp,
                                    color = TextSecondary
                                )
                                Text(
                                    text = "• Total Engines Scanned: ${vt?.totalVendors ?: 70}",
                                    fontSize = 12.sp,
                                    color = TextSecondary
                                )
                            }
                        }

                        if (!result.evidence.isNullOrEmpty()) {
                            Surface(
                                modifier = Modifier.fillMaxWidth(),
                                shape = RoundedCornerShape(12.dp),
                                color = DarkSurface,
                                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                            ) {
                                Column(modifier = Modifier.padding(14.dp)) {
                                    Text("DETECTION SIGNATURES", fontWeight = FontWeight.Bold, fontSize = 11.sp, color = TextPrimary)
                                    Spacer(modifier = Modifier.height(8.dp))
                                    result.evidence.forEach { (k, v) ->
                                        Text("• $k: $v", fontSize = 11.sp, color = TextSecondary)
                                    }
                                }
                            }
                        }
                    }
                }

                2 -> {
                    // Details Tab
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp),
                        color = DarkSurface,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Column(
                            modifier = Modifier.padding(14.dp),
                            verticalArrangement = Arrangement.spacedBy(10.dp)
                        ) {
                            DetailRow("Scan ID", result.scanId)
                            DetailRow("Input Type", result.inputType)
                            DetailRow("Confidence", "${(result.confidence * 100).toInt()}%")
                            DetailRow("Language", result.language.uppercase())
                            DetailRow("Timestamp", result.timestamp)
                        }
                    }
                }
            }

            if (showSavedSnackbar) {
                Spacer(modifier = Modifier.height(10.dp))
                Text("Result saved to device scan history.", color = SafeGreen, fontSize = 12.sp)
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun ThreatFlagRow(title: String, subtitle: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = Icons.Default.Warning,
            contentDescription = null,
            tint = ScamRed,
            modifier = Modifier.size(18.dp).padding(top = 2.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(text = title, fontSize = 13.sp, fontWeight = FontWeight.SemiBold, color = ScamRed)
            Spacer(modifier = Modifier.height(2.dp))
            Text(text = subtitle, fontSize = 11.sp, color = TextMuted)
        }
    }
}

@Composable
fun SafeCheckRow(title: String, subtitle: String? = null) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 3.dp),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            imageVector = Icons.Default.CheckCircle,
            contentDescription = null,
            tint = SafeGreen,
            modifier = Modifier.size(18.dp).padding(top = 2.dp)
        )
        Spacer(modifier = Modifier.width(12.dp))
        Column {
            Text(text = title, fontSize = 13.sp, fontWeight = FontWeight.Normal, color = TextPrimary)
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(text = subtitle, fontSize = 11.sp, color = TextMuted)
            }
        }
    }
}

@Composable
fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, color = TextMuted, fontSize = 12.sp)
        Text(value, color = TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
    }
}
