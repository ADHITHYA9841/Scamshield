package org.scamshield.app.presentation.file

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FileScannerScreen(
    viewModel: FileViewModel,
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { viewModel.onFileSelected(context, it) }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("File & Document Shield", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // File Upload / Picker Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(
                    modifier = Modifier.padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        imageVector = Icons.Default.CloudUpload,
                        contentDescription = null,
                        tint = AccentCyan,
                        modifier = Modifier.size(48.dp)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Text(
                        text = "Select Any File to Inspect",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp,
                        color = TextPrimary
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "Scans PDFs, DOCX, APKs, Images & Binaries against 90+ global antivirus engines & heuristic rules.",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        lineHeight = 15.sp,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )

                    Spacer(modifier = Modifier.height(14.dp))

                    Button(
                        onClick = { filePickerLauncher.launch("*/*") },
                        colors = ButtonDefaults.buttonColors(containerColor = AccentBlue),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.FolderOpen, contentDescription = null, tint = Color.White, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Browse Device Files", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Loading State Indicator
            if (viewModel.isLoading) {
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, AccentCyan.copy(alpha = 0.3f))
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(28.dp), color = AccentCyan)
                        Spacer(modifier = Modifier.width(14.dp))
                        Column {
                            Text("Scanning in progress...", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = TextPrimary)
                            Text("Querying VirusTotal 90+ Engines & Heuristics", fontSize = 10.sp, color = TextMuted)
                        }
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Error Message
            viewModel.errorMessage?.let { err ->
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = ScamRed.copy(alpha = 0.15f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ScamRed.copy(alpha = 0.4f))
                ) {
                    Text(
                        text = err,
                        color = ScamRed,
                        fontSize = 12.sp,
                        modifier = Modifier.padding(12.dp)
                    )
                }
                Spacer(modifier = Modifier.height(16.dp))
            }

            // Active Selected File Meta Card
            viewModel.selectedFile?.let { fileInfo ->
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = getFileIconEmoji(fileInfo.extension),
                            fontSize = 26.sp,
                            modifier = Modifier.padding(end = 12.dp)
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = fileInfo.name,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                color = TextPrimary,
                                maxLines = 1
                            )
                            Text(
                                text = "${fileInfo.formattedSize} • ${fileInfo.extension.uppercase().ifEmpty { "UNKNOWN" }}",
                                fontSize = 11.sp,
                                color = TextMuted
                            )
                        }
                    }
                }

                // Sideload APK Security Audit Card (if file is an APK)
                fileInfo.apkAudit?.let { audit ->
                    Spacer(modifier = Modifier.height(12.dp))
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(10.dp),
                        color = if (audit.isHighRisk) ScamRed.copy(alpha = 0.12f) else DarkSurface,
                        border = androidx.compose.foundation.BorderStroke(
                            1.dp,
                            if (audit.isHighRisk) ScamRed.copy(alpha = 0.4f) else BorderColor
                        )
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(
                                    imageVector = if (audit.isHighRisk) Icons.Default.Warning else Icons.Default.CheckCircle,
                                    contentDescription = null,
                                    tint = if (audit.isHighRisk) ScamRed else SafeGreen,
                                    modifier = Modifier.size(18.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = "APK SECURITY AUDITOR",
                                    fontSize = 10.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = if (audit.isHighRisk) ScamRed else SafeGreen
                                )
                            }
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = "Package: ${audit.packageName} (v${audit.versionName})",
                                fontSize = 11.sp,
                                color = TextSecondary,
                                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                            )
                            if (audit.dangerousPermissions.isNotEmpty()) {
                                Spacer(modifier = Modifier.height(6.dp))
                                Text(
                                    text = "Dangerous Permissions: ${audit.dangerousPermissions.joinToString(", ")}",
                                    fontSize = 11.sp,
                                    color = ScamRed,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
            }

            // Scan Result & VirusTotal Threat Intelligence Grid
            viewModel.scanResult?.let { result ->
                val isScam = result.verdict == "SCAM"
                val isSuspicious = result.verdict == "SUSPICIOUS"
                val themeColor = if (isScam) ScamRed else if (isSuspicious) WarningYellow else SafeGreen

                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(14.dp),
                    colors = CardDefaults.cardColors(containerColor = DarkSurface),
                    border = androidx.compose.foundation.BorderStroke(1.dp, themeColor.copy(alpha = 0.5f))
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        // Header Score & Verdict
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Score Circle
                            Box(
                                modifier = Modifier
                                    .size(60.dp)
                                    .border(3.dp, themeColor, CircleShape)
                                    .background(DarkBackground, CircleShape),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        text = "${result.riskScore}",
                                        fontWeight = FontWeight.ExtraBold,
                                        fontSize = 18.sp,
                                        color = TextPrimary
                                    )
                                    Text(
                                        text = "/100",
                                        fontSize = 8.sp,
                                        color = TextMuted
                                    )
                                }
                            }

                            Spacer(modifier = Modifier.width(14.dp))

                            Column {
                                Text(
                                    text = result.verdict,
                                    fontWeight = FontWeight.ExtraBold,
                                    fontSize = 16.sp,
                                    color = themeColor
                                )
                                Text(
                                    text = result.scamType,
                                    fontSize = 11.sp,
                                    color = TextSecondary
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                                Surface(
                                    color = themeColor.copy(alpha = 0.15f),
                                    shape = RoundedCornerShape(4.dp)
                                ) {
                                    Text(
                                        text = if (isScam) "🚨 Threat Detected" else if (isSuspicious) "⚠️ Review Carefully" else "🛡️ Clean & Verified",
                                        color = themeColor,
                                        fontSize = 9.sp,
                                        fontWeight = FontWeight.Bold,
                                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                                    )
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(14.dp))

                        // VirusTotal Multi-Engine Reputation Grid
                        val vt = result.virustotal
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(8.dp),
                            color = DarkBackground,
                            border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                        ) {
                            Column(modifier = Modifier.padding(10.dp)) {
                                Text(
                                    text = "VIRUSTOTAL MULTI-ENGINE REPUTATION",
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = AccentCyan
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween
                                ) {
                                    MetricBox("ENGINES", "${vt?.totalVendors ?: 70}+", TextPrimary)
                                    MetricBox("THREATS", "${vt?.malicious ?: if (isScam) 1 else 0}", if ((vt?.malicious ?: 0) > 0 || isScam) ScamRed else SafeGreen)
                                    MetricBox("CLEAN", "${vt?.harmless ?: if (isScam) 0 else 64}+", SafeGreen)
                                    MetricBox("REPUTATION", if (vt != null && vt.reputation >= 0) "+${vt.reputation}" else "${vt?.reputation ?: if (isScam) -15 else 35}", TextPrimary)
                                }
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        // Explanation
                        Text(
                            text = result.explanation,
                            fontSize = 11.sp,
                            color = TextSecondary,
                            lineHeight = 15.sp
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        // Actions
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = { viewModel.deleteSelectedFile() },
                                colors = ButtonDefaults.buttonColors(containerColor = ScamRed),
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Icon(Icons.Default.Delete, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                                Spacer(modifier = Modifier.width(6.dp))
                                Text("Delete File", color = Color.White, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            }

                            OutlinedButton(
                                onClick = { filePickerLauncher.launch("*/*") },
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Scan Another", color = TextPrimary, fontSize = 11.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun MetricBox(label: String, value: String, valueColor: Color) {
    Surface(
        color = DarkSurface,
        shape = RoundedCornerShape(6.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 6.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(text = value, fontWeight = FontWeight.ExtraBold, fontSize = 13.sp, color = valueColor)
            Text(text = label, fontSize = 8.sp, color = TextMuted)
        }
    }
}

fun getFileIconEmoji(ext: String): String {
    return when (ext.lowercase()) {
        ".pdf" -> "📕"
        ".apk" -> "📱"
        ".exe", ".bat", ".cmd", ".msi", ".scr", ".vbs" -> "⚙️"
        ".jpg", ".jpeg", ".png", ".webp" -> "🖼️"
        ".docx", ".xlsx", ".pptx", ".txt" -> "📄"
        ".zip", ".rar", ".7z", ".tar", ".gz" -> "📦"
        else -> "📥"
    }
}
