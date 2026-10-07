package org.scamshield.app.presentation.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
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
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import org.scamshield.app.core.theme.*
import java.net.URLDecoder
import java.util.concurrent.Executors

data class QrPayloadAnalysis(
    val rawText: String,
    val isUpi: Boolean = false,
    val isUpiDrainScam: Boolean = false,
    val upiAmount: String? = null,
    val upiPayee: String? = null,
    val isEncryptedScript: Boolean = false,
    val scriptType: String? = null,
    val decodedPayload: String? = null,
    val riskScore: Int = 0,
    val warningMessage: String = ""
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun QrScannerScreen(
    onNavigateBack: () -> Unit,
    onAnalyzeQr: (String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPermission = granted
    }

    var scannedAnalysis by remember { mutableStateOf<QrPayloadAnalysis?>(null) }
    var isAnalyzingImage by remember { mutableStateOf(false) }

    // Gallery Picker for QR Code screenshots
    val galleryLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            isAnalyzingImage = true
            try {
                val inputStream = context.contentResolver.openInputStream(it)
                val bitmap = BitmapFactory.decodeStream(inputStream)
                inputStream?.close()
                if (bitmap != null) {
                    val image = InputImage.fromBitmap(bitmap, 0)
                    val scanner = BarcodeScanning.getClient()
                    scanner.process(image)
                        .addOnSuccessListener { barcodes ->
                            isAnalyzingImage = false
                            if (barcodes.isNotEmpty()) {
                                val raw = barcodes[0].rawValue ?: ""
                                scannedAnalysis = inspectQrPayload(raw)
                            }
                        }
                        .addOnFailureListener {
                            isAnalyzingImage = false
                        }
                } else {
                    isAnalyzingImage = false
                }
            } catch (e: Exception) {
                isAnalyzingImage = false
            }
        }
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission) {
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("QR Code & Script Inspector", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                actions = {
                    IconButton(onClick = { galleryLauncher.launch("image/*") }) {
                        Icon(Icons.Default.PhotoLibrary, contentDescription = "Pick QR Image", tint = AccentCyan)
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
            // Live Camera Viewfinder Box
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .height(280.dp)
                    .border(2.dp, AccentCyan, RoundedCornerShape(16.dp))
                    .background(DarkSurface),
                contentAlignment = Alignment.Center
            ) {
                if (hasCameraPermission) {
                    AndroidView(
                        factory = { ctx ->
                            val previewView = PreviewView(ctx)
                            val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
                            val executor = Executors.newSingleThreadExecutor()

                            cameraProviderFuture.addListener({
                                val cameraProvider = cameraProviderFuture.get()
                                val preview = Preview.Builder().build().also {
                                    it.setSurfaceProvider(previewView.surfaceProvider)
                                }

                                val imageAnalysis = ImageAnalysis.Builder()
                                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                                    .build()

                                val scanner = BarcodeScanning.getClient()

                                imageAnalysis.setAnalyzer(executor) { imageProxy ->
                                    @androidx.camera.core.ExperimentalGetImage
                                    val mediaImage = imageProxy.image
                                    if (mediaImage != null) {
                                        val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
                                        scanner.process(image)
                                            .addOnSuccessListener { barcodes ->
                                                if (barcodes.isNotEmpty() && scannedAnalysis == null) {
                                                    val raw = barcodes[0].rawValue ?: ""
                                                    scannedAnalysis = inspectQrPayload(raw)
                                                }
                                            }
                                            .addOnCompleteListener {
                                                imageProxy.close()
                                            }
                                    } else {
                                        imageProxy.close()
                                    }
                                }

                                try {
                                    cameraProvider.unbindAll()
                                    cameraProvider.bindToLifecycle(
                                        lifecycleOwner,
                                        CameraSelector.DEFAULT_BACK_CAMERA,
                                        preview,
                                        imageAnalysis
                                    )
                                } catch (exc: Exception) {
                                    // Camera bind error
                                }
                            }, ContextCompat.getMainExecutor(ctx))

                            previewView
                        },
                        modifier = Modifier.fillMaxSize()
                    )
                } else {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.CameraAlt, contentDescription = null, tint = TextMuted, modifier = Modifier.size(48.dp))
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Camera Permission Required", color = TextSecondary, fontSize = 13.sp)
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                            colors = ButtonDefaults.buttonColors(containerColor = AccentBlue)
                        ) {
                            Text("Grant Permission", color = androidx.compose.ui.graphics.Color.White, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Quick Gallery Import Button
            OutlinedButton(
                onClick = { galleryLauncher.launch("image/*") },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary),
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Icon(Icons.Default.Image, contentDescription = null, tint = AccentBlueLight, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scan QR from Gallery Screenshot", fontSize = 13.sp, color = TextPrimary)
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Decoded QR Payload & Forensic Assessment Card
            scannedAnalysis?.let { analysis ->
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = DarkSurface),
                    border = androidx.compose.foundation.BorderStroke(
                        1.dp,
                        if (analysis.riskScore >= 70) ScamRed else if (analysis.riskScore >= 30) WarningYellow else SafeGreen
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = if (analysis.isUpiDrainScam) "🚨 UPI PAYMENT TRAP"
                                else if (analysis.isEncryptedScript) "🚨 ENCRYPTED SCRIPT PAYLOAD"
                                else if (analysis.riskScore == 0) "🛡️ VERIFIED CLEAN QR"
                                else "⚠️ SUSPICIOUS QR CODE",
                                fontWeight = FontWeight.ExtraBold,
                                fontSize = 14.sp,
                                color = if (analysis.riskScore >= 70) ScamRed else if (analysis.riskScore >= 30) WarningYellow else SafeGreen
                            )
                            Text(
                                text = "${analysis.riskScore}/100",
                                fontWeight = FontWeight.Bold,
                                fontSize = 14.sp,
                                color = if (analysis.riskScore >= 70) ScamRed else if (analysis.riskScore >= 30) WarningYellow else SafeGreen
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        Text(
                            text = analysis.warningMessage,
                            fontSize = 12.sp,
                            color = TextPrimary,
                            lineHeight = 16.sp
                        )

                        if (analysis.decodedPayload != null) {
                            Spacer(modifier = Modifier.height(8.dp))
                            Text("DECODED PAYLOAD:", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = AccentCyan)
                            Surface(
                                color = DarkBackground,
                                shape = RoundedCornerShape(6.dp),
                                modifier = Modifier.fillMaxWidth()
                            ) {
                                Text(
                                    text = analysis.decodedPayload,
                                    fontSize = 11.sp,
                                    color = TextSecondary,
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                    modifier = Modifier.padding(8.dp)
                                )
                            }
                        }

                        Spacer(modifier = Modifier.height(12.dp))

                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onAnalyzeQr(analysis.rawText) },
                                colors = ButtonDefaults.buttonColors(containerColor = AccentBlue),
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Deep Scan Payload", color = androidx.compose.ui.graphics.Color.White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                            }

                            OutlinedButton(
                                onClick = { scannedAnalysis = null },
                                modifier = Modifier.weight(1f)
                            ) {
                                Text("Scan Next", color = TextPrimary, fontSize = 12.sp)
                            }
                        }
                    }
                }
            } ?: run {
                // Informational Warning Banner
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = ScamRed.copy(alpha = 0.12f),
                    border = androidx.compose.foundation.BorderStroke(1.dp, ScamRed.copy(alpha = 0.3f))
                ) {
                    Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = ScamRed, modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(10.dp))
                        Text(
                            text = "CRITICAL RULE: You NEVER scan a QR code to receive money! Scanning a QR code authorizes a deduction from your account.",
                            color = ScamRed,
                            fontSize = 11.sp,
                            fontWeight = FontWeight.SemiBold,
                            lineHeight = 15.sp
                        )
                    }
                }
            }
        }
    }
}

// Deep inspection helper for QR code raw strings
fun inspectQrPayload(raw: String): QrPayloadAnalysis {
    val trimmed = raw.trim()
    val lower = trimmed.lowercase()

    // 1. Check for UPI Payment String (upi://pay?...)
    if (lower.startsWith("upi://pay")) {
        var payee: String? = null
        var amount: String? = null
        try {
            val uri = Uri.parse(trimmed)
            payee = uri.getQueryParameter("pn") ?: uri.getQueryParameter("pa")
            amount = uri.getQueryParameter("am")
        } catch (e: Exception) {}

        if (amount != null && amount.toDoubleOrNull() ?: 0.0 > 0) {
            return QrPayloadAnalysis(
                rawText = trimmed,
                isUpi = true,
                isUpiDrainScam = true,
                upiAmount = amount,
                upiPayee = payee,
                riskScore = 95,
                warningMessage = "🚨 DANGER: This QR code is configured to DEDUCT ₹$amount from your bank account to payee '${payee ?: "Unknown"}'. Scammers often claim this will 'credit' or 'refund' money to you!"
            )
        } else {
            return QrPayloadAnalysis(
                rawText = trimmed,
                isUpi = true,
                isUpiDrainScam = false,
                upiPayee = payee,
                riskScore = 40,
                warningMessage = "⚠️ UPI Payment Request: Pointing to payee '${payee ?: "Merchant"}'. Ensure you intend to send money."
            )
        }
    }

    // 2. Check for Encrypted / Obfuscated Script Payloads
    // Check for Base64 encoded scripts
    if (trimmed.length > 20 && trimmed.matches(Regex("^[A-Za-z0-9+/=]+$"))) {
        try {
            val decodedBytes = Base64.decode(trimmed, Base64.DEFAULT)
            val decodedStr = String(decodedBytes, Charsets.UTF_8)
            val lowerDecoded = decodedStr.lowercase()
            if (lowerDecoded.contains("powershell") || lowerDecoded.contains("cmd.exe") ||
                lowerDecoded.contains("http") || lowerDecoded.contains("exec") ||
                lowerDecoded.contains("<script") || lowerDecoded.contains("eval(") ||
                lowerDecoded.contains("sh ") || lowerDecoded.contains("bash")
            ) {
                return QrPayloadAnalysis(
                    rawText = trimmed,
                    isEncryptedScript = true,
                    scriptType = "Base64 Obfuscated Command Payload",
                    decodedPayload = decodedStr,
                    riskScore = 98,
                    warningMessage = "🚨 CRITICAL THREAT: Base64-obfuscated script detected inside QR code. Contains executable command sequence designed to compromise device or trigger remote execution."
                )
            }
        } catch (e: Exception) {}
    }

    // Check for Direct Script Injection (PowerShell, Bash, JavaScript data URI)
    if (lower.contains("powershell") || lower.contains("cmd.exe") || lower.startsWith("data:text/html") ||
        lower.contains("<script") || lower.contains("javascript:") || lower.contains("curl ") || lower.contains("wget ")
    ) {
        return QrPayloadAnalysis(
            rawText = trimmed,
            isEncryptedScript = true,
            scriptType = "Direct Script Injection",
            decodedPayload = trimmed,
            riskScore = 95,
            warningMessage = "🚨 MALICIOUS SCRIPT DETECTED: QR code contains raw shell/script execution commands."
        )
    }

    // 3. Phishing / Typosquatted URLs
    if (lower.startsWith("http://") || lower.startsWith("https://")) {
        val isIp = lower.contains("http://1") || lower.contains("http://2")
        val isLookalike = lower.contains("sbi-") || lower.contains("yono-") || lower.contains("paytm-")
        return QrPayloadAnalysis(
            rawText = trimmed,
            riskScore = if (isIp || isLookalike) 90 else 20,
            warningMessage = if (isIp || isLookalike) "🚨 HIGH RISK URL: QR code directs to a suspicious/lookalike host."
            else "🔗 Web Link: Directs to $trimmed. Run Deep Scan to verify with VirusTotal."
        )
    }

    // Clean Plaintext
    return QrPayloadAnalysis(
        rawText = trimmed,
        riskScore = 0,
        warningMessage = "Plain text content detected. No malicious payload indicators found."
    )
}
