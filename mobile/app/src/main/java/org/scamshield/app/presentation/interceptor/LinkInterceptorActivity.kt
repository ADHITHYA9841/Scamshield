package org.scamshield.app.presentation.interceptor

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.scamshield.app.ScamShieldApp
import org.scamshield.app.core.network.StandardResultDto
import org.scamshield.app.core.theme.*

class LinkInterceptorActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val targetUrl = intent?.data?.toString() ?: ""

        setContent {
            ScamShieldTheme {
                val app = application as ScamShieldApp
                val repository = app.repository
                val coroutineScope = rememberCoroutineScope()

                var isScanning by remember { mutableStateOf(true) }
                var scanResult by remember { mutableStateOf<StandardResultDto?>(null) }
                var errorMsg by remember { mutableStateOf<String?>(null) }

                LaunchedEffect(targetUrl) {
                    if (targetUrl.isNotBlank()) {
                        isScanning = true
                        coroutineScope.launch {
                            repository.analyzeUrl(targetUrl).fold(
                                onSuccess = { res ->
                                    isScanning = false
                                    scanResult = res
                                },
                                onFailure = { err ->
                                    isScanning = false
                                    errorMsg = err.message
                                }
                            )
                        }
                    } else {
                        isScanning = false
                        errorMsg = "No URL provided to inspect."
                    }
                }

                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = DarkBackground
                ) {
                    Box(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(20.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            shape = RoundedCornerShape(16.dp),
                            colors = CardDefaults.cardColors(containerColor = DarkSurface),
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (scanResult?.verdict == "SCAM") ScamRed
                                else if (scanResult?.verdict == "SUSPICIOUS") SuspiciousAmber
                                else BorderColor
                            )
                        ) {
                            Column(
                                modifier = Modifier.padding(20.dp),
                                horizontalAlignment = Alignment.CenterHorizontally
                            ) {
                                Text(
                                    text = "SCAMSHIELD LINK GATEWAY",
                                    fontSize = 11.sp,
                                    fontWeight = FontWeight.Bold,
                                    color = AccentBlueLight,
                                    letterSpacing = 1.sp
                                )

                                Spacer(modifier = Modifier.height(14.dp))

                                Surface(
                                    modifier = Modifier.fillMaxWidth(),
                                    shape = RoundedCornerShape(8.dp),
                                    color = DarkBackground,
                                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                                ) {
                                    Text(
                                        text = targetUrl,
                                        fontSize = 11.sp,
                                        color = TextSecondary,
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                        modifier = Modifier.padding(10.dp),
                                        maxLines = 2
                                    )
                                }

                                Spacer(modifier = Modifier.height(18.dp))

                                if (isScanning) {
                                    CircularProgressIndicator(color = AccentBlue, modifier = Modifier.size(36.dp))
                                    Spacer(modifier = Modifier.height(12.dp))
                                    Text(
                                        text = "Verifying link with VirusTotal 90+ Engines...",
                                        fontSize = 12.sp,
                                        color = TextSecondary
                                    )
                                } else if (scanResult != null) {
                                    val res = scanResult!!
                                    val isScam = res.verdict == "SCAM"
                                    val isSuspicious = res.verdict == "SUSPICIOUS"
                                    val themeColor = if (isScam) ScamRed else if (isSuspicious) WarningYellow else SafeGreen

                                    Box(
                                        modifier = Modifier
                                            .size(64.dp)
                                            .border(3.dp, themeColor, CircleShape)
                                            .background(DarkBackground, CircleShape),
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text("${res.riskScore}", fontWeight = FontWeight.ExtraBold, fontSize = 20.sp, color = TextPrimary)
                                    }

                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(res.verdict, fontWeight = FontWeight.ExtraBold, fontSize = 18.sp, color = themeColor)
                                    Text(res.scamType, fontSize = 12.sp, color = TextSecondary)

                                    Spacer(modifier = Modifier.height(10.dp))
                                    Text(res.explanation, fontSize = 11.sp, color = TextSecondary, lineHeight = 15.sp)

                                    Spacer(modifier = Modifier.height(18.dp))

                                    if (isScam) {
                                        Button(
                                            onClick = { finish() },
                                            colors = ButtonDefaults.buttonColors(containerColor = ScamRed),
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            Text("Block & Go Back (Recommended)", color = TextPrimary, fontWeight = FontWeight.Bold)
                                        }
                                    } else {
                                        Button(
                                            onClick = {
                                                try {
                                                    val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)).apply {
                                                        addCategory(Intent.CATEGORY_BROWSABLE)
                                                    }
                                                    val pm = packageManager
                                                    val resolveList = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                                                        pm.queryIntentActivities(browserIntent, android.content.pm.PackageManager.ResolveInfoFlags.of(0))
                                                    } else {
                                                        @Suppress("DEPRECATION")
                                                        pm.queryIntentActivities(browserIntent, 0)
                                                    }
                                                    val externalApp = resolveList.firstOrNull { it.activityInfo.packageName != packageName }
                                                    if (externalApp != null) {
                                                        browserIntent.setPackage(externalApp.activityInfo.packageName)
                                                        startActivity(browserIntent)
                                                    } else {
                                                        val chooser = Intent.createChooser(browserIntent, "Open with")
                                                        startActivity(chooser)
                                                    }
                                                } catch (e: Exception) {
                                                    // Fallback
                                                    try {
                                                        startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(targetUrl)))
                                                    } catch (ign: Exception) {}
                                                }
                                                finish()
                                            },
                                            colors = ButtonDefaults.buttonColors(containerColor = SafeGreen),
                                            shape = RoundedCornerShape(8.dp),
                                            modifier = Modifier.fillMaxWidth()
                                        ) {
                                            Text("Proceed to Website", color = androidx.compose.ui.graphics.Color.White, fontWeight = FontWeight.Bold)
                                        }
                                    }
                                } else {
                                    Text(errorMsg ?: "Could not verify link.", color = ScamRed, fontSize = 12.sp)
                                    Spacer(modifier = Modifier.height(14.dp))
                                    Button(onClick = { finish() }) { Text("Close") }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
