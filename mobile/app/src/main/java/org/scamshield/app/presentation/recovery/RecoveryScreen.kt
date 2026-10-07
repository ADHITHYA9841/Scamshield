package org.scamshield.app.presentation.recovery

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.scamshield.app.core.network.RecoveryGuideDto
import org.scamshield.app.core.theme.*
import org.scamshield.app.data.repositories.ScanRepository

class RecoveryViewModel(private val repository: ScanRepository) : ViewModel() {
    private val _guide = MutableStateFlow<RecoveryGuideDto?>(null)
    val guide = _guide.asStateFlow()

    fun loadGuide(incidentType: String) {
        viewModelScope.launch {
            repository.getRecoveryGuide(incidentType).onSuccess {
                _guide.value = it
            }
        }
    }
}

data class IncidentScenario(
    val id: String,
    val title: String,
    val icon: ImageVector,
    val urgency: String,
    val steps: List<String>
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RecoveryScreen(
    viewModel: RecoveryViewModel,
    initialIncidentType: String = "transferred_money",
    onNavigateBack: () -> Unit
) {
    val context = LocalContext.current
    var selectedScenario by remember { mutableStateOf<IncidentScenario?>(null) }
    var showEmergencyDialog by remember { mutableStateOf(false) }
    var completedSteps by remember { mutableStateOf(setOf<Int>()) }

    val scenarios = remember {
        listOf(
            IncidentScenario(
                id = "clicked_link",
                title = "Clicked a link",
                icon = Icons.Default.Link,
                urgency = "HIGH",
                steps = listOf(
                    "Disconnect your device from Wi-Fi and mobile data immediately.",
                    "Do NOT enter any passwords or login credentials on the opened webpage.",
                    "Clear your browser history, cache, and cookies immediately.",
                    "Check your Downloads folder for any unauthorized files or APKs.",
                    "Run a full device antivirus/malware scan using ScamShield or Google Play Protect."
                )
            ),
            IncidentScenario(
                id = "entered_password",
                title = "Entered my password",
                icon = Icons.Default.Lock,
                urgency = "CRITICAL",
                steps = listOf(
                    "Immediately log in from another trusted device and CHANGE your password.",
                    "Terminate all active sessions and log out from all devices.",
                    "Enable Multi-Factor Authentication (MFA) using an Authenticator app.",
                    "If the password is reused on other accounts (Email, Bank, Social), change them now.",
                    "Review recent account activity and audit registered recovery phone & email."
                )
            ),
            IncidentScenario(
                id = "entered_otp",
                title = "Entered OTP",
                icon = Icons.Default.Chat,
                urgency = "CRITICAL (GOLDEN HOUR)",
                steps = listOf(
                    "Call your bank customer care immediately to FREEZE internet banking & debit cards.",
                    "Do NOT share any subsequent OTP or SMS messages with anyone.",
                    "Check your bank account balance and review recent debit transactions.",
                    "Call the National Cyber Crime Reporting Portal helpline at 1930.",
                    "File an official fraud complaint on cybercrime.gov.in."
                )
            ),
            IncidentScenario(
                id = "entered_bank_details",
                title = "Entered bank details",
                icon = Icons.Default.CreditCard,
                urgency = "CRITICAL",
                steps = listOf(
                    "Immediately call your bank helpline to block your Debit / Credit card.",
                    "Temporarily freeze net-banking access via your bank's official app.",
                    "Set your card online transaction limits to ₹0 in your banking app.",
                    "Dial 1930 Cyber Fraud helpline immediately if funds have been deducted.",
                    "Keep transaction SMS, debit alert, and card statement as evidence."
                )
            ),
            IncidentScenario(
                id = "made_upi_payment",
                title = "Made a UPI payment",
                icon = Icons.Default.CurrencyRupee,
                urgency = "CRITICAL (ACT IN 60 MINS)",
                steps = listOf(
                    "Dial 1930 immediately! Cyber police can freeze the receiver's account within the Golden Hour.",
                    "Raise a chargeback dispute on your UPI app (GPay / PhonePe / Paytm / BHIM).",
                    "Contact your debiting bank branch with the 12-digit UPI UTR Reference Number.",
                    "File a cyber crime complaint at cybercrime.gov.in with receiver UPI ID and screenshots.",
                    "Do not transfer any more funds even if the scammer promises a 'refund'."
                )
            ),
            IncidentScenario(
                id = "downloaded_file",
                title = "Downloaded a file",
                icon = Icons.Default.FileDownload,
                urgency = "HIGH",
                steps = listOf(
                    "Turn on Airplane Mode immediately to prevent remote data exfiltration.",
                    "Go to your Downloads folder and delete the downloaded file permanently.",
                    "Do NOT open, preview, or install the downloaded file.",
                    "Run Google Play Protect scan and ScamShield file inspector.",
                    "Reboot your phone in Safe Mode if suspicious background behavior persists."
                )
            ),
            IncidentScenario(
                id = "installed_application",
                title = "Installed an application",
                icon = Icons.Default.Inventory2,
                urgency = "CRITICAL",
                steps = listOf(
                    "Immediately enable Airplane Mode to sever remote-access control.",
                    "Go to Settings > Apps > Special App Access > Device Admin Apps and revoke permissions.",
                    "Uninstall the suspicious app completely from Settings > Apps.",
                    "Check Accessibility Services and disable any unauthorized screen-sharing tools (AnyDesk, TeamViewer, RustDesk).",
                    "Change your primary passwords and consider a complete factory reset if spyware persists."
                )
            ),
            IncidentScenario(
                id = "shared_personal_info",
                title = "Shared personal information",
                icon = Icons.Default.Person,
                urgency = "HIGH",
                steps = listOf(
                    "If Aadhaar details were shared, lock your biometrics on the UIDAI portal/mAadhaar app.",
                    "If PAN or IDs were leaked, monitor your CIBIL score for unauthorized loans.",
                    "Alert your family and friends that fraudsters may impersonate you for emergency money.",
                    "Report the fraudulent communication to Sanchar Saathi (Chakshu portal).",
                    "Register a preventive complaint at your local cyber crime police station."
                )
            )
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = TextPrimary
                        )
                    }
                },
                title = {
                    Text(
                        text = "I Already Interacted",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        color = TextPrimary
                    )
                },
                actions = {
                    IconButton(
                        onClick = {
                            val shareIntent = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(
                                    Intent.EXTRA_TEXT,
                                    "ScamShield Cyber Incident Emergency Helpline: Dial 1930 or visit https://cybercrime.gov.in immediately to report financial fraud."
                                )
                            }
                            context.startActivity(Intent.createChooser(shareIntent, "Share Cyber Safety Guide"))
                        }
                    ) {
                        Icon(
                            imageVector = Icons.Default.Share,
                            contentDescription = "Share",
                            tint = TextPrimary
                        )
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
            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "Tell us what happened, and we'll guide you on the next steps.",
                fontSize = 13.sp,
                color = TextSecondary,
                lineHeight = 18.sp
            )

            Spacer(modifier = Modifier.height(16.dp))

            // 8 Action Scenario Cards
            scenarios.forEach { scenario ->
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .clickable {
                            selectedScenario = scenario
                            completedSteps = emptySet()
                        },
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            imageVector = scenario.icon,
                            contentDescription = null,
                            tint = AccentCyan,
                            modifier = Modifier.size(20.dp)
                        )

                        Spacer(modifier = Modifier.width(14.dp))

                        Text(
                            text = scenario.title,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.Medium,
                            color = TextPrimary,
                            modifier = Modifier.weight(1f)
                        )

                        Icon(
                            imageVector = Icons.Default.ChevronRight,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Bottom Emergency Helpline Card
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .clickable { showEmergencyDialog = true },
                shape = RoundedCornerShape(14.dp),
                color = DarkSurfaceVariant,
                border = androidx.compose.foundation.BorderStroke(1.dp, AccentBlue.copy(alpha = 0.5f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(44.dp)
                            .background(AccentBlue.copy(alpha = 0.15f), CircleShape)
                            .border(1.dp, AccentCyan.copy(alpha = 0.4f), CircleShape),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            imageVector = Icons.Default.Call,
                            contentDescription = null,
                            tint = AccentCyan,
                            modifier = Modifier.size(22.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(14.dp))

                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Need Immediate Help?",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = AccentCyan
                        )
                        Spacer(modifier = Modifier.height(2.dp))
                        Text(
                            text = "Contact your bank, official helplines, or cyber crime authorities.",
                            fontSize = 11.sp,
                            color = TextSecondary,
                            lineHeight = 15.sp
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }

    // Interactive Action Checklist Dialog / BottomSheet
    selectedScenario?.let { scenario ->
        AlertDialog(
            onDismissRequest = { selectedScenario = null },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(scenario.icon, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Column {
                        Text(
                            text = scenario.title,
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 16.sp
                        )
                        Text(
                            text = "Urgency: ${scenario.urgency}",
                            color = if (scenario.urgency.contains("CRITICAL")) ScamRed else SuspiciousAmber,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp
                        )
                    }
                }
            },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "Follow these immediate response steps:",
                        fontSize = 12.sp,
                        color = TextSecondary,
                        fontWeight = FontWeight.SemiBold
                    )

                    scenario.steps.forEachIndexed { index, step ->
                        val isChecked = completedSteps.contains(index)
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    completedSteps = if (isChecked) completedSteps - index else completedSteps + index
                                },
                            shape = RoundedCornerShape(8.dp),
                            color = if (isChecked) DarkSurfaceVariant.copy(alpha = 0.5f) else DarkSurfaceVariant,
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (isChecked) SafeGreen.copy(alpha = 0.4f) else BorderColor
                            )
                        ) {
                            Row(
                                modifier = Modifier.padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Checkbox(
                                    checked = isChecked,
                                    onCheckedChange = {
                                        completedSteps = if (isChecked) completedSteps - index else completedSteps + index
                                    },
                                    colors = CheckboxDefaults.colors(
                                        checkedColor = SafeGreen,
                                        checkmarkColor = DarkBackground
                                    )
                                )
                                Spacer(modifier = Modifier.width(6.dp))
                                Text(
                                    text = step,
                                    fontSize = 12.sp,
                                    color = if (isChecked) TextMuted else TextPrimary,
                                    lineHeight = 16.sp
                                )
                            }
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))

                    // Direct Action: Call 1930
                    Button(
                        onClick = {
                            val dialIntent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"))
                            context.startActivity(dialIntent)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = ScamRed),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.Call, contentDescription = null, tint = DarkBackground, modifier = Modifier.size(18.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Call 1930 National Cyber Helpline", color = DarkBackground, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                    }

                    // Direct Action: Open cybercrime.gov.in
                    OutlinedButton(
                        onClick = {
                            val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse("https://cybercrime.gov.in"))
                            context.startActivity(browserIntent)
                        },
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = AccentCyan),
                        border = androidx.compose.foundation.BorderStroke(1.dp, AccentCyan.copy(alpha = 0.6f)),
                        shape = RoundedCornerShape(10.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.OpenInNew, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Open Cyber Crime Portal", color = AccentCyan, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { selectedScenario = null }) {
                    Text("Done", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(16.dp)
        )
    }

    // Emergency Helpline Numbers Dialog
    if (showEmergencyDialog) {
        AlertDialog(
            onDismissRequest = { showEmergencyDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.SupportAgent, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(10.dp))
                    Text("Emergency Contacts", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930"))
                                context.startActivity(intent)
                            },
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.PhoneInTalk, contentDescription = null, tint = ScamRed, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text("National Cyber Crime Helpline", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = TextPrimary)
                                Text("1930 • Toll Free 24/7 (Golden Hour Response)", fontSize = 11.sp, color = AccentCyan)
                            }
                        }
                    }

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:112"))
                                context.startActivity(intent)
                            },
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Shield, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text("National Emergency Response", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = TextPrimary)
                                Text("112 • All-India Police Helpline", fontSize = 11.sp, color = TextSecondary)
                            }
                        }
                    }

                    Surface(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable {
                                val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://sancharsaathi.gov.in/sfc/"))
                                context.startActivity(intent)
                            },
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Row(modifier = Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Language, contentDescription = null, tint = SafeGreen, modifier = Modifier.size(20.dp))
                            Spacer(modifier = Modifier.width(10.dp))
                            Column {
                                Text("Chakshu (DoT Fraud Portal)", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = TextPrimary)
                                Text("Report fraudulent SMS, WhatsApp & calls", fontSize = 11.sp, color = TextSecondary)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showEmergencyDialog = false }) {
                    Text("Close", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(16.dp)
        )
    }
}
