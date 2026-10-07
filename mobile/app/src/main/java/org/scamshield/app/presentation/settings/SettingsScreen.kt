package org.scamshield.app.presentation.settings

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.locale.AppLocaleManager
import org.scamshield.app.core.service.StorageWatcherService
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    onClearHistory: () -> Unit,
    onNavigateToEvaluation: () -> Unit = {},
    onMenuClick: () -> Unit = {}
) {
    val context = LocalContext.current
    val activity = context as? android.app.Activity
    val prefs = remember { context.getSharedPreferences("scamshield_prefs", Context.MODE_PRIVATE) }

    // Preference states
    var selectedLanguage by remember { mutableStateOf(prefs.getString("selected_language", "English") ?: "English") }
    var selectedTheme by remember { mutableStateOf(prefs.getString("selected_theme", "Dark") ?: "Dark") }
    var notificationsEnabled by remember { mutableStateOf(prefs.getBoolean("notifications_enabled", true)) }

    var selectedLlmProvider by remember { mutableStateOf(prefs.getString("llm_provider", "OpenAI (Configured)") ?: "OpenAI (Configured)") }
    var selectedUrlIntelligence by remember { mutableStateOf(prefs.getString("url_intel", "VirusTotal (Configured)") ?: "VirusTotal (Configured)") }

    var saveScanHistory by remember { mutableStateOf(prefs.getBoolean("save_scan_history", true)) }
    var retentionPeriod by remember { mutableStateOf(prefs.getString("retention_period", "30 Days") ?: "30 Days") }

    // Detection settings toggles
    var realTimeSmsShield by remember { mutableStateOf(prefs.getBoolean("real_time_sms_shield", true)) }
    var autoDownloadScan by remember { mutableStateOf(prefs.getBoolean("auto_download_scan", true)) }
    var strictHeuristicMode by remember { mutableStateOf(prefs.getBoolean("strict_heuristic_mode", true)) }
    var vibrateOnThreat by remember { mutableStateOf(prefs.getBoolean("vibrate_on_threat", true)) }

    // Dialog visibility states
    var showLanguageDialog by remember { mutableStateOf(false) }
    var showThemeDialog by remember { mutableStateOf(false) }
    var showLlmDialog by remember { mutableStateOf(false) }
    var showUrlIntelDialog by remember { mutableStateOf(false) }
    var showDetectionSettingsDialog by remember { mutableStateOf(false) }
    var showRetentionDialog by remember { mutableStateOf(false) }
    var showClearConfirmDialog by remember { mutableStateOf(false) }
    var showHistoryClearedToast by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onMenuClick) {
                        Icon(
                            imageVector = Icons.Default.Menu,
                            contentDescription = "Menu",
                            tint = TextPrimary
                        )
                    }
                },
                title = {
                    Text(
                        text = "Settings",
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        color = TextPrimary
                    )
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
            verticalArrangement = Arrangement.spacedBy(18.dp)
        ) {
            Spacer(modifier = Modifier.height(4.dp))

            // ==========================================
            // 1. General Section
            // ==========================================
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "General",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = TextMuted
                )

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Column {
                        // Language Row
                        SettingsNavRow(
                            icon = Icons.Default.Language,
                            title = "Language",
                            trailingValue = selectedLanguage,
                            onClick = { showLanguageDialog = true }
                        )

                        HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                        // Theme Row
                        SettingsNavRow(
                            icon = Icons.Default.DarkMode,
                            title = "Theme",
                            trailingValue = selectedTheme,
                            onClick = { showThemeDialog = true }
                        )

                        HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                        // Notifications Row
                        SettingsToggleRow(
                            icon = Icons.Default.NotificationsNone,
                            title = "Notifications",
                            checked = notificationsEnabled,
                            onCheckedChange = {
                                notificationsEnabled = it
                                prefs.edit().putBoolean("notifications_enabled", it).apply()
                            }
                        )
                    }
                }
            }

            // ==========================================
            // 2. AI & Analysis Section
            // ==========================================
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "AI & Analysis",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = TextMuted
                )

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Column {
                        // LLM Provider
                        SettingsNavRow(
                            icon = Icons.Default.Memory,
                            title = "LLM Provider",
                            trailingValue = selectedLlmProvider,
                            onClick = { showLlmDialog = true }
                        )

                        HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                        // URL Intelligence
                        SettingsNavRow(
                            icon = Icons.Default.Shield,
                            title = "URL Intelligence",
                            trailingValue = selectedUrlIntelligence,
                            onClick = { showUrlIntelDialog = true }
                        )

                        HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                        // Detection Settings
                        SettingsNavRow(
                            icon = Icons.Default.Tune,
                            title = "Detection Settings",
                            trailingValue = "",
                            onClick = { showDetectionSettingsDialog = true }
                        )
                    }
                }
            }

            // ==========================================
            // 3. Privacy Section
            // ==========================================
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    text = "Privacy",
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    color = TextMuted
                )

                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Column {
                        // Save Scan History Row
                        SettingsToggleRow(
                            icon = Icons.Default.Description,
                            title = "Save Scan History",
                            checked = saveScanHistory,
                            onCheckedChange = {
                                saveScanHistory = it
                                prefs.edit().putBoolean("save_scan_history", it).apply()
                            }
                        )

                        HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                        // Retention Period Row
                        SettingsNavRow(
                            icon = Icons.Default.AccessTime,
                            title = "Retention Period",
                            trailingValue = retentionPeriod,
                            onClick = { showRetentionDialog = true }
                        )
                    }
                }
            }

            // Research Benchmarks Button
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(12.dp))
                    .clickable(onClick = onNavigateToEvaluation),
                shape = RoundedCornerShape(12.dp),
                color = DarkSurfaceVariant,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Row(
                    modifier = Modifier.padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier
                            .size(36.dp)
                            .background(AccentBlue.copy(alpha = 0.15f), RoundedCornerShape(8.dp)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.Analytics,
                            contentDescription = null,
                            tint = AccentCyan,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = "Research Benchmark Evaluation",
                            fontWeight = FontWeight.SemiBold,
                            fontSize = 13.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = "Rules vs LLM vs Hybrid model metrics",
                            fontSize = 11.sp,
                            color = TextSecondary
                        )
                    }
                    Icon(
                        Icons.Default.ChevronRight,
                        contentDescription = null,
                        tint = TextMuted,
                        modifier = Modifier.size(18.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(24.dp))
        }
    }

    // ==========================================
    // Dialogs & Modals
    // ==========================================

    // 1. Language Dialog
    if (showLanguageDialog) {
        val languages = listOf("English", "தமிழ் (Tamil)", "हिन्दी (Hindi)")
        AlertDialog(
            onDismissRequest = { showLanguageDialog = false },
            title = { Text("Select Language", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    languages.forEach { lang ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    selectedLanguage = lang
                                    if (activity != null) {
                                        AppLocaleManager.setLocale(activity, lang)
                                    } else {
                                        prefs.edit().putString("selected_language", lang).apply()
                                    }
                                    showLanguageDialog = false
                                }
                                .padding(vertical = 10.dp, horizontal = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedLanguage == lang,
                                onClick = {
                                    selectedLanguage = lang
                                    if (activity != null) {
                                        AppLocaleManager.setLocale(activity, lang)
                                    } else {
                                        prefs.edit().putString("selected_language", lang).apply()
                                    }
                                    showLanguageDialog = false
                                },
                                colors = RadioButtonDefaults.colors(selectedColor = AccentCyan)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(lang, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showLanguageDialog = false }) {
                    Text("Close", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 2. Theme Dialog
    if (showThemeDialog) {
        val themes = listOf("Dark", "Light", "System Default")
        AlertDialog(
            onDismissRequest = { showThemeDialog = false },
            title = { Text("Select Theme", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    themes.forEach { theme ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    selectedTheme = theme
                                    prefs.edit().putString("selected_theme", theme).apply()
                                    showThemeDialog = false
                                }
                                .padding(vertical = 10.dp, horizontal = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = selectedTheme == theme,
                                onClick = {
                                    selectedTheme = theme
                                    prefs.edit().putString("selected_theme", theme).apply()
                                    showThemeDialog = false
                                },
                                colors = RadioButtonDefaults.colors(selectedColor = AccentCyan)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(theme, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showThemeDialog = false }) {
                    Text("Close", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 3. LLM Provider Dialog
    if (showLlmDialog) {
        AlertDialog(
            onDismissRequest = { showLlmDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Memory, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("LLM Provider Configuration", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "ScamShield operates with an integrated autonomous hybrid intelligence engine:",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(modifier = Modifier.size(8.dp).background(SafeGreen, CircleShape))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("OpenAI GPT-4o-mini", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Status: Configured & Active (Cloud Analysis)", fontSize = 11.sp, color = SafeGreen)
                        }
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Box(modifier = Modifier.size(8.dp).background(AccentCyan, CircleShape))
                                Spacer(modifier = Modifier.width(8.dp))
                                Text("On-Device Offline Rules Engine", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
                            }
                            Spacer(modifier = Modifier.height(4.dp))
                            Text("Status: Active • Zero-delay on-device heuristic parser", fontSize = 11.sp, color = AccentCyan)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showLlmDialog = false }) {
                    Text("Done", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 4. URL Intelligence Dialog
    if (showUrlIntelDialog) {
        AlertDialog(
            onDismissRequest = { showUrlIntelDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Shield, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("URL Intelligence", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Multi-Engine Threat Intelligence layers protecting your device:",
                        fontSize = 12.sp,
                        color = TextSecondary
                    )
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("VirusTotal Multi-Engine", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
                            Text("Status: Configured • Scans across 70+ antivirus scanners", fontSize = 11.sp, color = SafeGreen)
                        }
                    }

                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(8.dp),
                        color = DarkSurfaceVariant,
                        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text("Google Safe Browsing & URLhaus", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
                            Text("Status: Active • Global real-time blacklist detection", fontSize = 11.sp, color = SafeGreen)
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showUrlIntelDialog = false }) {
                    Text("Done", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 5. Detection Settings Dialog
    if (showDetectionSettingsDialog) {
        AlertDialog(
            onDismissRequest = { showDetectionSettingsDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Tune, contentDescription = null, tint = AccentCyan, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Detection Settings", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    SettingsToggleRow(
                        icon = Icons.Default.Sms,
                        title = "Real-Time SMS Interceptor",
                        subtitle = "Inspect incoming SMS for OTP lures & banking fraud",
                        checked = realTimeSmsShield,
                        onCheckedChange = {
                            realTimeSmsShield = it
                            prefs.edit().putBoolean("real_time_sms_shield", it).apply()
                        }
                    )

                    HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                    SettingsToggleRow(
                        icon = Icons.Default.Download,
                        title = "Auto Download Inspector",
                        subtitle = "Scan newly downloaded files and APKs immediately",
                        checked = autoDownloadScan,
                        onCheckedChange = {
                            autoDownloadScan = it
                            prefs.edit().putBoolean("auto_download_scan", it).apply()
                            if (it) {
                                StorageWatcherService.startService(context)
                            } else {
                                StorageWatcherService.stopService(context)
                            }
                        }
                    )

                    // All Files Access prompt on Android 11+
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        val isStorageManager = Environment.isExternalStorageManager()
                        Surface(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    try {
                                        val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION).apply {
                                            data = Uri.parse("package:${context.packageName}")
                                        }
                                        context.startActivity(intent)
                                    } catch (e: Exception) {
                                        try {
                                            context.startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                                        } catch (e2: Exception) {}
                                    }
                                },
                            shape = RoundedCornerShape(8.dp),
                            color = if (isStorageManager) SafeGreenBg else DarkSurfaceVariant,
                            border = androidx.compose.foundation.BorderStroke(
                                1.dp,
                                if (isStorageManager) SafeGreen.copy(alpha = 0.4f) else BorderColor
                            )
                        ) {
                            Row(
                                modifier = Modifier.padding(10.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Icon(
                                    if (isStorageManager) Icons.Default.CheckCircle else Icons.Default.FolderOpen,
                                    contentDescription = null,
                                    tint = if (isStorageManager) SafeGreen else AccentCyan,
                                    modifier = Modifier.size(16.dp)
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    if (isStorageManager) "All Files Permission Granted"
                                    else "Enable All Files Access (Chrome Downloads)",
                                    fontSize = 11.sp,
                                    color = if (isStorageManager) SafeGreenText else TextPrimary,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    }

                    HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                    SettingsToggleRow(
                        icon = Icons.Default.Security,
                        title = "Strict Heuristic Sensitivity",
                        subtitle = "Heightened verification for UPI, KYC, and government lures",
                        checked = strictHeuristicMode,
                        onCheckedChange = {
                            strictHeuristicMode = it
                            prefs.edit().putBoolean("strict_heuristic_mode", it).apply()
                        }
                    )

                    HorizontalDivider(color = BorderColor, thickness = 0.8.dp)

                    SettingsToggleRow(
                        icon = Icons.Default.Vibration,
                        title = "Haptic Vibration on Threat Alert",
                        subtitle = "Strong vibration pattern when high-risk fraud is intercepted",
                        checked = vibrateOnThreat,
                        onCheckedChange = {
                            vibrateOnThreat = it
                            prefs.edit().putBoolean("vibrate_on_threat", it).apply()
                        }
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { showDetectionSettingsDialog = false }) {
                    Text("Done", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 6. Retention Period Dialog
    if (showRetentionDialog) {
        val periods = listOf("7 Days", "14 Days", "30 Days", "90 Days", "Keep Forever")
        AlertDialog(
            onDismissRequest = { showRetentionDialog = false },
            title = { Text("Retention Period", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    periods.forEach { period ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(8.dp))
                                .clickable {
                                    retentionPeriod = period
                                    prefs.edit().putString("retention_period", period).apply()
                                    showRetentionDialog = false
                                }
                                .padding(vertical = 10.dp, horizontal = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = retentionPeriod == period,
                                onClick = {
                                    retentionPeriod = period
                                    prefs.edit().putString("retention_period", period).apply()
                                    showRetentionDialog = false
                                },
                                colors = RadioButtonDefaults.colors(selectedColor = AccentCyan)
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(period, color = TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.Medium)
                        }
                    }

                    Spacer(modifier = Modifier.height(10.dp))
                    HorizontalDivider(color = BorderColor, thickness = 0.8.dp)
                    Spacer(modifier = Modifier.height(10.dp))

                    Button(
                        onClick = {
                            showRetentionDialog = false
                            showClearConfirmDialog = true
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = ScamRed.copy(alpha = 0.15f)),
                        border = androidx.compose.foundation.BorderStroke(1.dp, ScamRed.copy(alpha = 0.4f)),
                        shape = RoundedCornerShape(8.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.DeleteOutline, contentDescription = null, tint = ScamRed, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Wipe Scan History Database", color = ScamRed, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showRetentionDialog = false }) {
                    Text("Close", color = AccentCyan)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }

    // 7. Clear History Confirmation Dialog
    if (showClearConfirmDialog) {
        AlertDialog(
            onDismissRequest = { showClearConfirmDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, contentDescription = null, tint = ScamRed, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Clear All Scan History?", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                }
            },
            text = {
                Text(
                    "This will delete all past scans and detection logs from your device storage. This action cannot be undone.",
                    color = TextSecondary,
                    fontSize = 13.sp
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        onClearHistory()
                        showClearConfirmDialog = false
                        showHistoryClearedToast = true
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = ScamRed)
                ) {
                    Text("Yes, Wipe All", color = DarkBackground, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirmDialog = false }) {
                    Text("Cancel", color = TextMuted)
                }
            },
            containerColor = DarkSurface,
            shape = RoundedCornerShape(14.dp)
        )
    }
}

// ==========================================
// Reusable Row Components matching Mockup
// ==========================================

@Composable
fun SettingsNavRow(
    icon: ImageVector,
    title: String,
    trailingValue: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = TextSecondary,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(14.dp))
        Text(
            text = title,
            fontSize = 14.sp,
            fontWeight = FontWeight.Medium,
            color = TextPrimary,
            modifier = Modifier.weight(1f)
        )
        if (trailingValue.isNotBlank()) {
            Text(
                text = trailingValue,
                fontSize = 13.sp,
                color = TextMuted
            )
            Spacer(modifier = Modifier.width(6.dp))
        }
        Icon(
            imageVector = Icons.Default.ChevronRight,
            contentDescription = null,
            tint = TextMuted,
            modifier = Modifier.size(18.dp)
        )
    }
}

@Composable
fun SettingsToggleRow(
    icon: ImageVector,
    title: String,
    subtitle: String? = null,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = if (subtitle != null) 10.dp else 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = TextSecondary,
            modifier = Modifier.size(20.dp)
        )
        Spacer(modifier = Modifier.width(14.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                fontSize = 14.sp,
                fontWeight = FontWeight.Medium,
                color = TextPrimary
            )
            if (subtitle != null) {
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = subtitle,
                    fontSize = 11.sp,
                    color = TextSecondary
                )
            }
        }
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            colors = SwitchDefaults.colors(
                checkedThumbColor = androidx.compose.ui.graphics.Color.White,
                checkedTrackColor = AccentBlue,
                uncheckedThumbColor = TextMuted,
                uncheckedTrackColor = DarkSurfaceVariant
            )
        )
    }
}
