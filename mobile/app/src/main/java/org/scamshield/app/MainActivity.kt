package org.scamshield.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.R
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import org.scamshield.app.core.database.toStandardResultDto
import org.scamshield.app.core.locale.AppLocaleManager
import org.scamshield.app.core.service.StorageWatcherService
import org.scamshield.app.core.theme.AccentBlue
import org.scamshield.app.core.theme.AccentBlueLight
import org.scamshield.app.core.theme.AccentCyan
import org.scamshield.app.core.theme.DarkBackground
import org.scamshield.app.core.theme.DarkSurface
import org.scamshield.app.core.theme.ScamShieldTheme
import org.scamshield.app.core.theme.TextMuted
import org.scamshield.app.presentation.analyze.AnalyzeContentScreen
import org.scamshield.app.presentation.evaluation.EvaluationScreen
import org.scamshield.app.presentation.file.FileScannerScreen
import org.scamshield.app.presentation.file.FileViewModel
import org.scamshield.app.presentation.history.HistoryScreen
import org.scamshield.app.presentation.history.HistoryViewModel
import org.scamshield.app.presentation.home.HomeScreen
import org.scamshield.app.presentation.home.HomeViewModel
import org.scamshield.app.presentation.message.MessageScannerScreen
import org.scamshield.app.presentation.message.MessageViewModel
import org.scamshield.app.presentation.navigation.Screen
import org.scamshield.app.presentation.qr.QrScannerScreen
import org.scamshield.app.presentation.recovery.RecoveryScreen
import org.scamshield.app.presentation.recovery.RecoveryViewModel
import org.scamshield.app.presentation.result.ResultScreen
import org.scamshield.app.presentation.settings.SettingsScreen
import org.scamshield.app.presentation.splash.SplashScreen
import org.scamshield.app.presentation.statistics.StatisticsScreen
import org.scamshield.app.presentation.statistics.StatisticsViewModel
import org.scamshield.app.presentation.voice.VoiceScreen

data class BottomNavItem(val screen: Screen, val icon: ImageVector, val label: String)

class MainActivity : ComponentActivity() {
    override fun attachBaseContext(newBase: Context) {
        super.attachBaseContext(AppLocaleManager.applyStoredLocale(newBase))
    }

    private val requestPermissionsLauncher = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions()
    ) { _ ->
        try {
            StorageWatcherService.startService(this)
        } catch (e: Throwable) {}
    }

    override fun onStart() {
        super.onStart()
        try {
            StorageWatcherService.startService(this)
        } catch (e: Throwable) {}
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val app = application as ScamShieldApp
        val repository = app.repository

        // Request essential security permissions on startup
        val permissionsToRequest = mutableListOf<String>()
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (androidx.core.content.ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.POST_NOTIFICATIONS
                ) != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                permissionsToRequest.add(android.Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        if (android.os.Build.VERSION.SDK_INT <= android.os.Build.VERSION_CODES.S_V2) {
            if (androidx.core.content.ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.READ_EXTERNAL_STORAGE
                ) != android.content.pm.PackageManager.PERMISSION_GRANTED
            ) {
                permissionsToRequest.add(android.Manifest.permission.READ_EXTERNAL_STORAGE)
            }
        }
        if (androidx.core.content.ContextCompat.checkSelfPermission(
                this,
                android.Manifest.permission.RECEIVE_SMS
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            permissionsToRequest.add(android.Manifest.permission.RECEIVE_SMS)
        }
        if (androidx.core.content.ContextCompat.checkSelfPermission(
                this,
                android.Manifest.permission.READ_SMS
            ) != android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            permissionsToRequest.add(android.Manifest.permission.READ_SMS)
        }
        if (permissionsToRequest.isNotEmpty()) {
            requestPermissionsLauncher.launch(permissionsToRequest.toTypedArray())
        }
        
        try {
            StorageWatcherService.startService(this)
        } catch (e: Throwable) {}

        // Check for Android Share Intent (e.g. from WhatsApp, Chrome, SMS, Files)
        var sharedText: String? = null
        var sharedFileUri: Uri? = null

        if (intent?.action == Intent.ACTION_SEND) {
            if (intent.type == "text/plain") {
                sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            } else if (intent.type?.startsWith("image/") == true || intent.type?.startsWith("application/") == true) {
                @Suppress("DEPRECATION")
                sharedFileUri = intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
        } else if (intent?.hasExtra("shared_text") == true) {
            sharedText = intent.getStringExtra("shared_text")
        }

        setContent {
            ScamShieldTheme {
                val navController = rememberNavController()
                val homeViewModel = remember { HomeViewModel(repository) }
                val fileViewModel = remember { FileViewModel(repository) }
                val messageViewModel = remember { MessageViewModel(repository) }
                val historyViewModel = remember { HistoryViewModel(repository) }
                val statsViewModel = remember { StatisticsViewModel(repository) }
                val recoveryViewModel = remember { RecoveryViewModel(repository) }

                // Automatically trigger analysis if text shared via Android Share Sheet or Threat Notification
                LaunchedEffect(sharedText) {
                    sharedText?.let {
                        homeViewModel.analyzeText(it)
                        navController.navigate(Screen.Result.route)
                    }
                }

                // Automatically trigger analysis if file shared via Android Share Sheet
                LaunchedEffect(sharedFileUri) {
                    sharedFileUri?.let {
                        fileViewModel.onFileSelected(this@MainActivity, it)
                        navController.navigate(Screen.FileShield.route)
                    }
                }

                val bottomItems = listOf(
                    BottomNavItem(Screen.Home, Icons.Default.Shield, stringResource(R.string.nav_home)),
                    BottomNavItem(Screen.History, Icons.Default.History, stringResource(R.string.nav_history)),
                    BottomNavItem(Screen.Statistics, Icons.Default.BarChart, stringResource(R.string.nav_stats)),
                    BottomNavItem(Screen.Settings, Icons.Default.Settings, stringResource(R.string.nav_settings))
                )

                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route

                Scaffold(
                    bottomBar = {
                        val showBottomBar = bottomItems.any { it.screen.route == currentRoute }
                        if (showBottomBar) {
                            NavigationBar(
                                containerColor = DarkSurface,
                                tonalElevation = 8.dp
                            ) {
                                bottomItems.forEach { item ->
                                    val isSelected = currentRoute == item.screen.route
                                    NavigationBarItem(
                                        icon = { Icon(item.icon, contentDescription = item.label) },
                                        label = { Text(item.label, fontSize = 10.sp) },
                                        selected = isSelected,
                                        onClick = {
                                            if (currentRoute != item.screen.route) {
                                                navController.navigate(item.screen.route) {
                                                    popUpTo(navController.graph.findStartDestination().id) {
                                                        saveState = true
                                                    }
                                                    launchSingleTop = true
                                                    restoreState = true
                                                }
                                            }
                                        },
                                        colors = NavigationBarItemDefaults.colors(
                                            selectedIconColor = AccentCyan,
                                            selectedTextColor = AccentCyan,
                                            unselectedIconColor = TextMuted,
                                            unselectedTextColor = TextMuted,
                                            indicatorColor = androidx.compose.ui.graphics.Color.Transparent
                                        )
                                    )
                                }
                            }
                        }
                    },
                    containerColor = DarkBackground
                ) { innerPadding ->
                    NavHost(
                        navController = navController,
                        startDestination = Screen.Splash.route,
                        modifier = Modifier.padding(innerPadding)
                    ) {
                        composable(Screen.Splash.route) {
                            SplashScreen(
                                onSplashComplete = {
                                    navController.navigate(Screen.Home.route) {
                                        popUpTo(Screen.Splash.route) { inclusive = true }
                                    }
                                }
                            )
                        }

                        composable(Screen.Home.route) {
                            HomeScreen(
                                viewModel = homeViewModel,
                                onNavigateToResult = { navController.navigate(Screen.Result.route) },
                                onNavigateToQr = { navController.navigate(Screen.QrScanner.route) },
                                onNavigateToVoice = { navController.navigate(Screen.Voice.route) },
                                onNavigateToFile = { navController.navigate(Screen.FileShield.route) },
                                onNavigateToMessage = { navController.navigate(Screen.MessageShield.route) },
                                onNavigateToAnalyzeContent = { navController.navigate(Screen.AnalyzeContent.route) }
                            )
                        }

                        composable(Screen.AnalyzeContent.route) {
                            AnalyzeContentScreen(
                                onNavigateBack = { navController.popBackStack() },
                                onSelectText = { navController.navigate(Screen.Home.route) },
                                onSelectUrl = { navController.navigate(Screen.Home.route) },
                                onSelectDocument = { navController.navigate(Screen.FileShield.route) },
                                onSelectImage = { navController.navigate(Screen.FileShield.route) },
                                onSelectQr = { navController.navigate(Screen.QrScanner.route) },
                                onSelectVoice = { navController.navigate(Screen.Voice.route) },
                                onSelectPhone = { navController.navigate(Screen.Home.route) }
                            )
                        }

                        composable(Screen.FileShield.route) {
                            FileScannerScreen(
                                viewModel = fileViewModel,
                                onNavigateBack = { navController.popBackStack() }
                            )
                        }

                        composable(Screen.MessageShield.route) {
                            MessageScannerScreen(
                                viewModel = messageViewModel,
                                onNavigateBack = { navController.popBackStack() }
                            )
                        }

                        composable(Screen.Result.route) {
                            ResultScreen(
                                result = homeViewModel.lastResult,
                                isLoading = homeViewModel.isLoading,
                                onNavigateBack = { navController.popBackStack() },
                                onNavigateToRecovery = { category ->
                                    navController.navigate(Screen.Recovery.route)
                                }
                            )
                        }

                        composable(Screen.QrScanner.route) {
                            QrScannerScreen(
                                onNavigateBack = { navController.popBackStack() },
                                onAnalyzeQr = { payload ->
                                    homeViewModel.analyzeQr(payload)
                                    navController.navigate(Screen.Result.route)
                                }
                            )
                        }

                        composable(Screen.Voice.route) {
                            VoiceScreen(
                                onNavigateBack = { navController.popBackStack() },
                                onAnalyzeTranscript = { transcript ->
                                    homeViewModel.analyzeText(transcript)
                                    navController.navigate(Screen.Result.route)
                                }
                            )
                        }

                        composable(Screen.History.route) {
                            HistoryScreen(
                                viewModel = historyViewModel,
                                onSelectScan = { scan ->
                                    homeViewModel.setResult(scan.toStandardResultDto())
                                    navController.navigate(Screen.Result.route)
                                },
                                onMenuClick = { navController.navigate(Screen.AnalyzeContent.route) }
                            )
                        }

                        composable(Screen.Statistics.route) {
                            StatisticsScreen(viewModel = statsViewModel)
                        }

                        composable(Screen.Recovery.route) {
                            RecoveryScreen(
                                viewModel = recoveryViewModel,
                                onNavigateBack = { navController.popBackStack() }
                            )
                        }

                        composable(Screen.Settings.route) {
                            SettingsScreen(
                                onClearHistory = { historyViewModel.clearAll() },
                                onNavigateToEvaluation = { navController.navigate(Screen.Evaluation.route) },
                                onMenuClick = { navController.navigate(Screen.AnalyzeContent.route) }
                            )
                        }

                        composable(Screen.Evaluation.route) {
                            EvaluationScreen(onNavigateBack = { navController.popBackStack() })
                        }
                    }
                }
            }
        }
    }
}
