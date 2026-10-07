package org.scamshield.app.presentation.navigation

sealed class Screen(val route: String, val title: String) {
    object Splash : Screen("splash", "ScamShield")
    object Home : Screen("home", "Home")
    object Result : Screen("result", "Analysis Result")
    object QrScanner : Screen("qr_scanner", "Scan QR")
    object Voice : Screen("voice", "Voice Analysis")
    object History : Screen("history", "History")
    object Statistics : Screen("statistics", "Statistics")
    object Recovery : Screen("recovery", "Recovery Assistant")
    object Settings : Screen("settings", "Settings")
    object Evaluation : Screen("evaluation", "Research Benchmarks")
    object FileShield : Screen("file_shield", "File & Document Shield")
    object MessageShield : Screen("message_shield", "Scam & SMS Shield")
    object AnalyzeContent : Screen("analyze_content", "Analyze Content")
}
