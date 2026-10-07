package org.scamshield.app.core.theme

import androidx.compose.ui.graphics.Color

// Core Neutral Surfaces (Exact Mockup Midnight Navy)
val DarkBackground = Color(0xFF070C18)       // Deep midnight navy
val DarkSurface = Color(0xFF0D1527)          // Rich slate-navy card surface
val DarkSurfaceVariant = Color(0xFF121D34)   // Elevated pill & nested surface
val BorderColor = Color(0xFF18253D)          // Crisp divider & card border
val BorderSubtle = Color(0xFF141F33)         // Subtle container border

// Brand Cyan / Electric Blue (Logo, Analyze Button, Active Nav)
val AccentCyan = Color(0xFF00E5FF)           // Neon Cyan Glow / Subtitle
val AccentCyanGlow = Color(0xFF00B4D8)       // Cyan Glow Accent
val AccentBlue = Color(0xFF00A3FF)           // Solid Electric Sky-Blue (Analyze Button, Active Tab, Bars)
val AccentBlueLight = Color(0xFF38BDF8)      // Active Pill & Chip Blue
val AccentIndigo = Color(0xFF6366F1)         // Supporting Accent

// Threat Signals (Exact Mockup Red, Amber, Green)
val ScamRed = Color(0xFFEF4444)              // Vibrant Signal Red
val ScamRedBg = Color(0xFF260C12)            // Rich Red Card Container
val ScamRedBorder = Color(0xFFDC2626)        // Red Card Stroke
val ScamRedTrack = Color(0xFF2D0F16)         // Score gauge background track
val ScamRedText = Color(0xFFEF4444)

val SuspiciousAmber = Color(0xFFF59E0B)      // Warning Amber
val SuspiciousAmberBg = Color(0xFF2A1807)    // Amber Card Container
val SuspiciousAmberBorder = Color(0xFFD97706)
val SuspiciousAmberTrack = Color(0xFF3A230B)
val SuspiciousAmberText = Color(0xFFF59E0B)
val WarningYellow = SuspiciousAmber

val SafeGreen = Color(0xFF10B981)            // Verification Emerald
val SafeGreenBg = Color(0xFF06221A)          // Emerald Card Container
val SafeGreenBorder = Color(0xFF059669)
val SafeGreenTrack = Color(0xFF0A261D)       // Score gauge background track
val SafeGreenText = Color(0xFF10B981)

// Blue Information Alert (Safe Result Box)
val AlertBlueBg = Color(0xFF0A1C36)          // Safe screen blue info container
val AlertBlueBorder = Color(0xFF1D4ED8)      // Blue stroke
val AlertBlueText = Color(0xFF93C5FD)        // Blue hint text

// Typography (Crisp Hierarchy matching Mockup)
val TextPrimary = Color(0xFFFFFFFF)          // Pure Crisp White
val TextSecondary = Color(0xFF8295AD)        // Slate-blue secondary text
val TextMuted = Color(0xFF566A85)            // Slate muted text & placeholders
