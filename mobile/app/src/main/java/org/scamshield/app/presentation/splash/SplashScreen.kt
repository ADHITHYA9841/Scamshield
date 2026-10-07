package org.scamshield.app.presentation.splash

import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.scamshield.app.core.theme.*

@Composable
fun SplashScreen(
    onSplashComplete: () -> Unit
) {
    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 0.95f,
        targetValue = 1.05f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )
    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = 0.7f,
        animationSpec = infiniteRepeatable(
            animation = tween(1200, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "alpha"
    )

    var statusText by remember { mutableStateOf("Initializing Security Engine...") }

    LaunchedEffect(Unit) {
        delay(800)
        statusText = "Loading Local Heuristics & Threat DB..."
        delay(800)
        statusText = "Active Defense Ready"
        delay(400)
        onSplashComplete()
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        DarkBackground,
                        Color(0xFF0F172A),
                        DarkBackground
                    )
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
            modifier = Modifier.padding(24.dp)
        ) {
            // Glowing Shield Emblem
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(120.dp)
            ) {
                // Outer Pulse Aura
                Box(
                    modifier = Modifier
                        .size(110.dp)
                        .scale(pulseScale)
                        .alpha(pulseAlpha)
                        .border(2.dp, AccentBlueLight.copy(alpha = 0.5f), CircleShape)
                        .background(AccentBlue.copy(alpha = 0.1f), CircleShape)
                )

                // Inner Shield Container
                Box(
                    modifier = Modifier
                        .size(76.dp)
                        .background(DarkSurface, CircleShape)
                        .border(1.dp, BorderColor, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = Icons.Default.Shield,
                        contentDescription = "ScamShield",
                        tint = AccentBlueLight,
                        modifier = Modifier.size(42.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            // Brand Typography
            Text(
                text = "ScamShield",
                fontSize = 28.sp,
                fontWeight = FontWeight.ExtraBold,
                color = TextPrimary,
                letterSpacing = 0.5.sp
            )

            Spacer(modifier = Modifier.height(4.dp))

            Text(
                text = "CYBER DEFENSE & FRAUD INTELLIGENCE",
                fontSize = 10.sp,
                fontWeight = FontWeight.Bold,
                color = AccentBlueLight,
                letterSpacing = 2.sp
            )

            Spacer(modifier = Modifier.height(48.dp))

            // Status & Progress Indicator
            LinearProgressIndicator(
                modifier = Modifier
                    .width(160.dp)
                    .height(3.dp),
                color = AccentBlueLight,
                trackColor = BorderColor
            )

            Spacer(modifier = Modifier.height(14.dp))

            Text(
                text = statusText,
                fontSize = 11.sp,
                color = TextSecondary,
                letterSpacing = 0.5.sp
            )
        }

        // Bottom Footer
        Column(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .padding(bottom = 32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "ON-DEVICE ZERO-TRUST ARCHITECTURE",
                fontSize = 9.sp,
                fontWeight = FontWeight.Bold,
                color = TextMuted,
                letterSpacing = 1.5.sp
            )
            Spacer(modifier = Modifier.height(2.dp))
            Text(
                text = "v1.0.5 • Private & Autonomous",
                fontSize = 9.sp,
                color = TextMuted
            )
        }
    }
}
