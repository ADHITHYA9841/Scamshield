package org.scamshield.app.presentation.evaluation

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.theme.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EvaluationScreen(onNavigateBack: () -> Unit) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Research Benchmarks & Evaluation", color = TextPrimary, fontWeight = FontWeight.Bold, fontSize = 17.sp) },
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
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Spacer(modifier = Modifier.height(10.dp))

            // Dataset Overview Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("DATASET SPECIFICATIONS", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = AccentBlueLight)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text("• Total Curated Samples: 350 synthetic messages, URLs, and QR codes", color = TextPrimary, fontSize = 12.sp)
                    Text("• Categories: KYC, UPI Fraud, Delivery Phishing, Job Baits, Utilities, Safe Controls", color = TextSecondary, fontSize = 11.sp)
                    Text("• Languages: English (EN), Tamil (TA), Hindi (HI), Hinglish & Tanglish", color = TextSecondary, fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text("BASELINE COMPARISON METRICS", fontSize = 11.sp, fontWeight = FontWeight.Bold, color = TextMuted, letterSpacing = 1.sp)
            Spacer(modifier = Modifier.height(8.dp))

            // Metrics Table Cards
            MetricRowCard(
                modelName = "Rules-Only Baseline",
                accuracy = "44.0%",
                precision = "92.1%",
                recall = "26.9%",
                f1 = "41.7%",
                badgeColor = AccentBlueLight
            )

            Spacer(modifier = Modifier.height(10.dp))

            MetricRowCard(
                modelName = "LLM-Only Baseline",
                accuracy = "57.1%",
                precision = "100.0%",
                recall = "42.3%",
                f1 = "59.5%",
                badgeColor = AccentIndigo
            )

            Spacer(modifier = Modifier.height(10.dp))

            MetricRowCard(
                modelName = "Hybrid ScamShield (FUSED)",
                accuracy = "54.0%",
                precision = "79.0%",
                recall = "51.9%",
                f1 = "62.6%",
                badgeColor = SafeGreen,
                highlight = true
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Scientific Rationale Card
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp),
                color = DarkSurfaceVariant,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("DEFENSE ANALYSIS & RATIONALE", fontWeight = FontWeight.Bold, fontSize = 12.sp, color = TextPrimary)
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        "• Why Hybrid Fusion Wins: Standalone rules suffer from low recall (26.9%) because attackers continuously obfuscate phrases. Standalone LLMs miss network-level attacks (SSRF, homoglyphs, UPI traps).\n\n" +
                        "• ScamShield's hybrid fusion achieves the highest F1-Score (62.6%) and Recall (51.9%), effectively catching multi-stage threats while generating granular forensic evidence for user transparency.",
                        fontSize = 11.sp,
                        color = TextSecondary,
                        lineHeight = 16.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun MetricRowCard(
    modelName: String,
    accuracy: String,
    precision: String,
    recall: String,
    f1: String,
    badgeColor: androidx.compose.ui.graphics.Color,
    highlight: Boolean = false
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        color = if (highlight) DarkSurfaceVariant else DarkSurface,
        border = androidx.compose.foundation.BorderStroke(1.dp, if (highlight) SafeGreen else BorderColor)
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Text(modelName, fontWeight = FontWeight.Bold, fontSize = 13.sp, color = TextPrimary)
                Surface(color = badgeColor.copy(alpha = 0.2f), shape = RoundedCornerShape(4.dp)) {
                    Text("F1: $f1", color = badgeColor, fontSize = 10.sp, fontWeight = FontWeight.Bold, modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp))
                }
            }
            Spacer(modifier = Modifier.height(10.dp))
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Column { Text("Accuracy", fontSize = 9.sp, color = TextMuted); Text(accuracy, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary) }
                Column { Text("Precision", fontSize = 9.sp, color = TextMuted); Text(precision, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary) }
                Column { Text("Recall", fontSize = 9.sp, color = TextMuted); Text(recall, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = TextPrimary) }
                Column { Text("F1-Score", fontSize = 9.sp, color = TextMuted); Text(f1, fontSize = 12.sp, fontWeight = FontWeight.Bold, color = badgeColor) }
            }
        }
    }
}
