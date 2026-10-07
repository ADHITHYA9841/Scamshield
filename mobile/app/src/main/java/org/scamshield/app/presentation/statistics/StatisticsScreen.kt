package org.scamshield.app.presentation.statistics

import androidx.compose.foundation.Canvas
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.scamshield.app.R
import org.scamshield.app.core.network.StatisticsDto
import org.scamshield.app.core.theme.*
import org.scamshield.app.data.repositories.ScanRepository

class StatisticsViewModel(private val repository: ScanRepository) : ViewModel() {
    private val _stats = MutableStateFlow<StatisticsDto?>(null)
    val stats = _stats.asStateFlow()

    init {
        loadStats()
    }

    fun loadStats() {
        viewModelScope.launch {
            repository.getStatistics().onSuccess {
                _stats.value = it
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StatisticsScreen(viewModel: StatisticsViewModel) {
    val stats by viewModel.stats.collectAsState()
    var selectedRange by remember { mutableStateOf("Last 30 Days") }
    var showRangeMenu by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        viewModel.loadStats()
    }

    val totalScans = stats?.totalScans ?: 42
    val scamCount = stats?.scamCount ?: 12
    val suspiciousCount = stats?.suspiciousCount ?: 18
    val safeCount = stats?.safeCount ?: 12

    val safeTotal = maxOf(1, scamCount + suspiciousCount + safeCount)
    val scamPct = ((scamCount.toFloat() / safeTotal) * 100).toInt()
    val suspPct = ((suspiciousCount.toFloat() / safeTotal) * 100).toInt()
    val safePct = maxOf(0, 100 - scamPct - suspPct)

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Default.Shield,
                            contentDescription = null,
                            tint = AccentCyan,
                            modifier = Modifier.size(22.dp)
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = "Statistics",
                            color = TextPrimary,
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp
                        )
                    }
                },
                actions = {
                    Box {
                        Surface(
                            modifier = Modifier
                                .clip(RoundedCornerShape(14.dp))
                                .clickable { showRangeMenu = true },
                            shape = RoundedCornerShape(14.dp),
                            color = DarkSurfaceVariant,
                            border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                        ) {
                            Row(
                                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Text(
                                    text = selectedRange,
                                    fontSize = 11.sp,
                                    color = TextSecondary,
                                    fontWeight = FontWeight.Medium
                                )
                                Spacer(modifier = Modifier.width(4.dp))
                                Icon(
                                    imageVector = Icons.Default.KeyboardArrowDown,
                                    contentDescription = null,
                                    tint = TextMuted,
                                    modifier = Modifier.size(16.dp)
                                )
                            }
                        }

                        DropdownMenu(
                            expanded = showRangeMenu,
                            onDismissRequest = { showRangeMenu = false }
                        ) {
                            listOf("Today", "Last 7 Days", "Last 30 Days", "All Time").forEach { r ->
                                DropdownMenuItem(
                                    text = { Text(r) },
                                    onClick = {
                                        selectedRange = r
                                        showRangeMenu = false
                                    }
                                )
                            }
                        }
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

            // 1. Top 4 Stat Cards Row (Total Scans | Scams | Suspicious | Safe)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatCardPill(title = "Total Scans", value = "$totalScans", color = AccentCyan, modifier = Modifier.weight(1f))
                StatCardPill(title = "Scams", value = "$scamCount", color = ScamRed, modifier = Modifier.weight(1f))
                StatCardPill(title = "Suspicious", value = "$suspiciousCount", color = SuspiciousAmber, modifier = Modifier.weight(1f))
                StatCardPill(title = "Safe", value = "$safeCount", color = SafeGreen, modifier = Modifier.weight(1f))
            }

            Spacer(modifier = Modifier.height(18.dp))

            // 2. Scan Results Donut Chart Section
            Text(
                text = "Scan Results",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(8.dp))

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(18.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceAround
                ) {
                    // Donut Chart Canvas
                    Box(
                        modifier = Modifier.size(110.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Canvas(modifier = Modifier.size(96.dp)) {
                            val strokeWidth = 14.dp.toPx()
                            val scamAngle = (scamPct / 100f) * 360f
                            val suspAngle = (suspPct / 100f) * 360f
                            val safeAngle = 360f - scamAngle - suspAngle

                            var start = -90f
                            drawArc(color = ScamRed, startAngle = start, sweepAngle = scamAngle, useCenter = false, style = Stroke(strokeWidth))
                            start += scamAngle
                            drawArc(color = SuspiciousAmber, startAngle = start, sweepAngle = suspAngle, useCenter = false, style = Stroke(strokeWidth))
                            start += suspAngle
                            drawArc(color = SafeGreen, startAngle = start, sweepAngle = safeAngle, useCenter = false, style = Stroke(strokeWidth))
                        }

                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = "$totalScans",
                                fontSize = 18.sp,
                                fontWeight = FontWeight.Bold,
                                color = TextPrimary
                            )
                            Text(
                                text = "Total",
                                fontSize = 10.sp,
                                color = TextMuted
                            )
                        }
                    }

                    // Legend Column
                    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        DonutLegendItem(color = ScamRed, label = "Scam", percentage = "$scamPct%")
                        DonutLegendItem(color = SuspiciousAmber, label = "Suspicious", percentage = "$suspPct%")
                        DonutLegendItem(color = SafeGreen, label = "Safe", percentage = "$safePct%")
                    }
                }
            }

            Spacer(modifier = Modifier.height(18.dp))

            // 3. Input Types Horizontal Bar Chart Section
            Text(
                text = "Input Types",
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(8.dp))

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(14.dp),
                color = DarkSurface,
                border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    InputTypeBarRow("Text", 0.32f, "32%")
                    InputTypeBarRow("URL", 0.24f, "24%")
                    InputTypeBarRow("Document", 0.18f, "18%")
                    InputTypeBarRow("Image", 0.14f, "14%")
                    InputTypeBarRow("QR Code", 0.08f, "8%")
                    InputTypeBarRow("Audio", 0.06f, "6%")
                    InputTypeBarRow("Phone Number", 0.04f, "4%")
                }
            }

            Spacer(modifier = Modifier.height(30.dp))
        }
    }
}

@Composable
fun StatCardPill(title: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Surface(
        modifier = modifier.height(64.dp),
        shape = RoundedCornerShape(10.dp),
        color = DarkSurface,
        border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(horizontal = 6.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(value, fontSize = 17.sp, fontWeight = FontWeight.Black, color = color)
            Spacer(modifier = Modifier.height(2.dp))
            Text(title, fontSize = 9.sp, fontWeight = FontWeight.Medium, color = TextMuted, textAlign = TextAlign.Center)
        }
    }
}

@Composable
fun DonutLegendItem(color: Color, label: String, percentage: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Box(
            modifier = Modifier
                .size(10.dp)
                .background(color, CircleShape)
        )
        Text(label, fontSize = 12.sp, color = TextPrimary, fontWeight = FontWeight.Medium, modifier = Modifier.width(76.dp))
        Text(percentage, fontSize = 12.sp, color = TextSecondary, fontWeight = FontWeight.Bold)
    }
}

@Composable
fun InputTypeBarRow(name: String, fraction: Float, percentage: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = name,
            fontSize = 11.sp,
            color = TextPrimary,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.width(88.dp)
        )

        Box(
            modifier = Modifier
                .weight(1f)
                .height(6.dp)
                .clip(RoundedCornerShape(3.dp))
                .background(DarkSurfaceVariant)
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction.coerceIn(0.02f, 1.0f))
                    .height(6.dp)
                    .clip(RoundedCornerShape(3.dp))
                    .background(AccentBlue)
            )
        }

        Spacer(modifier = Modifier.width(12.dp))

        Text(
            text = percentage,
            fontSize = 10.sp,
            color = TextMuted,
            modifier = Modifier.width(28.dp),
            textAlign = TextAlign.End
        )
    }
}
