package org.scamshield.app.presentation.analyze

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.scamshield.app.core.theme.*

data class InputTypeItem(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val onClick: () -> Unit
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalyzeContentScreen(
    onNavigateBack: () -> Unit,
    onSelectText: () -> Unit,
    onSelectUrl: () -> Unit,
    onSelectDocument: () -> Unit,
    onSelectImage: () -> Unit,
    onSelectQr: () -> Unit,
    onSelectVoice: () -> Unit,
    onSelectPhone: () -> Unit
) {
    val items = listOf(
        InputTypeItem(
            title = "Text / Message",
            subtitle = "Paste suspicious text or message",
            icon = Icons.Default.Description,
            onClick = onSelectText
        ),
        InputTypeItem(
            title = "URL / Link",
            subtitle = "Enter a website link",
            icon = Icons.Default.Link,
            onClick = onSelectUrl
        ),
        InputTypeItem(
            title = "Document",
            subtitle = "PDF, DOCX, TXT, EML, HTML",
            icon = Icons.Default.InsertDriveFile,
            onClick = onSelectDocument
        ),
        InputTypeItem(
            title = "Image / Screenshot",
            subtitle = "Upload from gallery or camera",
            icon = Icons.Default.Image,
            onClick = onSelectImage
        ),
        InputTypeItem(
            title = "QR Code",
            subtitle = "Scan or upload QR code",
            icon = Icons.Default.QrCode,
            onClick = onSelectQr
        ),
        InputTypeItem(
            title = "Voice / Audio",
            subtitle = "Record or upload audio",
            icon = Icons.Default.Mic,
            onClick = onSelectVoice
        ),
        InputTypeItem(
            title = "Phone Number",
            subtitle = "Enter a phone number",
            icon = Icons.Default.Phone,
            onClick = onSelectPhone
        )
    )

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = TextPrimary)
                    }
                },
                title = {
                    Column {
                        Text(
                            text = "Analyze Content",
                            fontWeight = FontWeight.Bold,
                            fontSize = 18.sp,
                            color = TextPrimary
                        )
                        Text(
                            text = "Choose what you want to analyze",
                            fontSize = 11.sp,
                            color = TextSecondary
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
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Spacer(modifier = Modifier.height(6.dp))

            items.forEach { item ->
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .clickable(onClick = item.onClick),
                    shape = RoundedCornerShape(12.dp),
                    color = DarkSurface,
                    border = androidx.compose.foundation.BorderStroke(1.dp, BorderColor)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Box(
                            modifier = Modifier
                                .size(40.dp)
                                .background(DarkSurfaceVariant, RoundedCornerShape(10.dp))
                                .border(1.dp, BorderColor, RoundedCornerShape(10.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(
                                imageVector = item.icon,
                                contentDescription = null,
                                tint = AccentCyan,
                                modifier = Modifier.size(20.dp)
                            )
                        }

                        Spacer(modifier = Modifier.width(14.dp))

                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = item.title,
                                fontSize = 14.sp,
                                fontWeight = FontWeight.SemiBold,
                                color = TextPrimary
                            )
                            Spacer(modifier = Modifier.height(2.dp))
                            Text(
                                text = item.subtitle,
                                fontSize = 11.sp,
                                color = TextSecondary
                            )
                        }

                        Icon(
                            imageVector = Icons.Default.ChevronRight,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            Spacer(modifier = Modifier.height(20.dp))
        }
    }
}
