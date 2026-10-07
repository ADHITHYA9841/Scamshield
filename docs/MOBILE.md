# ScamShield Android Mobile Application Guide

## 1. Stack & Architecture
- **Language**: Kotlin 1.9+ (Strict Null-Safety)
- **UI Framework**: Jetpack Compose with Material 3 Design
- **Architecture**: Clean Architecture & MVVM (Presentation, Domain, Data, Core)
- **Networking**: Retrofit 2.10 + OkHttp 4.12
- **Local Storage**: Room Database 2.6
- **Coroutines & Flow**: Asynchronous background operations & StateFlow UI binding

---

## 2. Screens & Features
1. **Home Screen (`HomeScreen.kt`)**:
   - "Check Before You Click" header
   - Quick text/message paste and analyze card
   - Multiformat scanner grid: Analyze Link, Scan QR, Upload File, Voice Analysis, Check Phone, Screenshot OCR
   - Golden Rule safety tip banner
2. **Result Screen (`ResultScreen.kt`)**:
   - Circular calibrated risk meter (0–100)
   - Color-coded verdict badge (SAFE, SUSPICIOUS, SCAM)
   - **Live Multi-Engine Threat Intelligence Indicator**: Shows real-time vendor verification (`🛡️ VirusTotal Clean: 70+ AV Engines Verified`, `🚨 VirusTotal: Threat Flagged by Multi-Vendor Engines`, or `🛡️ Verified Official Authority Domain`)
   - Granular forensic evidence list
   - Recommended actions checklist
   - Direct launcher for Incident Recovery Assistant
3. **QR & UPI Scanner (`QrScannerScreen.kt`)**:
   - Decodes UPI URIs (`upi://pay?pa=...&pn=...&am=...&tn=...`)
   - Highlights reverse payment fraud traps
   - Bold warning: *"Entering your UPI PIN will DEDUCT funds, never credit!"*
   - **Offline Configuration QR Handoff**: Automatically imports backend URL and VirusTotal API key by scanning the Chrome Extension QR code (`scamshield://config?backend=...&vt=...`)
4. **Voice Screen (`VoiceScreen.kt`)**:
   - Audio recording interface with speech-to-text transcription
   - Social engineering call analysis
5. **History Screen (`HistoryScreen.kt`)**:
   - Room-backed local scan records
   - Filtering by verdict (All, Scam, Suspicious, Safe)
   - Search & swipe-to-delete
6. **Recovery Assistant (`RecoveryScreen.kt`)**:
   - Immediate containment checklists for compromised credentials, links, or payments
   - Emergency contacts: 1930 Cyber Crime Portal, RBI Sachet
7. **Settings Screen (`SettingsScreen.kt`)**:
   - Configurable self-hosted backend URL (`http://10.0.2.2:8000` for emulator or custom VPS)
   - **VirusTotal Multi-Engine Threat Intelligence**: Direct API key input (`virustotalApiKey`) persisted via SharedPreferences and automatically injected into OkHttp headers (`X-VirusTotal-Key`)
   - Test connection probe
   - Multilingual selection (English, Tamil, Hindi)

---

## 3. Building & Running in Android Studio

1. Open Android Studio -> Select **Open an existing project** -> Navigate to `mobile/`.
2. Ensure Android SDK 34 is installed in your SDK Manager.
3. In Android Studio, select **Build -> Make Project** or run:
   ```bash
   cd mobile
   ./gradlew assembleDebug
   ```
4. Deploy the APK to an Android device or emulator.
5. In the app, open **Settings**, verify the Backend URL (`http://10.0.2.2:8000` for standard emulator), and tap **Test Connection**.
