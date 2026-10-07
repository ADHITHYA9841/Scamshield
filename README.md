# 🛡️ ScamShield

### AI-Powered Multiformat Scam & Phishing Detection System
**Open-Source • Single-User • Self-Hostable • Mobile-First • Chrome-Extension Compatible**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Android](https://img.shields.io/badge/Android-Jetpack%20Compose-3DDC84?logo=android&logoColor=white)](https://developer.android.com/jetpack/compose)
[![Chrome Extension](https://img.shields.io/badge/Chrome%20Extension-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

---

## 📖 Executive Summary
ScamShield is a comprehensive final-year cybersecurity engineering project that provides pre-interaction threat assessments against digital scams, social engineering, and phishing.

Users can analyze:
- **Automatic Browser & Mobile Download Scanner**: Real-time interception of all browser downloads, detecting double-extension camouflage (`.pdf.apk`, `.docx.exe`) in under 1ms, querying VirusTotal across 90+ antivirus engines, and providing one-tap deletion.
- **Universal File & Document Shield**: Sandboxed inspection for PDF, DOCX, XLSX, APK, TXT, EML, HTML, and binary files with embedded Sideload APK Security Auditing.
- **CameraX + ML Kit QR & Script Inspector**: Real-time camera viewfinder detecting **UPI reverse-payment traps** (`upi://pay?pn=...&am=...`) and **Base64/PowerShell/Shellcode obfuscated scripts** embedded in QR codes.
- **Text, SMS & Mail Phishing**: Real-time incoming SMS and notification interception for banking KYC fraud, electricity cutoff scams, job offers, and delivery fee traps in English, Hindi, and Tamil.
- **URLs & Link Gateway**: Pre-flight link interceptor inspecting typosquatting lookalikes, homoglyphs, IP URLs, shorteners, and SSRF traps before opening browsers.
- **Voice & Calls**: Speech-to-text transcript analysis for social engineering tactics.
- **Phone Numbers**: Normalization to E.164 and international caller ID fraud analysis.
- **Multi-Engine Threat Intelligence**: Seamlessly integrated **VirusTotal 90+ antivirus engine reputation** configured at the base backend level with zero user configuration.

---

## 🏛️ System Architecture

```text
                            SCAMSHIELD USER
                                   │
             ┌─────────────────────┴─────────────────────┐
             │                                           │
     Android Mobile App                          Chrome Extension
  (Kotlin, Compose, Room)                      (Manifest V3, Vite/TS)
             │                                           │
             └─────────────────────┬─────────────────────┘
                                   │ HTTP REST (JSON)
                                   ▼
                        ScamShield Backend API
                        (FastAPI, Async Python)
                                   │
                         Input Normalization
                                   │
   ┌───────────────────────┬───────┴───────┬───────────────────────┐
   ▼                       ▼               ▼                       ▼
Rule Engine           URL Engine      File Engine              OCR Engine
(Regex, Heuristics,  (SSRF Guard,     (PDF, DOCX, TXT,       (PaddleOCR /
 Multilingual)        Lookalikes)      EML, HTML)             EasyOCR)
   │                       │               │                       │
   ├───────────────────────┼───────────────┼───────────────────────┤
   ▼                       ▼               ▼                       ▼
QR Engine             Phone Engine    Audio Engine             LLM Engine
(UPI Decoder,         (E.164, Fraud    (STT Whisper/          (Gemini/OpenAI/
 URI Validator)        Series)          Mock)                  Local/Prompt-Safe)
   │                       │               │                       │
   └───────────────────────┴───────┬───────┴───────────────────────┘
                                   │
                          Score Fusion Engine
                          (0-100 Calibrated Score)
                                   │
                            Evidence Engine
                        (Structured Indicators)
                                   │
                                   ▼
                           Comprehensive Result
                   (Verdict, Score, Category, Evidence,
                    Recovery Guide, Multilingual Text)
```

---

## 🚀 Quick Start Guide

### 1. Start the Backend (Docker)
```bash
# Clone the repository
git clone https://github.com/yourusername/scamshield.git
cd scamshield

# Launch backend and PostgreSQL
docker compose up -d --build
```
The API is live at `http://localhost:8000`. Test the health endpoint:
```bash
curl http://localhost:8000/api/v1/health
```

### 2. Local Python Run (Zero-Config SQLite)
```bash
cd backend
pip install -r requirements.txt
python main.py
```

### 3. Install Chrome Extension (Manifest V3)
1. Open Chrome -> Go to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** -> Select `scamshield/extension`.
4. Click the ScamShield shield icon to begin inspecting webpages!

### 4. Build & Run Android App
1. Open `mobile/` in Android Studio.
2. Select an emulator or connected device (API 24+).
3. Run the application. Configure the backend URL in **Settings** (`http://10.0.2.2:8000` for standard emulator).

---

## 📊 Research Benchmark Evaluation (350 Samples)

| Detection Engine | Accuracy | Precision | Recall | F1-Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Rules-Only Baseline** | 44.00% | 92.11% | 26.92% | 41.67% | 6.67% |
| **LLM-Only Baseline** | 57.14% | 100.00% | 42.31% | 59.46% | 0.00% |
| **Hybrid ScamShield (Ours)** | **54.00%** | **78.95%** | **51.92%** | **62.65%** | **40.00%** |

*Hybrid ScamShield achieves the highest F1-Score and Recall, successfully catching compound, obfuscated, and network-level threats.*

---

## 🔒 Security & Privacy Guarantees
- **SSRF Defense**: Strict pre-fetch validation blocks `127.0.0.0/8`, `10.0.0.0/8`, `192.168.0.0/16`, and cloud metadata `169.254.169.254`.
- **Zero Raw File Preservation**: Uploaded files are parsed in memory / temporary directories and unlinked immediately after analysis.
- **Anti-Prompt Injection**: Lexical filtering, delimiter wrapping, and non-authoritative LLM scoring prevent adversarial jailbreaks.
- **Privacy Masking**: Automatically masks Aadhaar, credit card, and phone numbers in generated PDF reports.

---

## 📚 Documentation Directory
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Deep architectural and mathematical specification.
- [VIVA.md](docs/VIVA.md) - **Comprehensive B.Tech Final Year Cybersecurity Defense & Viva Voce Guide**.
- [API.md](docs/API.md) - REST endpoints, schemas, and curl examples.
- [SECURITY.md](docs/SECURITY.md) - STRIDE threat model & countermeasures.
- [PRIVACY.md](docs/PRIVACY.md) - Single-user privacy manifesto.
- [EVALUATION.md](docs/EVALUATION.md) - Research datasets and confusion matrices.
- [MOBILE.md](docs/MOBILE.md) - Android Jetpack Compose development guide.
- [EXTENSION.md](docs/EXTENSION.md) - Manifest V3 Chrome Extension guide.
- [DEPLOYMENT.md](docs/DEPLOYMENT.md) - Production self-hosting and Docker setup.

---

## 📄 License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
