# ScamShield System Architecture

## 1. Architectural Philosophy
ScamShield is designed around four foundational pillars:
1. **Privacy-First & Single-User**: No centralized multi-tenant database, no surveillance telemetry. Each user self-hosts their backend or runs it locally.
2. **Hybrid Detection**: Combines deterministic rules, deep network URL intelligence, safe document parsing, OCR, UPI QR breakdown, and semantic LLM reasoning.
3. **Multi-Platform Ecosystem**: Android Mobile App (primary client) + Chromium Extension (Manifest V3) connected to a unified FastAPI engine.
4. **Honest Explainability**: Outputs calibrated 0–100 ScamShield Risk Scores, fine-grained forensic evidence items, and non-absolute legal verdicts.

---

## 2. High-Level System Architecture

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

## 3. Component Breakdown

### A. Mobile Application (`mobile/`)
- **Framework**: Modern Android with Jetpack Compose & Material 3.
- **Architecture**: Clean Architecture (Presentation, Domain, Data, Core).
- **State Management**: Kotlin Coroutines & `StateFlow`.
- **Local Persistence**: Android Room database storing offline scan history, search indices, and user preferences.
- **System Integration**: Registered `ACTION_SEND` intent filter for the Android Share Sheet, enabling one-tap analysis from WhatsApp, Chrome, SMS, and Gallery.

### B. Chrome Extension (`extension/`)
- **Specification**: Strictly compliant with Google Chrome Manifest V3.
- **Permissions**: Minimal attack surface (`activeTab`, `storage`, `scripting`, `contextMenus`).
- **Functionality**:
  - Context menu analysis of highlighted text and hyperlinks.
  - One-click popup inspecting current tab URL, page metadata, and visible text.
  - Zero passive surveillance: only executes on explicit user command.
  - Local QR Handoff: Generates an offline SVG/Canvas QR code to transfer investigation to mobile without cloud telemetry.

### C. Backend API Service (`backend/`)
- **Framework**: FastAPI (async ASGI) on Python 3.11+.
- **Database**: PostgreSQL with SQLAlchemy ORM (and zero-config SQLite local dev fallback).
- **Security Guardrails**:
  - Pre-fetch SSRF network validation (blocks loopback, private IPv4/IPv6, and cloud metadata endpoints).
  - Sanitized file handling with immediate automatic deletion upon analysis completion.
  - Prompt injection defense layer detecting adversarial instruction overrides.

---

## 4. Calibrated Score Fusion Mathematics

The ScamShield Risk Score ($S_{final} \in [0, 100]$) is calculated as a weighted combination of specialized engine outputs, elevated by critical threat triggers:

$$S_{raw} = w_r \cdot S_{rules} + w_u \cdot S_{url} + w_l \cdot S_{llm} + w_x \cdot S_{aux}$$

Where weights dynamically adjust based on input type:
- **Text / Message**: $w_r = 0.45, w_l = 0.35, w_u = 0.20$
- **URL**: $w_u = 0.55, w_r = 0.20, w_l = 0.25$
- **QR / UPI**: $w_{qr} = 0.50, w_u = 0.25, w_r = 0.25$
- **Phone**: $w_p = 0.50, w_r = 0.30, w_l = 0.20$

### Critical Trigger Elevation:
If any critical indicator is detected (SSRF violation, OTP credential harvesting, brand typosquatting, or UPI reverse payment scam), the score is immediately elevated:
$$S_{final} = \max(S_{raw}, 80 + 5 \cdot N_{critical})$$

### Verdict Assignment:
- $0 \le S_{final} \le 29$: **SAFE** ("No significant scam indicators were detected.")
- $30 \le S_{final} \le 69$: **SUSPICIOUS** ("This content contains some indicators commonly associated with scams.")
- $70 \le S_{final} \le 100$: **SCAM** ("This content contains multiple indicators commonly associated with scams.")
