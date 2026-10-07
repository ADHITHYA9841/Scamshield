# ScamShield REST API Documentation

Base URL: `http://localhost:8000/api/v1`

Interactive Swagger Docs: `http://localhost:8000/docs`

---

## Endpoints

### 1. Analyze Text
**`POST /api/v1/analyze/text`**

Request:
```json
{
  "text": "Your SBI bank account is suspended. Immediately share your OTP to prevent legal arrest: http://sbi-unblock.xyz",
  "language": "auto"
}
```

Response (`200 OK`):
```json
{
  "scan_id": "8e3b4a21-912f-48d9-a78b-d54b872c91a0",
  "timestamp": "2026-09-21T13:30:00Z",
  "input_type": "text",
  "verdict": "SCAM",
  "risk_score": 92,
  "confidence": 0.95,
  "scam_type": "KYC & Account Suspension Fraud",
  "language": "en",
  "evidence": [
    {
      "type": "threats",
      "severity": "critical",
      "source": "rules",
      "description": "Coercive threat or intimidation tactic",
      "evidence": "account is suspended"
    },
    {
      "type": "credential_harvesting",
      "severity": "critical",
      "source": "rules",
      "description": "Request for confidential credential or OTP",
      "evidence": "share your OTP"
    }
  ],
  "engine_results": {
    "rule_score": 90.0,
    "url_score": 65.0,
    "llm_score": 95.0
  },
  "explanation": "This content exhibits strong indicators of KYC & Account Suspension Fraud.",
  "recommended_actions": [
    "Do NOT click any attached links.",
    "Never share your OTP or bank password.",
    "Report financial fraud immediately to National Cyber Crime helpline 1930."
  ],
  "limitations": [
    "ScamShield provides an automated risk assessment and cannot guarantee absolute safety."
  ],
  "multilingual_explanations": {
    "en": "This content exhibits strong indicators of KYC fraud.",
    "ta": "இதில் KYC மோசடி தொடர்பான ஆபத்தான அறிகுறிகள் உள்ளன.",
    "hi": "इस संदेश में केवाईसी धोखाधड़ी के गंभीर लक्षण हैं।"
  }
}
```

---

### 2. Analyze URL
**`POST /api/v1/analyze/url`**

Request:
```json
{
  "url": "https://onlinesbi.verification-portal.top/netbanking",
  "visible_text": "https://www.onlinesbi.sbi"
}
```

Response (`200 OK`):
```json
{
  "scan_id": "7821-4921-...",
  "verdict": "SCAM",
  "risk_score": 95,
  "scam_type": "Phishing / Malicious Domain",
  "evidence": [
    {
      "type": "brand_typosquatting",
      "severity": "critical",
      "source": "url",
      "description": "Suspected brand impersonation targeting 'SBI'. Not an official domain.",
      "evidence": "onlinesbi.verification-portal.top"
    },
    {
      "type": "hyperlink_mismatch",
      "severity": "critical",
      "source": "url",
      "description": "Displayed link text does NOT match actual destination.",
      "evidence": "Display: https://www.onlinesbi.sbi -> Destination: https://onlinesbi.verification-portal.top/netbanking"
    }
  ]
}
```

---

### 3. Analyze QR Code & UPI Payload
**`POST /api/v1/analyze/qr`**

Request:
```json
{
  "qr_content": "upi://pay?pa=refund-desk@ybl&pn=SBI+Refund&am=5000&tn=Enter+PIN+to+receive+cashback"
}
```

Response (`200 OK`):
```json
{
  "verdict": "SCAM",
  "risk_score": 90,
  "scam_type": "UPI Payment Fraud",
  "evidence": [
    {
      "type": "upi_reverse_payment_scam",
      "severity": "critical",
      "source": "qr",
      "description": "UPI QR claims to 'credit' or 'refund' money. UPI QR codes CANNOT send you money. Scanning this will DEDUCT funds from your bank account!",
      "evidence": "Note: 'Enter PIN to receive cashback', Payee: 'SBI Refund'"
    }
  ]
}
```

---

### 4. Incident Recovery Guide
**`POST /api/v1/recovery-guide`**

Request:
```json
{
  "incident_type": "transferred_money"
}
```

Response (`200 OK`):
```json
{
  "incident_type": "transferred_money",
  "urgency_level": "CRITICAL",
  "immediate_actions": [
    "Call 1930 (National Cyber Crime Helpline) IMMEDIATELY.",
    "Save the Transaction Reference (UTR / UPI Ref Number).",
    "Inform your remitting bank to recall the transaction."
  ],
  "helplines": [
    {"name": "National Cyber Crime Helpline", "contact": "1930", "web": "https://cybercrime.gov.in"}
  ]
}
```

---

### 5. Health & Readiness
- `GET /api/v1/health` -> `{"status": "healthy", "service": "ScamShield", "version": "1.0.0"}`
- `GET /api/v1/ready` -> `{"status": "ready", "database": "connected"}`
