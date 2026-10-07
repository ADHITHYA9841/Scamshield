# ScamShield Evaluation Dataset Specifications

## 1. Dataset Overview
- **Total Instances**: 350 curated, synthetic samples.
- **Formats Available**: JSON (`dataset/benchmark.json`) and CSV (`dataset/benchmark.csv`).
- **Privacy Guarantee**: 100% synthetic data generated based on reported real-world modus operandi; zero PII or real victim records are included.

---

## 2. Category Distribution

| Category | Samples | Languages | Description |
| :--- | :---: | :--- | :--- |
| **KYC & Account Suspension** | 50 | EN, TA, HI, Mixed | Demands immediate action to prevent account/SIM deactivation; requests OTP or credentials. |
| **UPI & Payment Manipulation** | 50 | EN, TA, HI, Mixed, QR | Reverse-payment fraud, fake cashbacks, KBC lottery claims, fake advance fee payments. |
| **Delivery & Courier Phishing** | 50 | EN, TA, HI, Mixed | Impersonates India Post, FedEx, DHL, or customs officers threatening "digital arrest". |
| **Job & Investment Scams** | 50 | EN, TA, HI, Mixed | Fake work-from-home, rating YouTube videos, high-yield crypto schemes. |
| **Utility Disconnection** | 30 | EN, TA, HI, Mixed | Threatens power cut / electricity cutoff tonight if unverified payment is not made immediately. |
| **Malicious URLs & SSRF** | 30 | EN | Typosquatting lookalikes, Punycode homoglyphs, IP URLs, private IP / cloud metadata SSRF probes. |
| **Safe Control Group** | 90 | EN, TA, HI, Mixed | Legitimate bank debits, genuine Swiggy/Zomato OTPs, college invites, official bank portals. |

---

## 3. Schema Definition
Each sample follows this JSON schema:
```json
{
  "id": "SCAM_KYC_001",
  "input": "Dear Customer, Your SBI account KYC has expired. Update immediately: http://sbi-kyc-update.xyz/login",
  "input_type": "text",
  "language": "en",
  "label": "scam",
  "scam_type": "KYC Fraud",
  "source": "synthetic"
}
```
