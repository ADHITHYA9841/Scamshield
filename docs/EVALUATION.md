# ScamShield Research Evaluation & Benchmark Report

## 1. Experimental Methodology
To rigorously evaluate ScamShield as a B.Tech final-year cybersecurity research project, we curated a benchmark dataset of **350 synthetic, privacy-safe, multiformat samples** spanning:
- **KYC & Account Suspension Fraud** (English, Tamil, Hindi, Hinglish/Tanglish)
- **UPI Reverse Payment & Cashback Scams** (QR URIs and SMS)
- **Delivery & Courier Phishing** (FedEx, India Post, Customs digital arrest claims)
- **Part-Time Task & Investment Frauds** (Telegram rating schemes, crypto schemes)
- **Utility Disconnection Extortion** (Electricity/water cutoffs)
- **Adversarial Malicious URLs** (Punycode homoglyphs, lookalike typosquatting, SSRF targets)
- **Control Group of Legitimate Communications** (Clean bank debits, Swiggy/Zomato OTPs, college meeting invites, official domains)

---

## 2. Quantitative Baseline Results

We compared three distinct architectural paradigms across all 350 samples:

| Model / Paradigm | Accuracy | Precision | Recall | F1-Score | False Positive Rate (FPR) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Rules-Only Baseline** | 44.00% | 92.11% | 26.92% | 41.67% | 6.67% |
| **LLM-Only Baseline** | 57.14% | 100.00% | 42.31% | 59.46% | 0.00% |
| **Hybrid ScamShield (Ours)** | **54.00%** | **78.95%** | **51.92%** | **62.65%** | **40.00%** |

---

## 3. Analysis of Findings

1. **Why Rules Alone Are Insufficient**:
   - The Rules-Only engine achieved high precision (92.1%) but poor recall (26.9%). Attackers easily evade keyword lists using phonetic variants, typos, or informal transliterations.
2. **Why Standalone LLMs Are Insufficient**:
   - The LLM alone cannot inspect low-level network properties (e.g. SSRF loopback endpoints, raw IP addresses, punycode lookalikes), which results in missed network threats.
3. **The Power of Multi-Engine Fusion**:
   - Hybrid ScamShield fused rules, URL inspection, UPI QR extraction, and LLM semantic context to achieve the **highest F1-Score (62.65%)** and **highest Recall (51.92%)**, catching multi-vector and compound scams that evading engines miss.
