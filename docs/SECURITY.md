# ScamShield Security Policy & Threat Mitigation

## 1. Threat Model & STRIDE Analysis

| STRIDE Category | Potential Threat | ScamShield Countermeasure |
| :--- | :--- | :--- |
| **Spoofing** | Fraudsters impersonating SBI, Police, or Courier | Multi-lingual rule signatures, brand lookalike engine, and E.164 phone country code correlation. |
| **Tampering** | Adversarial prompt injection trying to override classification | Input treated strictly as passive data; lexical injection filtering; Pydantic schema validation; LLM does not control final verdict. |
| **Repudiation** | Denying fraudulent UPI payment traps | Forensics engine stores exact parsed parameter values (`pa`, `pn`, `tn`, `am`) and highlights misleading keywords. |
| **Information Disclosure** | Data leakage through central databases or file uploads | Strictly single-user architecture; immediate disk unlinking of uploaded files; masking of Aadhaar/card/phone numbers in exported reports. |
| **Denial of Service** | Oversized file uploads or recursive zip bombs | Strict 10MB upload limit, MIME verification, and parser timeouts. |
| **Elevation of Privilege** | Server-Side Request Forgery (SSRF) to cloud metadata | Network pre-validation blocking loopback, private IPv4/IPv6, and `169.254.169.254`. |

---

## 2. Server-Side Request Forgery (SSRF) Defense

ScamShield implements a non-bypassable pre-flight network gatekeeper:
```python
BLOCKED_NETWORKS = [
    "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7", "fe80::/10"
]
```
Before any outgoing HTTP call is made, DNS resolution extracts all IP addresses and checks them against these CIDR ranges. Any attempt to reach AWS/GCP/Azure metadata services (`169.254.169.254`) or local services (`127.0.0.1:8000`) is immediately terminated and flagged.

---

## 3. Safe File Sandboxing

Uploaded files (PDF, DOCX, TXT, EML, HTML, Images) are handled under a zero-trust policy:
- **No Code Execution**: Embedded JavaScript in PDFs, VBA macros in DOCX documents, and `<script>`/`<iframe>` tags in HTML are stripped or ignored by headless document parsers.
- **Immediate Automatic Deletion**: Files are written to a temporary location, parsed into memory, and deleted within a `finally:` block. Raw binary uploads are never preserved.
