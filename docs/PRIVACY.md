# ScamShield Privacy Architecture

## Single-User & Zero-Telemetry Guarantee

ScamShield is engineered from the ground up to protect user privacy:

1. **No Centralized Cloud Database**:
   Unlike commercial anti-phishing services that aggregate millions of users' messages into a central server, ScamShield is completely self-hostable. Your scan history lives solely on your Android device (Room database) or your private backend instance.

2. **No Passive Background Scraping**:
   - The Android app does **not** read SMS or monitor incoming WhatsApp messages continuously in the background. Analysis is only performed upon explicit user action or when content is explicitly shared via the Android Share Sheet.
   - The Chrome extension does **not** monitor your browsing history or keystrokes on banking pages. It only inspects content when you click "Analyze Current Page", "Analyze Current URL", or right-click selected text.

3. **Ephemeral File Processing**:
   When you upload a PDF, screenshot, or DOCX document:
   - The file is validated in memory or temporary storage.
   - Forensic features are extracted.
   - The file is deleted from the disk immediately before the response is returned.

4. **Sensitive Information Masking**:
   When generating formal PDF investigation reports, ScamShield automatically masks personal identification numbers:
   - Phone numbers: `+91 98****1234`
   - Credit / Debit cards: `XXXX-XXXX-XXXX-1234`
   - Aadhaar numbers: `XXXX-XXXX-1234`
