# ScamShield Chrome Extension Guide (Manifest V3)

## 1. Overview
The ScamShield Chrome Extension integrates real-time phishing and scam detection directly into your Chromium browser (Google Chrome, Brave, Microsoft Edge) while upholding strict user privacy.

## 2. Installation Instructions (Developer Mode)
1. Open Google Chrome (or any Chromium browser).
2. Navigate to `chrome://extensions/`.
3. In the top-right corner, enable the **Developer mode** toggle.
4. Click the **Load unpacked** button in the top-left corner.
5. Select the `scamshield/extension` directory from your filesystem.
6. ScamShield will appear in your extensions toolbar with the blue shield emblem!

---

## 3. Features & Usage
- **Analyze Current Tab**:
  Click the ScamShield toolbar icon and select **Analyze Page** or **Analyze URL** to initiate a forensic scan.
- **Context Menu Inspection**:
  - Highlight suspicious text on any webpage -> Right-click -> Select **🛡️ Analyze Selected Text with ScamShield**.
  - Right-click any hyperlink -> Select **🔗 Inspect Link with ScamShield**.
- **Automatic Download Scanning & Threat Containment**:
  Every file download initiated in Chrome is intercepted in real-time before completion:
  - **Double-Extension Forensics**: Flags deceptive files like `invoice.pdf.exe` or `aadhaar_update.pdf.apk`.
  - **Lookalike Host Correlation**: Detects APKs, executables, or installers hosted on typosquatted or unverified domains.
  - **Automatic Download Pause**: Automatically halts downloading of high-risk files.
  - **Interactive Action Notifications**: Displays a desktop alert with single-click **"🚫 Cancel & Delete"** and **"⚠️ Keep / Resume"** options.
- **Mobile QR Handoff**:
  Open the extension settings (or right-click icon -> Options) to view your offline QR handoff code. Scan with your ScamShield Android Mobile App to transfer the investigation without routing through third-party servers.
- **Backend Configuration**:
  Change the Backend API URL to your self-hosted instance (e.g. `http://localhost:8000` or `https://my-scamshield.example.com`).
