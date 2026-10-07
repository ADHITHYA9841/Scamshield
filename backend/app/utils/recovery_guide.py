from typing import Dict, Any, List
from app.models.schemas import RecoveryGuideResponse


RECOVERY_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "clicked_link": {
        "urgency": "HIGH",
        "immediate_actions": [
            "Disconnect your phone/computer from Wi-Fi and mobile data immediately.",
            "Close all open browser tabs and clear browser history, cookies, and cached data.",
            "Check your 'Downloads' folder and delete any files that were downloaded automatically.",
            "Do NOT enter any passwords, PINs, or personal details if the page asks."
        ],
        "secondary_actions": [
            "Scan your device with a trusted antivirus or Google Play Protect.",
            "Update your browser and operating system to the latest security patch.",
            "Monitor your accounts for suspicious login notifications."
        ],
        "helplines": [
            {"name": "National Cyber Crime Helpline (India)", "contact": "1930", "web": "https://cybercrime.gov.in"},
            {"name": "RBI Sachet Portal", "contact": "sachet.rbi.org.in", "web": "https://sachet.rbi.org.in"}
        ],
        "prevention_tips": [
            "Always inspect URLs before tapping, especially those received via SMS, WhatsApp, or Telegram.",
            "Enable browser phishing protection (Safe Browsing) in your browser settings."
        ]
    },
    "entered_otp": {
        "urgency": "CRITICAL",
        "immediate_actions": [
            "IMMEDIATELY contact your bank's fraud helpline or use net banking / mobile app to FREEZE your debit/credit card and internet banking.",
            "Change your net banking login and transaction passwords immediately from a secure device.",
            "If UPI PIN was compromised, open your UPI app (GPay/PhonePe/Paytm) and reset your UPI PIN right now."
        ],
        "secondary_actions": [
            "Call the National Cyber Crime Helpline at 1930 within the 'Golden Hour' to request payment freeze.",
            "File a formal cyber crime complaint with transaction screenshots at cybercrime.gov.in.",
            "Review your recent transaction statement and notify the bank of any unauthorized debits."
        ],
        "helplines": [
            {"name": "National Cyber Crime Reporting Portal", "contact": "1930", "web": "https://cybercrime.gov.in"},
            {"name": "Emergency Financial Fraud Reporting", "contact": "1930", "web": "Toll-Free 24x7"}
        ],
        "prevention_tips": [
            "Bank employees and customer care representatives will NEVER ask you for an OTP or PIN.",
            "Remember that OTP is required only to SEND money, never to RECEIVE money or cashback."
        ]
    },
    "transferred_money": {
        "urgency": "CRITICAL",
        "immediate_actions": [
            "Call 1930 (National Cyber Crime Helpline) IMMEDIATELY. Reporting within 2-3 hours increases chances of freezing the scammer's bank account before withdrawal.",
            "Save the Transaction Reference (UTR / UPI Ref Number / Bank IMPS Reference) and payment screenshots.",
            "Inform your remitting bank and request them to recall the transaction / place a lien on the beneficiary account."
        ],
        "secondary_actions": [
            "File a formal online FIR at cybercrime.gov.in and obtain an Acknowledgement Number.",
            "Submit a written complaint along with the cyber complaint acknowledgement to your home bank branch manager."
        ],
        "helplines": [
            {"name": "National Cyber Crime Helpline (Golden Hour Hotline)", "contact": "1930", "web": "https://cybercrime.gov.in"},
            {"name": "Banking Ombudsman (RBI)", "contact": "14448", "web": "https://cms.rbi.org.in"}
        ],
        "prevention_tips": [
            "Never scan a QR code or enter a UPI PIN expecting to receive money.",
            "Beware of investment schemes, part-time video rating tasks, or lotteries promising guaranteed returns."
        ]
    },
    "downloaded_file": {
        "urgency": "HIGH",
        "immediate_actions": [
            "Do NOT open, tap, or install the downloaded file.",
            "Delete the file immediately from your file manager / downloads directory.",
            "If an APK was installed, disconnect internet (turn on Airplane mode) immediately."
        ],
        "secondary_actions": [
            "Boot device into Safe Mode to uninstall suspicious apps that hide their launcher icons.",
            "Navigate to Settings -> Apps -> Special App Access -> Device Admin Apps and disable unknown administrators.",
            "Revoke Accessibility and Notification permissions for suspicious apps.",
            "If remote access apps (e.g. AnyDesk, TeamViewer, RustDesk) were installed by the scammer, uninstall them immediately."
        ],
        "helplines": [
            {"name": "National Cyber Crime Portal", "contact": "1930", "web": "https://cybercrime.gov.in"}
        ],
        "prevention_tips": [
            "Never install APK files sent over WhatsApp or downloaded from unofficial websites.",
            "Keep Google Play Protect turned on at all times."
        ]
    },
    "shared_id": {
        "urgency": "MEDIUM",
        "immediate_actions": [
            "Log in to the official UIDAI portal (myaadhaar.uidai.gov.in) and LOCK your Aadhaar Biometrics immediately.",
            "Check your Aadhaar authentication history on UIDAI for any unauthorized authentication requests."
        ],
        "secondary_actions": [
            "Check your CIBIL / Experian credit report to verify that no unauthorized loans or credit cards have been applied in your name.",
            "File a General Diary (GD) / Police Complaint regarding identity document loss/compromise to prevent liability in case of misuse."
        ],
        "helplines": [
            {"name": "UIDAI Aadhaar Helpline", "contact": "1947", "web": "https://uidai.gov.in"},
            {"name": "National Cyber Crime Portal", "contact": "1930", "web": "https://cybercrime.gov.in"}
        ],
        "prevention_tips": [
            "Use Masked Aadhaar (showing only last 4 digits) whenever sharing identity proof.",
            "Never share clear photocopies of PAN, Aadhaar, or Passport with unverified agents."
        ]
    }
}


def get_recovery_guide(incident_type: str) -> RecoveryGuideResponse:
    """Returns structured, safe recovery instructions for incident response."""
    key = incident_type.lower().strip()
    data = RECOVERY_KNOWLEDGE_BASE.get(key, RECOVERY_KNOWLEDGE_BASE["clicked_link"])

    return RecoveryGuideResponse(
        incident_type=key,
        urgency_level=data["urgency"],
        immediate_actions=data["immediate_actions"],
        secondary_actions=data["secondary_actions"],
        helplines=data["helplines"],
        prevention_tips=data["prevention_tips"],
        disclaimer="These guidelines provide immediate harm-reduction steps. Always consult with your official bank and local law enforcement for legal and financial recovery."
    )
