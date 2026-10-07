import json
import csv
import os
from typing import List, Dict, Any

OUTPUT_JSON = os.path.join(os.path.dirname(__file__), "../../../dataset/benchmark.json")
OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "../../../dataset/benchmark.csv")


def generate_benchmark_dataset() -> List[Dict[str, Any]]:
    samples = []
    idx = 1

    # 1. KYC Scams (EN, TA, HI, Mixed) - 50 samples
    kyc_templates = [
        ("Dear Customer, Your SBI account KYC has expired. Update immediately to prevent account suspension: http://sbi-kyc-update.xyz/login", "text", "en", "scam", "KYC Fraud"),
        ("Urgent: Your HDFC Bank netbanking is blocked due to pending PAN update. Click here to verify OTP: http://hdfc-pan-verify.top", "text", "en", "scam", "KYC Fraud"),
        ("உங்கள் பாரத ஸ்டேட் வங்கி கணக்கு KYC முடிவடைந்தது. உடனே இந்த இணைப்பை கிளிக் செய்து OTP பகிரவும்.", "text", "ta", "scam", "KYC Fraud"),
        ("प्रिय ग्राहक, आपका बैंक खाता आज बंद हो जाएगा। तुरंत अपना पैन कार्ड और ओटीपी दर्ज करें: http://bank-update.click", "text", "hi", "scam", "KYC Fraud"),
        ("Your KYC expire aagum within 24 hours. Udane click panni OTP share pannunga.", "text", "mixed", "scam", "KYC Fraud"),
        ("Aapka bank account freeze ho jayega. Turant KYC update kare aur OTP bataye.", "text", "mixed", "scam", "KYC Fraud"),
        ("SIM card KYC incomplete. Telecom Department will deactivate your mobile number within 2 hours. Call 9876543210 immediately.", "text", "en", "scam", "KYC Fraud"),
        ("Aadhaar-PAN linking deadline today. Pay Rs 500 penalty and enter your card details: http://pan-aadhaar-link.top", "text", "en", "scam", "KYC Fraud"),
        ("ICICI Alert: Your credit card is temporarily restricted. Submit your CVV and OTP to restore access.", "text", "en", "scam", "KYC Fraud"),
        ("Warning: Bank account audit failed. Send your 6 digit UPI PIN to verify account ownership.", "text", "en", "scam", "KYC Fraud")
    ]
    for _ in range(5):
        for text, itype, lang, label, cat in kyc_templates:
            samples.append({
                "id": f"SCAM_KYC_{idx:03d}",
                "input": text if idx <= 10 else f"{text} (Ref #{idx*104})",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 2. UPI & Payment Manipulation Scams - 50 samples
    upi_templates = [
        ("upi://pay?pa=refund-agent@ybl&pn=SBI+Refund&am=5000&tn=Scan+and+enter+PIN+to+receive+Rs+5000+cashback", "qr", "en", "scam", "UPI Fraud"),
        ("You have won Rs 25,000 lottery from PhonePe! Scan this QR code and type your UPI PIN to claim money.", "text", "en", "scam", "UPI Fraud"),
        ("Google Pay Scratch Card: Rs 4,999 credited to your wallet. Click to accept and enter MPIN: http://gpay-reward.xyz", "text", "en", "scam", "UPI Fraud"),
        ("பரிசு விழுந்துள்ளது! உங்கள் வங்கிக் கணக்கில் ரூ 10000 பெற QR குறியீட்டை ஸ்கேன் செய்து பின் எண்ணை உள்ளிடவும்.", "text", "ta", "scam", "UPI Fraud"),
        ("बधाई हो! आपको 15,000 रुपये का कैशबैक मिला है। तुरंत प्राप्त करने के लिए अपना यूपीआई पिन दर्ज करें।", "text", "hi", "scam", "UPI Fraud"),
        ("Congratulations! You won KBC Kaun Banega Crorepati lucky draw of 25 Lakhs. Pay processing fee of Rs 2500 to release cheque.", "text", "en", "scam", "UPI Fraud"),
        ("OLX Buyer: I have sent advance payment of Rs 12,000 via QR code. Just scan it and approve transaction to receive funds.", "text", "en", "scam", "UPI Fraud"),
        ("Aapko 5000 cash prize mila hai. Udane paise receive karne ke liye UPI PIN enter kare.", "text", "mixed", "scam", "UPI Fraud"),
        ("upi://pay?pa=electricity-care@paytm&pn=Bijli+Office&am=1890&tn=Disconnection+fine+pay+now", "qr", "en", "scam", "UPI Fraud"),
        ("Payment failed. Transfer Rs 10 verification charge to activate your pending loan disbursement.", "text", "en", "scam", "UPI Fraud")
    ]
    for _ in range(5):
        for text, itype, lang, label, cat in upi_templates:
            samples.append({
                "id": f"SCAM_UPI_{idx:03d}",
                "input": text if idx <= 60 else f"{text} (TrxID: {idx*71})",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 3. Delivery & Courier Phishing - 50 samples
    courier_templates = [
        ("India Post: Your package could not be delivered due to incorrect street number. Update address here within 12 hours: http://indiapost-parcel.top/track", "text", "en", "scam", "Delivery Scam"),
        ("FedEx Express: Parcel #FDX8921 on hold. Pay outstanding customs clearance fee of Rs 48. Click: http://fedex-express-customs.xyz", "text", "en", "scam", "Delivery Scam"),
        ("DHL Courier: Urgent notice! Your international shipment has been stopped by customs. Contact inspector immediately: +923001234567", "text", "en", "scam", "Delivery Scam"),
        ("உங்கள் அஞ்சல் பார்சல் முகவரி தவறு காரணமாக நிறுத்தப்பட்டுள்ளது. உடனே புதுப்பிக்க: http://post-tn.click", "text", "ta", "scam", "Delivery Scam"),
        ("भारतीय डाक: आपका पार्सल पते की गलती के कारण रुक गया है। आज ही पता अपडेट करें अन्यथा पार्सल वापस कर दिया जाएगा।", "text", "hi", "scam", "Delivery Scam"),
        ("Delhi Police Cyber Crime: Illegal narcotics found in courier booked under your Aadhaar. Digital arrest warrant issued. Join Skype call now.", "text", "en", "scam", "Delivery Scam"),
        ("Amazon Delivery: Driver could not reach you. Reschedule delivery date and verify identity: http://amazon-redelivery.xyz", "text", "en", "scam", "Delivery Scam"),
        ("BlueDart: Address validation fee of Rs 5 pending for courier consignment #BD7391. Pay now: http://bluedart-fee.top", "text", "en", "scam", "Delivery Scam"),
        ("Parcel aana baaki hai. Address update nahi kiya toh return ho jayega. Click: http://track-pack.xyz", "text", "mixed", "scam", "Delivery Scam"),
        ("Courier service officer: Pay customs duty via UPI to avoid criminal seizure report.", "text", "en", "scam", "Delivery Scam")
    ]
    for _ in range(5):
        for text, itype, lang, label, cat in courier_templates:
            samples.append({
                "id": f"SCAM_DEL_{idx:03d}",
                "input": text if idx <= 110 else f"{text} (Tracking: IND{idx*33})",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 4. Job & Investment Scams - 50 samples
    job_templates = [
        ("Part-time Work from Home! Earn Rs 3000 to Rs 8000 daily by rating Google Maps & liking YouTube videos. Contact HR on Telegram @EarnDailyFast", "text", "en", "scam", "Job Scam"),
        ("Amazon Recruiter: Congratulations! Your resume shortlisted for remote data entry. Pay Rs 999 registration fee for onboarding kit.", "text", "en", "scam", "Job Scam"),
        ("வீட்டிலிருந்தே வேலை! தினமும் 5000 ரூபாய் சம்பாதிக்கலாம். உடனடியாக Telegram குழுவில் இணையுங்கள்.", "text", "ta", "scam", "Job Scam"),
        ("घर बैठे पैसे कमाएं! यूट्यूब वीडियो लाइक करके रोज 2000-5000 कमाएं। अभी व्हाट्सएप करें: +919876543210", "text", "hi", "scam", "Job Scam"),
        ("VIP Crypto Investment Club: 200% guaranteed profit within 7 days. Deposit minimum Rs 5000 today.", "text", "en", "scam", "Job Scam"),
        ("Ghar baithe part time job. Rozana 4000 kamaye. Join telegram channel now for instant payout.", "text", "mixed", "scam", "Job Scam"),
        ("Railway Recruitment Board: Direct job appointment letter issued. Pay medical examination fee to secure joining.", "text", "en", "scam", "Job Scam"),
        ("Stock trading AI bot with 99.8% win rate. Transfer funds to our manager account to start compounding.", "text", "en", "scam", "Job Scam"),
        ("Instagram Influencer Collaboration: Earn Rs 50,000. Click here and sign in with your Instagram password: http://collab-login.xyz", "text", "en", "scam", "Job Scam"),
        ("Instant loan approved up to Rs 5,00,000 without CIBIL score! Pay 2% processing fee to release disbursement.", "text", "en", "scam", "Job Scam")
    ]
    for _ in range(5):
        for text, itype, lang, label, cat in job_templates:
            samples.append({
                "id": f"SCAM_JOB_{idx:03d}",
                "input": text if idx <= 160 else f"{text} (ID #{idx*47})",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 5. Electricity & Utility Disconnection Scams - 30 samples
    utility_templates = [
        ("Electricity Officer Notice: Your power supply will be disconnected tonight at 9:30 PM because previous month bill was not updated. Call our electricity officer at 9123456780 immediately.", "text", "en", "scam", "Utility Scam"),
        ("உங்கள் மின்சார இணைப்பு இன்று இரவு 9 மணிக்கு துண்டிக்கப்படும். உடனே இந்த எண்ணை தொடர்பு கொள்ளவும்: 9840123456", "text", "ta", "scam", "Utility Scam"),
        ("प्रिय उपभोक्ता, आज रात 9:30 बजे आपकी बिजली काट दी जाएगी क्योंकि आपका पिछला बिल अपडेट नहीं हुआ है। तुरंत संपर्क करें।", "text", "hi", "scam", "Utility Scam"),
        ("Bijli cut ho jayegi aaj raat 9 baje. Bill update karne ke liye turant call kare 9876543210.", "text", "mixed", "scam", "Utility Scam"),
        ("Water department notice: Unpaid water tax penalty. Pay immediately via link or tap will be disconnected: http://water-tax.top", "text", "en", "scam", "Utility Scam"),
        ("Gas connection subsidy expiring today. Update bank details to continue receiving LPG subsidy: http://lpg-subsidy.xyz", "text", "en", "scam", "Utility Scam")
    ]
    for _ in range(5):
        for text, itype, lang, label, cat in utility_templates:
            samples.append({
                "id": f"SCAM_UTIL_{idx:03d}",
                "input": text if idx <= 210 else f"{text} (Consumer #{idx*88})",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 6. Malicious URLs, Homoglyphs & Lookalikes - 30 samples
    url_templates = [
        ("http://192.168.1.1/admin/login.php", "url", "en", "suspicious", "SSRF / Local IP"),
        ("http://169.254.169.254/latest/meta-data/", "url", "en", "scam", "SSRF Cloud Metadata"),
        ("https://onlinesbi.login-portal.top/netbanking", "url", "en", "scam", "Lookalike Typosquatting"),
        ("https://hdfcbank.secure-auth.xyz/verify", "url", "en", "scam", "Lookalike Typosquatting"),
        ("https://paytm.cashback-offer.club/claim", "url", "en", "scam", "Lookalike Typosquatting"),
        ("https://xn--sbi-8ka.com/login", "url", "en", "scam", "Punycode Homoglyph")
    ]
    for _ in range(5):
        for u, itype, lang, label, cat in url_templates:
            samples.append({
                "id": f"SCAM_URL_{idx:03d}",
                "input": u if idx <= 240 else f"{u}?ref={idx}",
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    # 7. Legitimate & Safe Samples (Control Group) - 90 samples
    safe_templates = [
        ("Your OTP for transaction of Rs 499.00 at Swiggy is 482910. Valid for 10 mins. Do NOT share OTP with anyone including bank staff.", "text", "en", "safe", "Clean"),
        ("Dear Customer, Rs 2,500.00 debited from A/C XX4921 on 21-Sep-26 towards UPI-ZOMATO. Available bal: Rs 48,210.50. SBI.", "text", "en", "safe", "Clean"),
        ("Your Amazon order #402-892182-192 for 'Wireless Mouse' has been shipped and will arrive tomorrow by 8 PM.", "text", "en", "safe", "Clean"),
        ("Hey Arun, are we meeting for the project presentation at the college library at 4 PM today?", "text", "en", "safe", "Clean"),
        ("உங்கள் கணக்கிலிருந்து ரூ 500 எடுக்கப்பட்டுள்ளது. மீதி இருப்பு ரூ 12000. பாரத ஸ்டேட் வங்கி.", "text", "ta", "safe", "Clean"),
        ("வணக்கம், நாளை காலை கல்லூரியில் நடைபெறும் கருத்தரங்கிற்கு அனைவரும் தவறாமல் வரவும்.", "text", "ta", "safe", "Clean"),
        ("आपके खाते से 1000 रुपये डेबिट हुए हैं। शेष राशि 15,400 रुपये है। बैंक ऑफ बड़ौदा।", "text", "hi", "safe", "Clean"),
        ("कल सुबह 10 बजे मीटिंग है। कृपया सभी प्रोजेक्ट रिपोर्ट साथ लेकर आएं।", "text", "hi", "safe", "Clean"),
        ("Kal college aane se pehle assignment print karva lena.", "text", "mixed", "safe", "Clean"),
        ("Nalaiki seminar ku presentation ready pannitiya?", "text", "mixed", "safe", "Clean"),
        ("https://www.onlinesbi.sbi", "url", "en", "safe", "Clean"),
        ("https://www.hdfcbank.com", "url", "en", "safe", "Clean"),
        ("https://cybercrime.gov.in", "url", "en", "safe", "Clean"),
        ("https://www.google.com", "url", "en", "safe", "Clean"),
        ("https://github.com", "url", "en", "safe", "Clean")
    ]
    for _ in range(6):
        for text, itype, lang, label, cat in safe_templates:
            if itype == "url":
                inp = text if idx <= 270 else f"{text}?ref={idx}"
            else:
                inp = text if idx <= 270 else f"{text} [Seq {idx}]"
            samples.append({
                "id": f"SAFE_{idx:03d}",
                "input": inp,
                "input_type": itype,
                "language": lang,
                "label": label,
                "scam_type": cat,
                "source": "synthetic"
            })
            idx += 1

    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2, ensure_ascii=False)

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "input", "input_type", "language", "label", "scam_type", "source"])
        writer.writeheader()
        writer.writerows(samples)

    print(f"Generated {len(samples)} benchmark samples in {OUTPUT_JSON} and {OUTPUT_CSV}.")
    return samples


if __name__ == "__main__":
    generate_benchmark_dataset()
