import re
from typing import List, Dict, Any, Tuple
from app.models.schemas import EvidenceItem


class RuleEngine:
    """
    Multilingual Rule & Heuristic Detection Engine.
    Detects urgency, threats, credential requests, payment manipulation,
    and impersonation across English, Tamil, Hindi, and transliterated Roman text (Hinglish/Tanglish).
    Includes negative context filtering to prevent false positives on legitimate security advisories.
    """

    CATEGORIES = {
        "urgency": {
            "weight": 1.2,
            "patterns": [
                (r"(?i)\b(urgently?|immediate(ly)?|act\s+now|action\s+required|right\s+now|expires?\s+today|within\s+\d+\s*(hours?|hrs?|mins?|minutes?|days?)|final\s+(warning|notice)|last\s+chance|before\s+it'?s\s+too\s+late|urgent\s*:)\b", "high", "High urgency language creating panic"),
                (r"(?i)\b(expire\s+aagum|udane\s+seiyavum|seekiram|vudane)\b", "high", "Urgent language detected (Tamil transliterated)"),
                (r"(உடனடியாக|இன்றே\s+கடைசி|உடனே\s+செய்யவும்|முடக்கப்படும்\s+முன்|இன்று\s+இரவு)", "high", "Urgent language detected (Tamil script)"),
                (r"(तुरंत|जल्दी\s+करें|आज\s+ही|अंतिम\s+चेतावनी|24\s+घंटे\s+के\s+अंदर|आज\s+रात)", "high", "Urgent language detected (Hindi script)"),
                (r"(?i)\b(turant|jaldi\s+kare|aaj\s+hi|khatam\s+ho\s+jayega|aaj\s+raat)\b", "high", "Urgent language detected (Hindi transliterated)")
            ]
        },
        "threats": {
            "weight": 1.5,
            "patterns": [
                (r"(?i)\b((account|netbanking|card|credit\s+card|debit\s+card|sim(\s+card)?|power\s+supply|water\s+supply|gas(\s+connection)?)\s+(is|will\s+be)?\s*(blocked|suspended|frozen|terminated|deactivated|restricted|disconnected|cut\s*off))\b", "critical", "Account suspension or utility cutoff threat"),
                (r"(?i)\b(legal\s+action|police\s+(complaint|arrest|case)|arrest\s+warrant|court\s+notice|cbi|customs\s+seizure|income\s+tax\s+penalty|digital\s+arrest|parcel\s+seized|drugs\s+found|illegal\s+contraband)\b", "critical", "Coercive legal threat or arrest intimidation tactic"),
                (r"(கணக்கு\s+முடக்கப்படும்|மின்சாரம்\s+துண்டிக்கப்படும்|இணைப்பு\s+துண்டிக்கப்படும்|காவல்துறை\s+நடவடிக்கை|வழக்கு\s+பதிவு)", "critical", "Threat or account suspension detected (Tamil)"),
                (r"(खाता\s+बंद\s+हो\s+जाएगा|बिजली\s+काट\s+दी\s+जाएगी|बिजली\s+काट|पुलिस\s+कार्रवाई|गिरफ्तारी\s+वारंट|खाता\s+फ्रीज|कट\s+जाएगी)", "critical", "Threat or legal action detected (Hindi)"),
                (r"(?i)\b(account\s+band\s+ho\s+jayega|bijli\s+kat\s+jayegi|bijli\s+cut\s+ho|police\s+case|kanooni\s+karwayi|account\s+freeze)\b", "critical", "Threat detected (Hindi transliterated)"),
                (r"(?i)\b(mudakkapadum|inaippu\s+thundikkapadum|thundikkapadum)\b", "critical", "Threat detected (Tamil transliterated)")
            ]
        },
        "credential_harvesting": {
            "weight": 2.0,
            "patterns": [
                (r"(?i)\b((enter|type|share|send|submit|verify|validate|provide)\s+(your\s+|the\s+)?(otp|pin|credentials?|debit\s+card\s+pin|upi\s*pin|mpin|cvv|password|passcode))\b", "critical", "Direct solicitation of confidential credential or OTP"),
                (r"(?i)\b(aadhaar\s+number|aadhaar[- ]pan(\s+link(ing)?)?|pan\s+card\s+update|pending\s+pan\s+update|kyc\s*(update|verification|pending|incomplete|expire(d)?)|submit\s+your\s+cvv)\b", "critical", "Request for sensitive personal or banking identity credentials"),
                (r"(?i)\b(click\s+(here\s+)?to\s+(verify|update|claim|login|activate))\b", "high", "Phishing call-to-action link to credential capture portal"),
                (r"(ஓடிபி\s*(பகிரவும்|அனுப்பவும்|உள்ளிடவும்)|பின்\s*எண்|கடவுச்சொல்|கேஒய்சி\s*(புதுப்பிக்க|முடிவடைந்தது)|பான்\s*கார்டு)", "critical", "Credential / OTP request detected (Tamil)"),
                (r"(ओटीपी\s*(बताएं|शेयर\s+करें|भेजें|दर्ज\s+करें)|पिन\s*नंबर|पासवर्ड\s*दर्ज\s*करें|केवाईसी\s*अपडेट|पैन\s*कार्ड\s*(और|अपडेट))", "critical", "Credential / OTP request detected (Hindi)"),
                (r"(?i)\b(otp\s+(share\s+karo|bhejo|batao|kodu|anupu|enter\s+kare|share\s+pannunga)|pan\s+card\s+link\s+karo|kyc\s+update\s+kare)\b", "critical", "Credential harvesting detected (Transliterated)")
            ]
        },
        "payment_manipulation": {
            "weight": 1.6,
            "patterns": [
                (r"(?i)\b(processing\s+fee|registration\s+fee|verification\s+charge|refundable\s+deposit|pay\s+rs\.?\s*\d+\s+penalty|validation\s+fee|medical\s+examination\s+fee|onboarding\s+kit)\b", "high", "Advance fee or fake penalty demand"),
                (r"(?i)\b(claim\s+(lottery|prize|reward|cashback|money)|won\s+(a\s+)?(prize|reward|car|iphone|cash|lottery)|kbc\s+(lucky\s+draw|kaun\s+banega)|scratch\s+card.*credited)\b", "high", "Financial manipulation or fake prize bait"),
                (r"(?i)\b(part[- ]time\s+(work|job)|work\s+from\s+home.*earn|rating\s+google\s+maps|liking\s+youtube|telegram\s+task|earn\s+rs\.?\s*\d+.*daily|daily\s+income|rozana\s+\d+\s+kamaye)\b", "high", "Fake task/job employment or investment return scam"),
                (r"(?i)\b(resume\s+shortlisted|remote\s+data\s+entry|crypto\s+investment|guaranteed\s+profit|stock\s+trading(\s+ai)?\s+bot|influencer\s+collaboration|instant\s+loan\s+approved|without\s+cibil|recruitment\s+board|appointment\s+letter|transfer\s+funds\s+to\s+our\s+manager|pending\s+loan\s+disbursement)\b", "high", "Employment, investment, or fake loan advance fee bait"),
                (r"(?i)\b(package\s+(could\s+not\s+be\s+delivered|delayed)|incorrect\s+street\s+number|update\s+(your\s+)?address.*here|unpaid\s+water\s+tax|previous\s+month\s+bill\s+was\s+not\s+updated|lpg\s+subsidy|consignment|customs\s+(clearance|duty)|reschedule\s+delivery)\b", "high", "Delivery failure bait or utility impersonation extortion"),
                (r"(?i)\b(scan\s+(this\s+)?qr(\s+code)?\s+and\s+(type|enter)\s+(your\s+)?(upi\s+)?pin|approve\s+transaction\s+to\s+receive)\b", "critical", "UPI reverse payment trap attempting unauthorized deduction"),
                (r"(பரிசு\s+விழுந்துள்ளது|பணம்\s+அனுப்பவும்|முன்பணம்|கட்டணம்\s+செலுத்தவும்|வீட்டிலிருந்தே\s+சம்பாதிக்க|மதிப்பீடு\s+செய்து)", "high", "Lottery or advance fee scam indicator (Tamil)"),
                (r"(इनाम\s+जीता\s+है|पैसे\s+भेजें|रजिस्ट्रेशन\s+शुल्क|घर\s+बैठे\s+कमाएं|लॉटरी\s+लगी\s+है|कैशबैक\s+मिला\s+है)", "high", "Lottery or money transfer fraud indicator (Hindi)"),
                (r"(?i)\b(paise\s+(bhejo|transfer\s+karo)|lottery\s+lagi\s+hai|ghar\s+baithe\s+kamaye|inam\s+mila\s+hai|cash\s+prize\s+mila)\b", "high", "Financial manipulation detected (Hindi transliterated)")
            ]
        },
        "authority_impersonation": {
            "weight": 1.4,
            "patterns": [
                (r"(?i)\b(state\s+bank\s+of\s+india|sbi(\s+bank)?|hdfc(\s+bank)?|icici(\s+bank)?|axis(\s+bank)?|punjab\s+national\s+bank|reserve\s+bank\s+of\s+india|rbi)\b", "medium", "Banking authority claim"),
                (r"(?i)\b(trai|telecom\s+department|india\s+post|income\s+tax(\s+department)?|customs(\s+department)?|mumbai\s+police|delhi\s+police|cyber\s+crime(\s+branch)?|electricity\s+officer|water\s+department|fedex|dhl|bluedart|amazon\s+(recruiter|delivery)|railway\s+recruitment)\b", "medium", "Government, utility, or courier authority claim"),
                (r"(பாரத\s+ஸ்டேட்\s+வங்கி|இந்திய\s+அஞ்சல்|வருமான\s+வரித்துறை|காவல்துறை|மின்சார\s+அலுவலர்)", "medium", "Authority claim detected (Tamil)"),
                (r"(भारतीय\s+स्टेट\s+बैंक|भारतीय\s+डाक|आयकर\s+विभाग|साइबर\s+क्राइम|बिजली\s+विभाग)", "medium", "Authority claim detected (Hindi)")
            ]
        }
    }

    def detect_language(self, text: str) -> str:
        """Detect whether text contains Tamil, Hindi, English, or mixed scripts."""
        has_tamil = bool(re.search(r'[\u0B80-\u0BFF]', text))
        has_hindi = bool(re.search(r'[\u0900-\u097F]', text))
        has_english = bool(re.search(r'[a-zA-Z]', text))

        if (has_tamil and has_english) or (has_hindi and has_english) or (has_tamil and has_hindi):
            return "mixed"
        if has_tamil:
            return "ta"
        if has_hindi:
            return "hi"
        return "en"

    def is_legitimate_security_advisory(self, text: str) -> bool:
        """
        Detects standard bank transaction SMS and security advisories instructing user NEVER to share OTP.
        e.g.: 'Your OTP for transaction of Rs 499 at Swiggy is 482910. Valid for 10 mins. Do NOT share OTP with anyone.'
        """
        lower = text.lower()
        has_negative_advisory = bool(re.search(r"\b(do\s+not|never|don't)\s+(share|disclose|give|reveal)\s+(the\s+|your\s+)?(otp|pin|password|mpin|cvv)", lower))
        has_transactional_context = bool(re.search(r"\b(debited\s+from|credited\s+to|available\s+bal|valid\s+for\s+\d+\s*mins?|order\s+#?\w+\s+has\s+been\s+shipped)\b", lower))
        has_no_phishing_link = not bool(re.search(r'https?://[^\s<>"]+', text))

        return (has_negative_advisory and has_transactional_context and has_no_phishing_link)

    def analyze(self, text: str) -> Tuple[float, List[EvidenceItem], Dict[str, Any]]:
        """
        Executes rule-based pattern matching.
        Returns:
            - rule_score (0.0 to 100.0)
            - evidence_items (List[EvidenceItem])
            - category_matches (Dict[str, int])
        """
        if not text or not text.strip():
            return 0.0, [], {}

        # 1. Check for genuine transactional alert advising NOT to share OTP
        if self.is_legitimate_security_advisory(text):
            evidence_items = [
                EvidenceItem(
                    type="legitimate_security_advisory",
                    severity="low",
                    source="rules",
                    description="Standard legitimate transaction notification containing security advisory (advising never to share OTP).",
                    evidence="Legitimate Security Notice"
                )
            ]
            return 0.0, evidence_items, {cat: 0 for cat in self.CATEGORIES}

        evidence_items: List[EvidenceItem] = []
        category_hits: Dict[str, int] = {cat: 0 for cat in self.CATEGORIES}
        total_weighted_points = 0.0

        for cat_name, cat_data in self.CATEGORIES.items():
            weight = cat_data["weight"]
            for pattern, severity, description in cat_data["patterns"]:
                matches = list(re.finditer(pattern, text))
                for match in matches:
                    matched_snippet = match.group(0)

                    # If in credential_harvesting, ensure it's not preceded by 'do not share' or 'never share'
                    if cat_name == "credential_harvesting":
                        start_pos = match.start()
                        prefix = text[max(0, start_pos - 25):start_pos].lower()
                        if re.search(r"\b(do\s+not|never|don't)\s*$", prefix):
                            continue

                    category_hits[cat_name] += 1

                    # Severity point mapping
                    severity_points = {
                        "low": 10,
                        "medium": 20,
                        "high": 35,
                        "critical": 50
                    }.get(severity, 20)

                    total_weighted_points += severity_points * weight

                    evidence_items.append(EvidenceItem(
                        type=cat_name,
                        severity=severity,
                        source="rules",
                        description=description,
                        evidence=matched_snippet
                    ))

        # Check for synergy (e.g. Threat + Credential Request is almost certainly a scam)
        if category_hits["threats"] > 0 and category_hits["credential_harvesting"] > 0:
            total_weighted_points += 30
            evidence_items.append(EvidenceItem(
                type="compound_tactic",
                severity="critical",
                source="rules",
                description="Coercive threat combined with credential request detected",
                evidence="Threat + Credential Combination"
            ))

        if category_hits["urgency"] > 0 and category_hits["payment_manipulation"] > 0:
            total_weighted_points += 20
            evidence_items.append(EvidenceItem(
                type="compound_tactic",
                severity="high",
                source="rules",
                description="Urgent pressure combined with payment demand detected",
                evidence="Urgency + Payment Demand Combination"
            ))

        if category_hits["authority_impersonation"] > 0 and (category_hits["threats"] > 0 or category_hits["credential_harvesting"] > 0):
            total_weighted_points += 20

        # Normalize score into 0-100 scale with ceiling dampening
        raw_score = total_weighted_points
        normalized_score = min(100.0, round(raw_score / 1.4, 1))

        return normalized_score, evidence_items, category_hits
