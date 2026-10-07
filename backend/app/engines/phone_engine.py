import re
from typing import Dict, Any, List, Tuple, Optional
from app.models.schemas import EvidenceItem


class PhoneEngine:
    """
    Phone Number Intelligence & Fraud Pattern Engine.
    Normalizes phone numbers, detects international mismatch, virtual VoIP/telemarketing series,
    and analyzes message context for caller identity fraud.
    """

    # High-risk prefixes commonly associated with cross-border WhatsApp impersonation scams in India
    SUSPICIOUS_FOREIGN_PREFIXES = {
        "+92": "Pakistan",
        "+234": "Nigeria",
        "+880": "Bangladesh",
        "+84": "Vietnam",
        "+62": "Indonesia",
        "+254": "Kenya",
        "+233": "Ghana"
    }

    def normalize_number(self, phone: str) -> str:
        """Standardize phone string into cleaned E.164 format where possible."""
        cleaned = re.sub(r'[^\d+]', '', phone.strip())
        if cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        elif not cleaned.startswith("+"):
            # Assume India (+91) if 10 digits starting with 6-9
            if len(cleaned) == 10 and cleaned[0] in "6789":
                cleaned = "+91" + cleaned
            elif len(cleaned) == 11 and cleaned.startswith("0"):
                cleaned = "+91" + cleaned[1:]
            else:
                cleaned = "+" + cleaned
        return cleaned

    def analyze(self, raw_phone: str, context_text: Optional[str] = None) -> Tuple[float, List[EvidenceItem], Dict[str, Any]]:
        """
        Analyzes a phone number and optional context for scam patterns.
        """
        evidence_items: List[EvidenceItem] = []
        normalized = self.normalize_number(raw_phone)

        details: Dict[str, Any] = {
            "raw_input": raw_phone,
            "normalized": normalized,
            "country_code": None,
            "is_suspicious_prefix": False,
            "is_telemarketing_series": False
        }

        risk_score = 0.0

        # Check country prefix
        for prefix, country in self.SUSPICIOUS_FOREIGN_PREFIXES.items():
            if normalized.startswith(prefix):
                details["country_code"] = prefix
                details["is_suspicious_prefix"] = True
                risk_score += 45.0
                evidence_items.append(EvidenceItem(
                    type="international_prefix_flag",
                    severity="high",
                    source="phone",
                    description=f"Phone number originates from {country} ({prefix}), frequently used in cross-border identity spoofing.",
                    evidence=normalized
                ))
                break

        # Check Indian Telemarketing / Robocall series (+91 140 / 160)
        if normalized.startswith("+91140") or normalized.startswith("+91160"):
            details["is_telemarketing_series"] = True
            risk_score += 25.0
            evidence_items.append(EvidenceItem(
                type="telemarketing_series",
                severity="medium",
                source="phone",
                description="Number is registered under commercial telemarketing / automated voice call series.",
                evidence=normalized
            ))

        # Context correlation check:
        # If context text claims to be Indian Police / Bank / Courier but phone is foreign or unknown mobile
        if context_text:
            text_lower = context_text.lower()
            claims_indian_authority = any(term in text_lower for term in [
                "sbi", "hdfc", "police", "customs", "cbi", "income tax", "mumbai police", "delhi police", "electricity"
            ])

            if claims_indian_authority and details["is_suspicious_prefix"]:
                risk_score += 45.0
                evidence_items.append(EvidenceItem(
                    type="authority_phone_mismatch",
                    severity="critical",
                    source="phone",
                    description="Message claims to be Indian Authority or Bank, but contact number originates from outside India.",
                    evidence=f"Claims authority in message while using {normalized}"
                ))

        # Baseline safety rule: unknown number alone is not proof of scam
        if risk_score == 0.0:
            evidence_items.append(EvidenceItem(
                type="standard_phone",
                severity="low",
                source="phone",
                description="Phone number format is standard. No known malicious prefix patterns identified.",
                evidence=normalized
            ))

        return min(100.0, round(risk_score, 1)), evidence_items, details
