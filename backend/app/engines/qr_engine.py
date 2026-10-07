import re
import urllib.parse
from typing import Dict, Any, List, Tuple
from app.models.schemas import EvidenceItem


class QREngine:
    """
    QR Code Analysis Engine with specialized UPI (Unified Payments Interface) fraud detection.
    Analyzes UPI payees, amount traps, reverse payment scams, and malicious URLs inside QR codes.
    Never executes or initiates payments.
    """

    def parse_upi_uri(self, uri: str) -> Dict[str, Any]:
        """
        Parses standard UPI URI scheme (upi://pay?pa=...&pn=...&am=...&tn=...)
        """
        parsed = urllib.parse.urlparse(uri)
        query_params = urllib.parse.parse_qs(parsed.query)

        pa = query_params.get("pa", [""])[0]  # Payee Address (VPA)
        pn = query_params.get("pn", [""])[0]  # Payee Name
        am = query_params.get("am", [""])[0]  # Amount
        tn = query_params.get("tn", [""])[0]  # Transaction Note / Remark
        cu = query_params.get("cu", ["INR"])[0] # Currency
        tr = query_params.get("tr", [""])[0]  # Transaction Reference ID

        return {
            "is_upi": True,
            "payee_address": pa,
            "payee_name": pn,
            "amount": am,
            "transaction_note": tn,
            "currency": cu,
            "transaction_ref": tr
        }

    def analyze(self, qr_payload: str) -> Tuple[float, List[EvidenceItem], Dict[str, Any]]:
        """
        Analyzes decoded QR payload.
        Returns:
            - risk_score (0.0 to 100.0)
            - evidence_items (List[EvidenceItem])
            - details_dict (Dict[str, Any])
        """
        evidence_items: List[EvidenceItem] = []
        details: Dict[str, Any] = {
            "raw_payload": qr_payload,
            "type": "text",
            "is_upi": False,
            "upi_details": None
        }

        risk_score = 0.0
        cleaned = qr_payload.strip()

        # Check if UPI payment link
        if cleaned.lower().startswith("upi://pay"):
            details["type"] = "upi"
            details["is_upi"] = True
            upi_info = self.parse_upi_uri(cleaned)
            details["upi_details"] = upi_info

            pa = upi_info["payee_address"].lower()
            pn = upi_info["payee_name"].lower()
            tn = upi_info["transaction_note"].lower()

            # Check 1: Reverse Payment Scam & Extortion Notes
            # UPI protocol NEVER requires scanning a QR to RECEIVE funds into your bank account!
            scam_keywords = [
                "receive", "credit", "refund", "cashback", "prize", "lottery",
                "kbc", "reward", "won", "pin", "disconnection", "fine", "penalty",
                "cut off", "overdue", "urgent", "bill update"
            ]
            if any(kw in tn for kw in scam_keywords) or any(kw in pn for kw in scam_keywords):
                risk_score += 75.0
                evidence_items.append(EvidenceItem(
                    type="upi_reverse_payment_scam",
                    severity="critical",
                    source="qr",
                    description="UPI QR claims to 'credit' or 'refund' money. UPI QR codes CANNOT send you money. Scanning this will DEDUCT funds from your bank account!",
                    evidence=f"Note: '{upi_info['transaction_note']}', Payee: '{upi_info['payee_name']}'"
                ))

            # Check 2: Fake official merchant impersonation in VPA
            # e.g. sbi-support@ybl or electricity-bill@paytm
            impersonated = re.search(r'(sbi|hdfc|icici|electricity|bijli|bescom|tneb|paytm.*care|phonepe.*support)', pa)
            if impersonated and not any(pa.endswith(d) for d in ["@sbi", "@icici", "@hdfcbank"]):
                risk_score += 45.0
                evidence_items.append(EvidenceItem(
                    type="upi_spoofed_merchant",
                    severity="high",
                    source="qr",
                    description=f"Payee VPA '{pa}' appears to impersonate an official bank/utility, but uses an individual UPI handle.",
                    evidence=pa
                ))

            # Warning item: Always inform user about UPI PIN implications
            evidence_items.append(EvidenceItem(
                type="upi_security_notice",
                severity="medium",
                source="qr",
                description="Security Rule: Never enter your UPI PIN to receive money. UPI PIN is only needed to transfer money out.",
                evidence="UPI Protocol Safety"
            ))

            if risk_score == 0.0:
                # Normal UPI payment code with non-suspicious values
                risk_score = 15.0

        elif cleaned.startswith(("http://", "https://")):
            details["type"] = "url"
            details["url"] = cleaned
            # The URL engine will do detailed checks; here we flag basic QR-embedded link risks
            risk_score += 20.0
            evidence_items.append(EvidenceItem(
                type="qr_url_payload",
                severity="medium",
                source="qr",
                description="QR code redirects to an external web URL.",
                evidence=cleaned
            ))
        else:
            details["type"] = "text"
            risk_score = 5.0

        return min(100.0, round(risk_score, 1)), evidence_items, details
