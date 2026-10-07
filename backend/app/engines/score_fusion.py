from typing import List, Dict, Any, Optional
from app.core.config import settings
from app.models.schemas import EvidenceItem, StandardResult


class ScoreFusionEngine:
    """
    Multimodal Score Fusion and Calibration Engine.
    Fuses outputs from Rule, URL, File, OCR, QR, Phone, and LLM engines into a single calibrated
    ScamShield Risk Score (0-100) and authoritative verdict with explainable evidence.
    """

    def __init__(self):
        self.thresh_safe = settings.RISK_THRESHOLD_SAFE
        self.thresh_scam = settings.RISK_THRESHOLD_SCAM

    def fuse(
        self,
        input_type: str,
        detected_language: str,
        rule_score: float = 0.0,
        rule_evidence: Optional[List[EvidenceItem]] = None,
        url_score: float = 0.0,
        url_evidence: Optional[List[EvidenceItem]] = None,
        llm_score: float = 0.0,
        llm_data: Optional[Dict[str, Any]] = None,
        qr_score: float = 0.0,
        qr_evidence: Optional[List[EvidenceItem]] = None,
        phone_score: float = 0.0,
        phone_evidence: Optional[List[EvidenceItem]] = None,
        file_evidence: Optional[List[EvidenceItem]] = None,
        engine_details: Optional[Dict[str, Any]] = None
    ) -> StandardResult:
        rule_evidence = rule_evidence or []
        url_evidence = url_evidence or []
        qr_evidence = qr_evidence or []
        phone_evidence = phone_evidence or []
        file_evidence = file_evidence or []
        llm_data = llm_data or {}
        engine_details = engine_details or {}

        all_evidence: List[EvidenceItem] = []
        all_evidence.extend(rule_evidence)
        all_evidence.extend(url_evidence)
        all_evidence.extend(qr_evidence)
        all_evidence.extend(phone_evidence)
        all_evidence.extend(file_evidence)

        # Append LLM evidence points
        for ep in llm_data.get("evidence_points", []):
            all_evidence.append(EvidenceItem(
                type=ep.get("type", "semantic"),
                severity=ep.get("severity", "medium"),
                source="llm",
                description=ep.get("description", "Semantic risk factor"),
                evidence=ep.get("evidence", "")
            ))

        # Check for Critical Triggers (e.g. OTP harvesting, lookalike domain, SSRF, UPI reverse payment)
        critical_count = sum(1 for e in all_evidence if e.severity == "critical")
        high_count = sum(1 for e in all_evidence if e.severity == "high")

        # Dynamic weighted score combination based on active modalities
        if input_type == "url":
            fused_score = (url_score * 0.60) + (rule_score * 0.20) + (llm_score * 0.20)
        elif input_type == "qr":
            fused_score = (qr_score * 0.50) + (llm_score * 0.30) + (rule_score * 0.20)
        elif input_type == "phone":
            fused_score = (phone_score * 0.50) + (rule_score * 0.30) + (llm_score * 0.20)
        else:
            # General text or file
            if url_score > 0 or len(url_evidence) > 0:
                fused_score = (rule_score * 0.40) + (llm_score * 0.35) + (url_score * 0.25)
            else:
                fused_score = (rule_score * 0.50) + (llm_score * 0.50)

        # Cross-engine concordance and strong signal elevation
        if llm_score >= 80 and rule_score >= 50:
            fused_score = max(fused_score, max(llm_score, rule_score))
        elif llm_score >= 85 or rule_score >= 80 or qr_score >= 75 or url_score >= 80:
            fused_score = max(fused_score, 78.0)
        elif llm_score >= 70 or rule_score >= 60 or qr_score >= 60:
            fused_score = max(fused_score, 70.0)

        # Elevate score if critical indicators detected
        if any(e.type == "ssrf_blocked" for e in all_evidence) or url_score >= 90:
            fused_score = max(fused_score, 95.0)
        elif critical_count >= 1:
            fused_score = max(fused_score, 80.0 + (critical_count * 5.0))
        elif high_count >= 2:
            fused_score = max(fused_score, 70.0)

        # Safe Domain / Legitimate Advisory Override
        if (engine_details.get("is_verified_safe_domain") or any(e.type == "virustotal_verified_clean" for e in all_evidence)) and critical_count == 0 and high_count == 0:
            fused_score = 0.0

        if any(e.type == "legitimate_security_advisory" for e in all_evidence) and url_score == 0:
            fused_score = 0.0

        if llm_data.get("scam_category") in ("Clean / Legitimate", "Legitimate / Clean") and llm_score <= 10 and critical_count == 0 and high_count == 0:
            fused_score = min(fused_score, 10.0)

        # Clamp between 0 and 100
        final_risk_score = int(min(100, max(0, round(fused_score))))

        # Determine Verdict
        if final_risk_score >= self.thresh_scam:
            verdict = "SCAM"
            explanation = "This content contains multiple indicators commonly associated with scams. Exercise extreme caution and do not proceed with any requested actions."
        elif final_risk_score > self.thresh_safe:
            verdict = "SUSPICIOUS"
            explanation = "This content contains some indicators commonly associated with scams. Verify sender identity through independent channels."
        else:
            verdict = "SAFE"
            explanation = "No significant scam indicators were detected in this content."

        # Scam Category Determination
        scam_category = llm_data.get("scam_category", "General Fraud")
        if verdict == "SAFE":
            scam_category = "Clean / Legitimate"
        elif qr_score > 60:
            scam_category = "UPI Payment Fraud"
        elif url_score > 60:
            scam_category = "Phishing / Malicious Domain"
        elif phone_score > 60:
            scam_category = "Identity Impersonation / Robocall"

        # Multilingual explanations
        multilingual_explanations = {
            "en": llm_data.get("explanation_en", explanation),
            "ta": llm_data.get("explanation_ta", "இதில் மோசடி அறிகுறிகள் இருக்கலாம். எச்சரிக்கையாக இருக்கவும்."),
            "hi": llm_data.get("explanation_hi", "इस सामग्री में धोखाधड़ी के लक्षण हो सकते हैं। सतर्क रहें।")
        }

        # Recommendations
        recommended_actions = llm_data.get("recommended_actions", [])
        if not recommended_actions:
            if verdict == "SCAM":
                recommended_actions = [
                    "Do NOT click any links, open attachments, or scan QR codes.",
                    "Never share OTP, PIN, UPI PIN, passwords, or personal documents.",
                    "Block and report the sender on your messaging platform.",
                    "Report financial fraud immediately to National Cyber Crime helpline 1930."
                ]
            elif verdict == "SUSPICIOUS":
                recommended_actions = [
                    "Verify the sender's identity through official contact numbers.",
                    "Check the official website directly instead of clicking provided links."
                ]
            else:
                recommended_actions = [
                    "No immediate action required. Maintain good cybersecurity awareness."
                ]

        limitations = [
            "ScamShield provides an automated risk assessment and cannot guarantee absolute safety.",
            "Newly created or zero-day phishing domains may not yet be recorded in all reputation databases.",
            "Always verify critical financial or legal notices directly with the concerned institution."
        ]

        # Confidence calculation based on evidence volume & concordance
        confidence = 0.90
        if len(all_evidence) >= 3:
            confidence = 0.95
        elif len(all_evidence) == 0:
            confidence = 0.85

        return StandardResult(
            input_type=input_type,
            verdict=verdict,
            risk_score=final_risk_score,
            confidence=round(confidence, 2),
            scam_type=scam_category,
            language=detected_language,
            evidence=all_evidence,
            engine_results={
                "rule_score": rule_score,
                "url_score": url_score,
                "llm_score": llm_score,
                "qr_score": qr_score,
                "phone_score": phone_score,
                "details": engine_details
            },
            explanation=explanation,
            recommended_actions=recommended_actions,
            limitations=limitations,
            multilingual_explanations=multilingual_explanations
        )
