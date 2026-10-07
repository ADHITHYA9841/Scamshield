import re
import math
import urllib.parse
from typing import List, Dict, Any, Tuple, Optional
import tldextract
from app.core.security import validate_url_safety
from app.models.schemas import EvidenceItem
from app.providers.virustotal import VirusTotalProvider, VERIFIED_SAFE_DOMAINS


# Known URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "rb.gy", "goo.gl", "tiny.cc", "bc.vc", "shorturl.at"
}

# Suspicious or frequently abused generic Top Level Domains (gTLDs)
SUSPICIOUS_TLDS = {
    "top", "xyz", "click", "buzz", "loan", "work", "rest", "icu",
    "sbs", "cfd", "link", "gq", "ml", "cf", "ga", "tk", "surf", "casa"
}

# Protected brands commonly targeted in India and globally
PROTECTED_BRANDS = {
    "sbi": ["onlinesbi", "statebankofindia", "sbi"],
    "hdfc": ["hdfcbank", "hdfc"],
    "icici": ["icicibank", "icici"],
    "axis": ["axisbank"],
    "paytm": ["paytm", "paytmbank"],
    "phonepe": ["phonepe"],
    "google": ["google", "gmail", "gpay"],
    "amazon": ["amazon", "amazonpay"],
    "flipkart": ["flipkart"],
    "indiapost": ["indiapost", "postofficeservice"],
    "incometax": ["incometax", "incometaxgov"],
    "uidai": ["uidai", "myaadhaar"],
    "netflix": ["netflix"],
    "microsoft": ["microsoft", "office365"],
    "apple": ["apple", "icloud"],
    "whatsapp": ["whatsapp"],
    "telegram": ["telegram"]
}


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect algorithmically generated / random domains."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


class URLEngine:
    """
    URL Security & Intelligence Engine.
    Inspects URL anatomy, SSRF exposure, punycode/homoglyphs, lookalike typosquatting,
    anchor text mismatches, and domain entropy.
    """

    def __init__(self):
        self.extractor = tldextract.TLDExtract(cache_dir=False)

    def extract_urls(self, text: str) -> List[str]:
        """Extract all URLs from free-form text."""
        url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
        matches = re.findall(url_pattern, text)
        clean_urls = []
        for u in matches:
            if not u.startswith("http"):
                u = "http://" + u
            # Strip trailing punctuation
            u = u.rstrip(".,;!?'\")")
            clean_urls.append(u)
        return clean_urls

    def check_link_mismatch(self, visible_text: str, actual_url: str) -> Tuple[bool, Optional[EvidenceItem]]:
        """
        Detects hyperlink spoofing where displayed anchor text shows a safe trusted domain
        while the actual target URL leads elsewhere.
        Example: Anchor text 'https://onlinesbi.sbi' pointing to 'https://sbi-login.scam.xyz'
        """
        if not visible_text or not actual_url:
            return False, None

        # Check if visible text looks like a URL
        visible_urls = self.extract_urls(visible_text)
        if visible_urls:
            vis_extracted = self.extractor(visible_urls[0])
            act_extracted = self.extractor(actual_url)

            vis_domain = f"{vis_extracted.domain}.{vis_extracted.suffix}".lower()
            act_domain = f"{act_extracted.domain}.{act_extracted.suffix}".lower()

            if vis_domain and act_domain and vis_domain != act_domain:
                evidence = EvidenceItem(
                    type="hyperlink_mismatch",
                    severity="critical",
                    source="url",
                    description=f"Displayed link text '{vis_domain}' does NOT match actual destination '{act_domain}'. Classic phishing trap.",
                    evidence=f"Display: {visible_text} -> Destination: {actual_url}"
                )
                return True, evidence

        return False, None

    def analyze(self, raw_url: str, visible_text: Optional[str] = None, vt_api_key: Optional[str] = None, skip_live_vt: bool = False) -> Tuple[float, List[EvidenceItem], Dict[str, Any]]:
        """
        Performs in-depth inspection of a target URL.
        Returns:
            - risk_score (0.0 to 100.0)
            - evidence_items (List[EvidenceItem])
            - details_dict (Dict[str, Any])
        """
        evidence_items: List[EvidenceItem] = []
        details: Dict[str, Any] = {
            "url": raw_url,
            "ssrf_safe": True,
            "is_ip_based": False,
            "is_shortener": False,
            "has_homoglyphs": False,
            "is_lookalike": False,
            "suspicious_tld": False,
            "high_entropy": False,
            "entropy": 0.0
        }

        raw_url = raw_url.strip()
        extracted_links = self.extract_urls(raw_url)
        if extracted_links:
            raw_url = extracted_links[0]
        elif not raw_url.startswith(("http://", "https://")):
            raw_url = "http://" + raw_url

        # 1. SSRF Safety Verification
        is_safe, ssrf_msg = validate_url_safety(raw_url)
        if not is_safe:
            details["ssrf_safe"] = False
            evidence_items.append(EvidenceItem(
                type="ssrf_blocked",
                severity="critical",
                source="url",
                description=f"Security Policy Block: {ssrf_msg}",
                evidence=raw_url
            ))
            return 95.0, evidence_items, details

        # 2. Parse URL
        try:
            parsed = urllib.parse.urlparse(raw_url)
        except Exception:
            evidence_items.append(EvidenceItem(
                type="malformed_url",
                severity="medium",
                source="url",
                description="The URL is malformed or unparseable.",
                evidence=raw_url
            ))
            return 40.0, evidence_items, details

        extracted = self.extractor(raw_url)
        subdomain = extracted.subdomain.lower()
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()
        full_host = (parsed.hostname or "").lower()

        details["domain"] = domain
        details["tld"] = suffix
        details["subdomain"] = subdomain

        risk_score = 0.0

        # 3. Check for IP-based URL
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, full_host):
            details["is_ip_based"] = True
            risk_score += 45.0
            evidence_items.append(EvidenceItem(
                type="ip_based_url",
                severity="high",
                source="url",
                description="URL uses a raw IP address instead of a recognized domain name.",
                evidence=full_host
            ))

        # 4. Check for URL Shorteners
        host_no_sub = f"{domain}.{suffix}" if suffix else domain
        if host_no_sub in SHORTENER_DOMAINS:
            details["is_shortener"] = True
            risk_score += 25.0
            evidence_items.append(EvidenceItem(
                type="url_shortener",
                severity="medium",
                source="url",
                description="URL shortener detected. Masks final destination.",
                evidence=host_no_sub
            ))

        # 5. Punycode & Homoglyph detection (e.g. xn-- or non-ascii lookalikes)
        if "xn--" in full_host:
            details["has_homoglyphs"] = True
            risk_score += 50.0
            evidence_items.append(EvidenceItem(
                type="punycode_homoglyph",
                severity="critical",
                source="url",
                description="Internationalized Domain Name (Punycode 'xn--') used. High risk of character spoofing.",
                evidence=full_host
            ))

        # 6. Suspicious / Abused TLDs
        if suffix in SUSPICIOUS_TLDS:
            details["suspicious_tld"] = True
            risk_score += 20.0
            evidence_items.append(EvidenceItem(
                type="suspicious_tld",
                severity="medium",
                source="url",
                description=f"Domain uses high-abuse top-level domain (.{suffix}).",
                evidence=f".{suffix}"
            ))

        # 7. Lookalike & Brand Typosquatting
        target_check = f"{subdomain}.{domain}" if subdomain else domain
        for brand_key, brand_variants in PROTECTED_BRANDS.items():
            for variant in brand_variants:
                # If variant appears in subdomain or domain with hyphens/numbers but isn't official
                if variant in target_check:
                    # Check if legitimate official domain
                    official_whitelist = {
                        "sbi": ["onlinesbi.sbi", "statebankofindia.com", "sbi.co.in"],
                        "hdfc": ["hdfcbank.com"],
                        "icici": ["icicibank.com"],
                        "axis": ["axisbank.com"],
                        "paytm": ["paytm.com"],
                        "phonepe": ["phonepe.com"],
                        "google": ["google.com", "google.co.in"],
                        "amazon": ["amazon.in", "amazon.com"],
                        "flipkart": ["flipkart.com"],
                        "indiapost": ["indiapost.gov.in"],
                        "incometax": ["incometax.gov.in"],
                        "uidai": ["uidai.gov.in"],
                        "netflix": ["netflix.com"],
                        "microsoft": ["microsoft.com"],
                        "apple": ["apple.com"],
                        "whatsapp": ["whatsapp.com"],
                        "telegram": ["telegram.org"]
                    }

                    is_official = False
                    for legit in official_whitelist.get(brand_key, []):
                        if host_no_sub == legit or host_no_sub.endswith("." + legit):
                            is_official = True
                            break

                    if not is_official:
                        details["is_lookalike"] = True
                        details["impersonated_brand"] = brand_key
                        risk_score += 65.0
                        evidence_items.append(EvidenceItem(
                            type="brand_typosquatting",
                            severity="critical",
                            source="url",
                            description=f"Suspected brand impersonation targeting '{brand_key.upper()}'. Not an official domain.",
                            evidence=f"{target_check}.{suffix}"
                        ))
                        break

        # 8. Domain Entropy (randomness)
        entropy = calculate_entropy(domain)
        details["entropy"] = entropy
        if entropy > 3.8 and len(domain) > 10:
            details["high_entropy"] = True
            risk_score += 20.0
            evidence_items.append(EvidenceItem(
                type="high_domain_entropy",
                severity="medium",
                source="url",
                description=f"Domain has high character randomness (entropy {entropy}), indicative of DGA or disposable host.",
                evidence=domain
            ))

        # 9. Link Mismatch check
        visible_text_mismatched = False
        if visible_text:
            mismatched, mismatch_ev = self.check_link_mismatch(visible_text, raw_url)
            if mismatched and mismatch_ev:
                visible_text_mismatched = True
                risk_score += 55.0
                evidence_items.append(mismatch_ev)

        # 10. High-Authority Verified Safe Domain Verification
        full_domain = f"{domain}.{suffix}" if suffix else domain
        is_verified_safe = (
            full_domain in VERIFIED_SAFE_DOMAINS or
            any(full_domain.endswith("." + sd) for sd in VERIFIED_SAFE_DOMAINS)
        )
        details["is_verified_safe_domain"] = is_verified_safe

        if is_verified_safe:
            evidence_items.append(EvidenceItem(
                type="virustotal_verified_clean",
                severity="low",
                source="virustotal",
                description="VirusTotal & Whitelist: Verified clean high-authority official domain.",
                evidence=full_domain
            ))
            evidence_items.append(EvidenceItem(
                type="verified_official_domain",
                severity="low",
                source="url",
                description=f"Domain '{full_domain}' is a verified official authority domain.",
                evidence=full_domain
            ))
            return 0.0, evidence_items, details

        # 11. VirusTotal Live Threat Intelligence Integration
        if not skip_live_vt:
            vt_client = VirusTotalProvider(api_key=vt_api_key)
            vt_result = vt_client.query_virustotal_url(raw_url)
            if not vt_result or vt_result.get("status") == "not_found":
                vt_result = vt_client.query_virustotal_domain(full_domain)
        else:
            vt_result = None

        if vt_result and vt_result.get("status") == "success":
            details["virustotal"] = vt_result
            malicious_count = vt_result.get("malicious", 0)
            suspicious_count = vt_result.get("suspicious", 0)
            harmless_count = vt_result.get("harmless", 0)
            total_vendors = vt_result.get("total_vendors", 0)

            if malicious_count > 0:
                details["virustotal_detected"] = True
                vt_score = min(100.0, 75.0 + (malicious_count * 5.0))
                risk_score = max(risk_score, vt_score)
                vendors_str = ", ".join(vt_result.get("flagging_vendors", []))
                evidence_items.append(EvidenceItem(
                    type="virustotal_malicious_detection",
                    severity="critical",
                    source="virustotal",
                    description=f"VirusTotal Threat Intelligence: Flagged as MALICIOUS / PHISHING by {malicious_count} security vendors ({vendors_str}).",
                    evidence=f"VirusTotal: {malicious_count}/{total_vendors} security vendor detections"
                ))
            elif suspicious_count > 0:
                risk_score = max(risk_score, 45.0)
                evidence_items.append(EvidenceItem(
                    type="virustotal_suspicious_detection",
                    severity="high",
                    source="virustotal",
                    description=f"VirusTotal Threat Intelligence: Marked as SUSPICIOUS by {suspicious_count} security engines.",
                    evidence=f"VirusTotal: {suspicious_count} suspicious vendor flags"
                ))
            elif harmless_count >= 10 and malicious_count == 0:
                # Verified benign by multiple security engines
                risk_score = max(0.0, risk_score - 30.0)
                evidence_items.append(EvidenceItem(
                    type="virustotal_verified_clean",
                    severity="low",
                    source="virustotal",
                    description=f"VirusTotal Threat Intelligence: Clean reputation verified by {harmless_count} security vendors with zero detections.",
                    evidence=f"VirusTotal: 0/{total_vendors} detections"
                ))

        # If domain is verified official (e.g. google.com, github.com) and no lookalike/homoglyph/mismatch, guarantee SAFE
        if is_verified_safe and not details.get("is_lookalike") and not details.get("has_homoglyphs") and not details.get("is_ip_based") and not visible_text_mismatched:
            risk_score = 0.0
            evidence_items = [e for e in evidence_items if e.severity != "critical"]
            evidence_items.append(EvidenceItem(
                type="verified_official_domain",
                severity="low",
                source="url",
                description=f"Domain '{full_domain}' is a verified official authority domain.",
                evidence=full_domain
            ))

        # Cap score at 100
        final_score = min(100.0, round(risk_score, 1))
        return final_score, evidence_items, details
