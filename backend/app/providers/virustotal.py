import os
import base64
import time
from typing import Dict, Any, Optional, Tuple
import httpx
from app.core.config import settings

# In-memory cache for VirusTotal lookups to avoid exceeding rate limits (4 req/min free tier)
# Maps query -> (timestamp, result_dict)
VT_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour cache

# High-Authority Verified Domain Whitelist (Prevents False Positives on major legitimate websites)
VERIFIED_SAFE_DOMAINS = {
    # Search & Cloud
    "google.com", "google.co.in", "google.co.uk", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "live.com", "office.com", "bing.com", "azure.com", "windows.com",
    "apple.com", "icloud.com", "cloudflare.com", "aws.amazon.com", "amazonaws.com",
    "github.com", "githubusercontent.com", "gitlab.com", "stackoverflow.com",
    
    # Social & Media
    "youtube.com", "youtu.be", "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "facebook.com", "whatsapp.com", "telegram.org", "wikipedia.org", "wikimedia.org",
    "reddit.com", "medium.com", "quora.com",
    
    # E-Commerce & Services
    "amazon.com", "amazon.in", "flipkart.com", "myntra.com", "meesho.com",
    "swiggy.com", "zomato.com", "uber.com", "ola.in", "makemytrip.com", "irctc.co.in",
    
    # Financial & Banking (Official Domains)
    "onlinesbi.sbi", "statebankofindia.com", "sbi.co.in",
    "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com", "pnbindia.in",
    "bankofbaroda.in", "canarabank.com", "rbi.org.in", "paytm.com", "phonepe.com",
    "bhimupi.org.in", "npci.org.in", "paypal.com",
    
    # Government & Law
    "gov.in", "nic.in", "cybercrime.gov.in", "uidai.gov.in", "incometax.gov.in",
    "passportindia.gov.in", "parivahan.gov.in", "epfindia.gov.in"
}


class VirusTotalProvider:
    """
    VirusTotal API v3 Threat Intelligence Client.
    Provides multi-vendor antivirus & URL reputation scanning with caching and fallback.
    """

    VT_URL_API = "https://www.virustotal.com/api/v3/urls"
    VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains"

    def __init__(self, api_key: Optional[str] = None):
        raw_key = api_key or settings.VIRUSTOTAL_API_KEY or os.environ.get("VIRUSTOTAL_API_KEY") or ""
        cleaned = raw_key.strip().strip('"').strip("'")
        self.api_key = cleaned if cleaned else None

    def is_verified_safe_domain(self, domain: str) -> bool:
        """Checks if a domain is part of the verified high-authority whitelist."""
        domain_lower = domain.lower().strip()
        for safe_dom in VERIFIED_SAFE_DOMAINS:
            if domain_lower == safe_dom or domain_lower.endswith("." + safe_dom):
                return True
        return False

    def get_url_id(self, url: str) -> str:
        """Computes VirusTotal v3 URL ID using base64url encoding without padding."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    def query_virustotal_url(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Queries VirusTotal API for URL scan analysis with caching."""
        if not self.api_key:
            return None

        # Check Cache
        now = time.time()
        if target_url in VT_CACHE:
            cached_time, cached_val = VT_CACHE[target_url]
            if now - cached_time < CACHE_TTL_SECONDS:
                return cached_val

        url_id = self.get_url_id(target_url)
        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"{self.VT_URL_API}/{url_id}", headers=headers)
                
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    results = attr.get("last_analysis_results", {})
                    
                    # Extract vendors that flagged as malicious or phishing
                    flagging_vendors = []
                    for vendor, vdata in results.items():
                        category = vdata.get("category", "")
                        if category in ("malicious", "suspicious"):
                            flagging_vendors.append(f"{vendor} ({vdata.get('result') or category})")

                    output = {
                        "source": "virustotal",
                        "status": "success",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "reputation": attr.get("reputation", 0),
                        "flagging_vendors": flagging_vendors[:8],
                        "total_vendors": sum(stats.values()) if stats else 0
                    }
                    VT_CACHE[target_url] = (now, output)
                    return output
                    
                elif resp.status_code == 404:
                    # URL not yet analyzed in VirusTotal database
                    return {
                        "source": "virustotal",
                        "status": "not_found",
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "note": "URL not previously scanned in VirusTotal dataset."
                    }
                elif resp.status_code == 429:
                    return {"source": "virustotal", "status": "rate_limited", "malicious": 0}
                elif resp.status_code == 401:
                    return {"source": "virustotal", "status": "invalid_api_key", "malicious": 0}
        except Exception as e:
            # Network or timeout failure - graceful degradation
            return {"source": "virustotal", "status": "error", "error": str(e), "malicious": 0}

        return None

    def query_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Queries VirusTotal API for Domain reputation."""
        if not self.api_key:
            return None

        now = time.time()
        if domain in VT_CACHE:
            cached_time, cached_val = VT_CACHE[domain]
            if now - cached_time < CACHE_TTL_SECONDS:
                return cached_val

        headers = {
            "x-apikey": self.api_key,
            "Accept": "application/json"
        }

        try:
            with httpx.Client(timeout=8.0) as client:
                resp = client.get(f"{self.VT_DOMAIN_API}/{domain}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    attr = data.get("attributes", {})
                    stats = attr.get("last_analysis_stats", {})
                    
                    output = {
                        "source": "virustotal_domain",
                        "status": "success",
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "reputation": attr.get("reputation", 0)
                    }
                    VT_CACHE[domain] = (now, output)
                    return output
        except Exception:
            pass

        return None
