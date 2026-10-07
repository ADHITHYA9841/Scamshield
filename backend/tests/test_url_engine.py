import pytest
from app.engines.url_engine import URLEngine


@pytest.fixture
def url_engine():
    return URLEngine()


def test_ssrf_blocking_localhost(url_engine):
    score, evidence, details = url_engine.analyze("http://127.0.0.1:8080/admin")
    assert not details["ssrf_safe"]
    assert score >= 90
    assert any(e.type == "ssrf_blocked" for e in evidence)


def test_ssrf_blocking_cloud_metadata(url_engine):
    score, evidence, details = url_engine.analyze("http://169.254.169.254/latest/meta-data/")
    assert not details["ssrf_safe"]
    assert score >= 90


def test_brand_typosquatting_sbi(url_engine):
    score, evidence, details = url_engine.analyze("https://onlinesbi.verification-login.top/netbanking")
    assert details["is_lookalike"]
    assert details["impersonated_brand"] == "sbi"
    assert score >= 65
    assert any(e.type == "brand_typosquatting" for e in evidence)


def test_punycode_homoglyph_detection(url_engine):
    score, evidence, details = url_engine.analyze("https://xn--pple-43d.com/login")
    assert details["has_homoglyphs"]
    assert any(e.type == "punycode_homoglyph" for e in evidence)


def test_hyperlink_mismatch(url_engine):
    visible_anchor = "https://www.hdfcbank.com"
    actual_destination = "https://hdfc-update.xyz/login"
    is_mismatch, ev = url_engine.check_link_mismatch(visible_anchor, actual_destination)
    assert is_mismatch
    assert ev.type == "hyperlink_mismatch"
    assert ev.severity == "critical"


def test_verified_official_domains_zero_false_positive(url_engine):
    """Ensures major legitimate domains are recognized with 0 false positive risk."""
    for safe_url in ["https://www.google.com/search?q=test", "https://github.com/scamshield", "https://onlinesbi.sbi"]:
        score, evidence, details = url_engine.analyze(safe_url)
        assert details["is_verified_safe_domain"] is True
        assert score == 0.0
        assert any(e.type == "verified_official_domain" for e in evidence)


def test_virustotal_threat_intelligence_escalation(monkeypatch, url_engine):
    """Simulates a VirusTotal multi-vendor threat detection."""
    from app.providers.virustotal import VirusTotalProvider

    fake_vt_response = {
        "status": "success",
        "malicious": 8,
        "suspicious": 2,
        "harmless": 55,
        "total_vendors": 65,
        "flagging_vendors": ["Kaspersky", "Sophos", "BitDefender", "Google Safe Browsing"]
    }

    monkeypatch.setattr(VirusTotalProvider, "query_virustotal_url", lambda self, url: fake_vt_response)
    score, evidence, details = url_engine.analyze("https://unfamiliar-random-site.net/verify", vt_api_key="mock_vt_key")

    assert details.get("virustotal_detected") is True
    assert score >= 75.0
    assert any(e.type == "virustotal_malicious_detection" for e in evidence)

