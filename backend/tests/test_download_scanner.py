from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_download_scanner_double_extension():
    payload = {
        "url": "http://downloads-cdn.net/files/sbi_kyc_form.pdf.exe",
        "filename": "sbi_kyc_form.pdf.exe"
    }
    response = client.post("/api/v1/analyze/download", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SCAM"
    assert data["risk_score"] >= 90
    assert data["should_pause"] is True
    assert data["is_double_extension"] is True


def test_download_scanner_apk_from_lookalike_domain():
    payload = {
        "url": "http://onlinesbi.verification-login.top/apps/sbi_update.apk",
        "filename": "sbi_update.apk"
    }
    response = client.post("/api/v1/analyze/download", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SCAM"
    assert data["risk_score"] >= 80
    assert data["should_pause"] is True
    assert data["is_dangerous_extension"] is True


def test_download_scanner_safe_pdf():
    payload = {
        "url": "https://www.hdfcbank.com/docs/terms_and_conditions.pdf",
        "filename": "terms_and_conditions.pdf"
    }
    response = client.post("/api/v1/analyze/download", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SAFE"
    assert data["should_pause"] is False
