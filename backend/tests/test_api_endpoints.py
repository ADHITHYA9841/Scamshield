from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_ready_endpoint():
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"


def test_analyze_text_api():
    payload = {
        "text": "Your SBI bank account is suspended. Immediately share your OTP to prevent legal action: http://sbi-unblock.top",
        "language": "auto"
    }
    response = client.post("/api/v1/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SCAM"
    assert data["risk_score"] >= 70
    assert len(data["evidence"]) > 0
    assert "scan_id" in data


def test_analyze_url_api():
    payload = {
        "url": "http://169.254.169.254/latest/meta-data/"
    }
    response = client.post("/api/v1/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SCAM"
    assert data["risk_score"] >= 90


def test_recovery_guide_api():
    payload = {
        "incident_type": "transferred_money"
    }
    response = client.post("/api/v1/recovery-guide", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["urgency_level"] == "CRITICAL"
    assert any("1930" in str(h) for h in data["helplines"])


def test_statistics_api():
    response = client.get("/api/v1/statistics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "scam_count" in data


def test_analyze_url_with_virustotal_header():
    payload = {"url": "https://www.google.com"}
    headers = {"X-VirusTotal-Key": "test_vt_api_key_123"}
    response = client.post("/api/v1/analyze/url", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 0.0


def test_analyze_download_with_virustotal_header():
    payload = {
        "url": "https://www.google.com/chrome/installer.exe",
        "filename": "installer.exe"
    }
    headers = {"X-VirusTotal-Key": "test_vt_api_key_123"}
    response = client.post("/api/v1/analyze/download", json=payload, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "verdict" in data
    assert "risk_score" in data

