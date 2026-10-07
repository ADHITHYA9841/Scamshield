import pytest
from app.engines.qr_engine import QREngine
from app.engines.phone_engine import PhoneEngine


def test_upi_reverse_payment_scam():
    qr = QREngine()
    uri = "upi://pay?pa=cashback-agent@ybl&pn=PhonePe+Rewards&am=2000&tn=Scan+and+enter+PIN+to+receive+Rs+2000"
    score, evidence, details = qr.analyze(uri)
    assert details["is_upi"]
    assert score >= 70
    assert any(e.type == "upi_reverse_payment_scam" for e in evidence)


def test_upi_normal_payment():
    qr = QREngine()
    uri = "upi://pay?pa=merchant@icici&pn=Fresh+Grocery&am=350&tn=Bill+3921"
    score, evidence, details = qr.analyze(uri)
    assert details["is_upi"]
    assert score < 30


def test_phone_number_normalization():
    pe = PhoneEngine()
    norm = pe.normalize_number("9876543210")
    assert norm == "+919876543210"

    norm_zero = pe.normalize_number("09876543210")
    assert norm_zero == "+919876543210"


def test_phone_suspicious_prefix_and_context():
    pe = PhoneEngine()
    score, evidence, details = pe.analyze("+923001234567", context_text="This is Mumbai Police cyber crime officer.")
    assert details["is_suspicious_prefix"]
    assert score >= 70
    assert any(e.type == "authority_phone_mismatch" for e in evidence)
