import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.db.session import Base


class ScanRequest(Base):
    __tablename__ = "scan_requests"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    input_type = Column(String(50), nullable=False, index=True)  # text, url, file, qr, phone, audio
    client_ip_hash = Column(String(64), nullable=True)  # Privacy-preserving hash
    source_client = Column(String(50), default="mobile")  # mobile, extension, api
    language_hint = Column(String(10), default="auto")

    result = relationship("ScanResult", back_populates="request", uselist=False, cascade="all, delete-orphan")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(36), ForeignKey("scan_requests.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    verdict = Column(String(20), nullable=False, index=True)  # SAFE, SUSPICIOUS, SCAM
    risk_score = Column(Integer, nullable=False, index=True)  # 0 to 100
    confidence = Column(Float, nullable=False)
    scam_category = Column(String(100), nullable=False)
    detected_language = Column(String(10), default="en")
    explanation = Column(Text, nullable=False)
    recommended_actions = Column(JSON, default=list)
    limitations = Column(JSON, default=list)
    engine_scores = Column(JSON, default=dict)

    request = relationship("ScanRequest", back_populates="result")
    evidence_items = relationship("ScanEvidence", back_populates="scan_result", cascade="all, delete-orphan")


class ScanEvidence(Base):
    __tablename__ = "scan_evidence"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_result_id = Column(String(36), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    source_engine = Column(String(50), nullable=False)
    description = Column(Text, nullable=False)
    matched_content = Column(Text, nullable=False)
    location_reference = Column(String(100), nullable=True)

    scan_result = relationship("ScanResult", back_populates="evidence_items")


class URLAnalysis(Base):
    __tablename__ = "url_analysis"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    original_url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False, index=True)
    tld = Column(String(50), nullable=True)
    is_ip_based = Column(Boolean, default=False)
    is_shortener = Column(Boolean, default=False)
    has_homoglyphs = Column(Boolean, default=False)
    is_lookalike = Column(Boolean, default=False)
    impersonated_brand = Column(String(100), nullable=True)
    entropy_score = Column(Float, default=0.0)
    reputation_status = Column(String(50), default="clean")
    analysis_details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)


class PhoneAnalysis(Base):
    __tablename__ = "phone_analysis"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    normalized_number = Column(String(30), nullable=False, index=True)
    country_code = Column(String(10), nullable=True)
    is_virtual_voip = Column(Boolean, default=False)
    reputation_score = Column(Float, default=0.0)
    flagged_fraud_pattern = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class QRAnalysis(Base):
    __tablename__ = "qr_analysis"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    payload_type = Column(String(50), nullable=False)  # upi, url, text, contact
    raw_payload = Column(Text, nullable=False)
    upi_payee_address = Column(String(100), nullable=True)
    upi_payee_name = Column(String(150), nullable=True)
    upi_amount = Column(String(50), nullable=True)
    is_spoofed_merchant = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    sanitized_filename = Column(String(255), nullable=False)
    file_type = Column(String(50), nullable=False)
    file_size_bytes = Column(Integer, nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    is_retained = Column(Boolean, default=False)  # Default: temporary auto-deleted
    created_at = Column(DateTime, default=datetime.utcnow)


class Feedback(Base):
    __tablename__ = "feedback"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), nullable=False, index=True)
    user_verdict = Column(String(50), nullable=False)
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id = Column(String(50), primary_key=True)
    name = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    pattern_regex = Column(Text, nullable=False)
    severity = Column(String(20), default="high")
    weight = Column(Float, default=1.0)
    language = Column(String(10), default="all")
    is_active = Column(Boolean, default=True)


class ScamCategory(Base):
    __tablename__ = "scam_categories"

    id = Column(String(50), primary_key=True)
    display_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    typical_tactics = Column(JSON, default=list)


class AppSetting(Base):
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(100), nullable=False)
    details = Column(Text, nullable=True)
    client_source = Column(String(50), nullable=True)


class SystemMetric(Base):
    __tablename__ = "system_metrics"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
