import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    type: str = Field(..., description="Indicator category, e.g. urgency, otp_request, brand_impersonation")
    severity: str = Field(..., description="'low', 'medium', 'high', 'critical'")
    source: str = Field(..., description="'rules', 'url', 'file', 'ocr', 'qr', 'phone', 'llm'")
    description: str = Field(..., description="Human-readable explanation of why this was flagged")
    evidence: str = Field(..., description="Specific text or snippet that triggered the indicator")
    location: Optional[str] = Field(None, description="Page number, line, or component where found")


class StandardResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    input_type: str = Field(..., description="'text', 'url', 'file', 'qr', 'phone', 'audio'")
    verdict: str = Field(..., description="'SAFE', 'SUSPICIOUS', 'SCAM'")
    risk_score: int = Field(..., ge=0, le=100, description="Calibrated ScamShield Risk Score 0-100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence level 0.0-1.0")
    scam_type: str = Field(..., description="Classified category, e.g. KYC Fraud, UPI Scam, Clean")
    language: str = Field("en", description="'en', 'ta', 'hi', or 'mixed'")
    evidence: List[EvidenceItem] = Field(default_factory=list)
    engine_results: Dict[str, Any] = Field(default_factory=dict)
    explanation: str = Field(..., description="Detailed explanation of the verdict")
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    multilingual_explanations: Dict[str, str] = Field(default_factory=dict)


class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Suspicious text or message")
    language: Optional[str] = Field("auto", description="'auto', 'en', 'ta', 'hi'")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class URLAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="Suspicious URL or link")
    visible_text: Optional[str] = Field(None, description="Hyperlink anchor text for mismatch detection")
    language: Optional[str] = Field("auto")


class QRAnalysisRequest(BaseModel):
    qr_content: str = Field(..., min_length=1, description="Decoded QR content or UPI URI string")
    language: Optional[str] = Field("auto")


class PhoneAnalysisRequest(BaseModel):
    phone_number: str = Field(..., min_length=3, max_length=30, description="Phone number to verify")
    context_text: Optional[str] = Field(None, description="Accompanying SMS or chat message context")
    language: Optional[str] = Field("auto")


class DownloadAnalysisRequest(BaseModel):
    url: str = Field(..., description="Source download URL")
    filename: str = Field(..., description="Name of the file being downloaded")
    referrer: Optional[str] = Field(None, description="Referring webpage URL")
    file_size: Optional[int] = Field(None, description="Reported file size in bytes")
    mime_type: Optional[str] = Field(None, description="Content-Type MIME string")


class DownloadAnalysisResponse(BaseModel):
    scan_id: str
    filename: str
    url: Optional[str] = None
    verdict: str  # SAFE, SUSPICIOUS, SCAM
    risk_score: int
    should_pause: bool
    is_dangerous_extension: bool
    is_double_extension: bool
    scam_category: str
    reasons: List[str] = Field(default_factory=list)
    notification_title: str
    notification_message: str
    file_size_formatted: Optional[str] = None
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    virustotal: Optional[Dict[str, Any]] = None
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class FeedbackRequest(BaseModel):
    scan_id: str
    user_verdict: str  # 'accurate', 'false_positive', 'false_negative'
    comments: Optional[str] = None


class RecoveryRequest(BaseModel):
    incident_type: str  # 'clicked_link', 'entered_otp', 'transferred_money', 'installed_app', 'shared_id'
    details: Optional[str] = None
    language: Optional[str] = "en"


class RecoveryGuideResponse(BaseModel):
    incident_type: str
    urgency_level: str  # 'CRITICAL', 'HIGH', 'MEDIUM'
    immediate_actions: List[str]
    secondary_actions: List[str]
    helplines: List[Dict[str, str]]
    prevention_tips: List[str]
    disclaimer: str


class EvaluationMetrics(BaseModel):
    total_samples: int
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    confusion_matrix: Dict[str, Dict[str, int]]
    by_category: Dict[str, Any]
    by_language: Dict[str, Any]
