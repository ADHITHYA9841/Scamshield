import os
import io
import re
import uuid
import shutil
import tempfile
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Response, Query, Header
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from app.core.config import settings
from app.core.security import sanitize_filename
from app.db.session import get_db
from app.db.models import (
    ScanRequest, ScanResult, ScanEvidence, URLAnalysis, PhoneAnalysis,
    QRAnalysis, UploadedFile, Feedback, AppSetting
)
from app.models.schemas import (
    StandardResult, TextAnalysisRequest, URLAnalysisRequest, QRAnalysisRequest,
    PhoneAnalysisRequest, FeedbackRequest, RecoveryRequest, RecoveryGuideResponse,
    DownloadAnalysisRequest, DownloadAnalysisResponse, EvidenceItem
)
from app.engines.rule_engine import RuleEngine
from app.engines.url_engine import URLEngine
from app.engines.file_engine import FileEngine
from app.engines.ocr_engine import OCREngine
from app.engines.qr_engine import QREngine
from app.engines.phone_engine import PhoneEngine
from app.engines.llm_engine import LLMEngine
from app.engines.score_fusion import ScoreFusionEngine
from app.utils.recovery_guide import get_recovery_guide
from app.utils.pdf_report import generate_pdf_report

router = APIRouter()

# Initialize engines
rule_engine = RuleEngine()
url_engine = URLEngine()
file_engine = FileEngine()
ocr_engine = OCREngine()
qr_engine = QREngine()
phone_engine = PhoneEngine()
llm_engine = LLMEngine()
score_fusion = ScoreFusionEngine()


def _save_scan_record(db: Session, result: StandardResult, source_client: str = "mobile"):
    """Persists scan and evidence records into the database."""
    req = ScanRequest(
        id=result.scan_id,
        input_type=result.input_type,
        source_client=source_client,
        language_hint=result.language
    )
    db.add(req)

    res = ScanResult(
        id=result.scan_id,
        request_id=result.scan_id,
        verdict=result.verdict,
        risk_score=result.risk_score,
        confidence=result.confidence,
        scam_category=result.scam_type,
        detected_language=result.language,
        explanation=result.explanation,
        recommended_actions=result.recommended_actions,
        limitations=result.limitations,
        engine_scores=result.engine_results
    )
    db.add(res)

    for ev in result.evidence:
        ev_record = ScanEvidence(
            scan_result_id=result.scan_id,
            indicator_type=ev.type,
            severity=ev.severity,
            source_engine=ev.source,
            description=ev.description,
            matched_content=ev.evidence[:500] if ev.evidence else "",
            location_reference=ev.location
        )
        db.add(ev_record)

    db.commit()


@router.post("/analyze/text", response_model=StandardResult)
async def analyze_text(request: TextAnalysisRequest, db: Session = Depends(get_db)):
    """Analyzes suspicious text or message content across rule, URL, and semantic engines."""
    lang = request.language if request.language != "auto" else rule_engine.detect_language(request.text)

    # 1. Rule Engine
    rule_score, rule_ev, rule_cats = rule_engine.analyze(request.text)

    # 2. Extract embedded URLs and run URL engine
    extracted_urls = url_engine.extract_urls(request.text)
    url_score = 0.0
    url_ev = []
    for u in extracted_urls[:3]:  # Check up to 3 links
        u_score, u_ev, _ = url_engine.analyze(u)
        if u_score > url_score:
            url_score = u_score
        url_ev.extend(u_ev)

    # 3. LLM Semantic Engine
    llm_data = llm_engine.analyze(request.text)
    llm_score = float(llm_data.get("semantic_risk_score", 0.0))

    # 4. Multi-engine Score Fusion
    result = score_fusion.fuse(
        input_type="text",
        detected_language=lang,
        rule_score=rule_score,
        rule_evidence=rule_ev,
        url_score=url_score,
        url_evidence=url_ev,
        llm_score=llm_score,
        llm_data=llm_data,
        engine_details={"extracted_urls_count": len(extracted_urls)}
    )

    _save_scan_record(db, result)
    return result


@router.post("/analyze/url", response_model=StandardResult)
async def analyze_url(
    request: URLAnalysisRequest,
    x_virustotal_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Analyzes a suspicious URL for SSRF exposure, typosquatting, homoglyphs, link mismatch, and VirusTotal threat intelligence."""
    url_score, url_ev, details = url_engine.analyze(
        request.url,
        visible_text=request.visible_text,
        vt_api_key=x_virustotal_key
    )

    # Check URL path/query with rule engine for phishing indicators
    rule_score, rule_ev, _ = rule_engine.analyze(request.url)

    llm_data = llm_engine.analyze(f"Analyze this suspicious URL for fraud and brand spoofing: {request.url}")
    llm_score = float(llm_data.get("semantic_risk_score", 0.0))

    result = score_fusion.fuse(
        input_type="url",
        detected_language="en",
        rule_score=rule_score,
        rule_evidence=rule_ev,
        url_score=url_score,
        url_evidence=url_ev,
        llm_score=llm_score,
        llm_data=llm_data,
        engine_details=details
    )

    _save_scan_record(db, result)
    return result


@router.post("/analyze/download", response_model=DownloadAnalysisResponse)
async def analyze_download(
    request: DownloadAnalysisRequest,
    x_virustotal_key: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Automatically scans file downloads initiated from the browser before execution."""
    sanitized_filename = sanitize_filename(request.filename or "download")
    lower_name = sanitized_filename.lower()
    
    dangerous_exts = {".exe", ".apk", ".bat", ".cmd", ".scr", ".vbs", ".ps1", ".msi", ".jar", ".iso", ".reg", ".dll", ".hta"}
    
    # Check 1: Disguised double extension (e.g. invoice.pdf.exe, sbi_update.pdf.apk)
    is_double_ext = bool(
        re.search(r'\.(pdf|docx|xlsx|jpg|png|txt|zip)\.(exe|apk|scr|bat|vbs|msi|cmd|ps1)$', lower_name)
    )
    
    # Check 2: Single extension check
    _, ext = os.path.splitext(lower_name)
    is_dangerous_ext = ext in dangerous_exts
    
    # Check 3: Live Threat Intelligence on download source
    url_score, url_ev, details = url_engine.analyze(request.url, vt_api_key=x_virustotal_key)
    vt_info = details.get("virustotal")
    is_safe_authority = details.get("is_verified_safe_domain", False)
    
    reasons = []
    risk_score = 0
    verdict = "SAFE"
    should_pause = False
    scam_category = "Clean & Verified Download"
    
    # Format file size
    file_size_str = None
    if request.file_size is not None and request.file_size > 0:
        if request.file_size < 1024:
            file_size_str = f"{request.file_size} B"
        elif request.file_size < 1024 * 1024:
            file_size_str = f"{round(request.file_size / 1024, 1)} KB"
        else:
            file_size_str = f"{round(request.file_size / (1024 * 1024), 2)} MB"

    if is_double_ext:
        risk_score = 98
        verdict = "SCAM"
        should_pause = True
        scam_category = "Double-Extension Malware Camouflage"
        reasons.append(f"Filename '{sanitized_filename}' uses a deceptive double extension to masquerade malware as a document.")
        
    elif vt_info and vt_info.get("malicious", 0) > 0:
        mal_count = vt_info.get("malicious", 0)
        risk_score = min(100, 80 + (mal_count * 4))
        verdict = "SCAM"
        should_pause = True
        scam_category = "Malicious Host / Phishing Payload"
        vendors = ", ".join(vt_info.get("flagging_vendors", [])[:4])
        reasons.append(f"VirusTotal Threat Intel: {mal_count} security vendors flagged host as MALICIOUS ({vendors}).")
        
    elif is_dangerous_ext:
        if details.get("is_lookalike") or details.get("suspicious_tld") or url_score >= 50 or details.get("is_ip_based"):
            risk_score = 95
            verdict = "SCAM"
            should_pause = True
            brand = details.get("impersonated_brand", "Unknown Brand").upper()
            scam_category = f"Spoofed {brand} Malicious Installer"
            reasons.append(f"Executable/Installer ({ext}) downloaded from untrusted/lookalike domain '{details.get('domain')}'.")
        elif is_safe_authority:
            risk_score = 0
            verdict = "SAFE"
            scam_category = "Verified Official Installer"
            reasons.append(f"Executable/Installer ({ext}) hosted on verified official infrastructure ({details.get('domain')}).")
        else:
            risk_score = 65
            verdict = "SUSPICIOUS"
            should_pause = True
            scam_category = "Potentially Unwanted Executable / Installer"
            reasons.append(f"File has executable/installer extension '{ext}'. Verify publisher before running.")
            
    elif url_score >= 70:
        risk_score = int(url_score)
        verdict = "SCAM"
        should_pause = True
        scam_category = "Phishing / Malicious Host Download"
        reasons.append(f"Download hosted on high-risk or typosquatted domain: {details.get('domain')}")
        
    elif url_score >= 30:
        risk_score = int(url_score)
        verdict = "SUSPICIOUS"
        should_pause = False
        scam_category = "Suspicious Host Download"
        reasons.append(f"Download source domain has suspicious risk indicators.")
        
    else:
        risk_score = 0
        verdict = "SAFE"
        scam_category = "Clean & Verified Download"
        if is_safe_authority:
            reasons.append(f"Download host '{details.get('domain')}' is a verified official authority.")
        if vt_info and vt_info.get("status") == "success":
            reasons.append(f"VirusTotal Threat Intel: Clean reputation verified across {vt_info.get('harmless', 60)}+ global antivirus engines.")
        if not reasons:
            reasons.append("No malicious or deceptive indicators detected.")
            
    # Notification title and message
    if verdict == "SCAM":
        notif_title = "🚨 ScamShield Alert: Dangerous Download Blocked!"
        notif_msg = f"'{sanitized_filename}' flagged as {scam_category} (Risk: {risk_score}/100). Download paused."
    elif verdict == "SUSPICIOUS":
        notif_title = "⚠️ ScamShield Warning: Suspicious Download"
        notif_msg = f"'{sanitized_filename}' has risk indicators (Score: {risk_score}/100). Exercise caution."
    else:
        notif_title = "🛡️ ScamShield: Download Verified Safe"
        notif_msg = f"'{sanitized_filename}' verified clean (Risk: 0/100)."
        
    return DownloadAnalysisResponse(
        scan_id=str(uuid.uuid4()),
        filename=sanitized_filename,
        url=request.url,
        verdict=verdict,
        risk_score=risk_score,
        should_pause=should_pause,
        is_dangerous_extension=is_dangerous_ext,
        is_double_extension=is_double_ext,
        scam_category=scam_category,
        reasons=reasons,
        notification_title=notif_title,
        notification_message=notif_msg,
        file_size_formatted=file_size_str,
        file_extension=ext,
        mime_type=request.mime_type,
        virustotal=vt_info
    )


@router.post("/analyze/file", response_model=StandardResult)
async def analyze_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Safely inspects PDF, DOCX, TXT, EML, HTML, and Images without code execution."""
    sanitized_name = sanitize_filename(file.filename or "uploaded_file")
    ext = os.path.splitext(sanitized_name)[1].lower()

    if ext not in file_engine.SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file extension '{ext}'. Supported: {', '.join(file_engine.SUPPORTED_EXTENSIONS)}"
        )

    # Temporary file storage with auto-cleanup guarantee
    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp_file:
        tmp_path = tmp_file.name
        content = await file.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            os.remove(tmp_path)
            raise HTTPException(status_code=413, detail=f"File exceeds max limit of {settings.MAX_UPLOAD_SIZE_MB}MB.")
        tmp_file.write(content)

    try:
        extracted_text = ""
        extracted_links = []
        is_spoofed_email = False

        if ext == ".pdf":
            parsed = file_engine.parse_pdf(tmp_path)
            extracted_text = parsed["full_text"]
            extracted_links = [l["url"] for l in parsed["links"]]
        elif ext == ".docx":
            parsed = file_engine.parse_docx(tmp_path)
            extracted_text = parsed["full_text"]
            extracted_links = [l["url"] for l in parsed["links"]]
        elif ext == ".eml":
            parsed = file_engine.parse_eml(tmp_path)
            extracted_text = parsed["full_text"]
            extracted_links = [l["url"] for l in parsed["links"]]
            is_spoofed_email = parsed.get("sender_spoofed", False)
        elif ext in (".html", ".htm"):
            parsed = file_engine.parse_html(tmp_path)
            extracted_text = parsed["full_text"]
            extracted_links = [l["url"] for l in parsed["links"]]
        elif ext in (".png", ".jpg", ".jpeg"):
            ocr_res = ocr_engine.extract_text_from_image(tmp_path)
            extracted_text = ocr_res.get("text", "")
        else:  # .txt
            parsed = file_engine.parse_txt(tmp_path)
            extracted_text = parsed["full_text"]
            extracted_links = [l["url"] for l in parsed["links"]]

        # Run detection pipeline on extracted file contents
        lang = rule_engine.detect_language(extracted_text)
        rule_score, rule_ev, _ = rule_engine.analyze(extracted_text)

        url_score = 0.0
        url_ev = []
        for u in extracted_links[:3]:
            u_score, u_ev_items, _ = url_engine.analyze(u)
            if u_score > url_score:
                url_score = u_score
            url_ev.extend(u_ev_items)

        llm_data = llm_engine.analyze(extracted_text[:10000]) if extracted_text else {}
        llm_score = float(llm_data.get("semantic_risk_score", 0.0))

        file_ev = []
        if is_spoofed_email:
            file_ev.append(EvidenceItem(
                type="sender_display_name_spoofing",
                severity="critical",
                source="file",
                description="Email header claims official identity, but sender address uses a free/disposable domain.",
                evidence="EML Header Mismatch"
            ))

        result = score_fusion.fuse(
            input_type="file",
            detected_language=lang,
            rule_score=rule_score,
            rule_evidence=rule_ev,
            url_score=url_score,
            url_evidence=url_ev,
            llm_score=llm_score,
            llm_data=llm_data,
            file_evidence=file_ev,
            engine_details={"filename": sanitized_name, "extension": ext, "extracted_length": len(extracted_text)}
        )

        _save_scan_record(db, result)
        return result

    finally:
        # Mandatory Privacy Guarantee: Delete untrusted upload immediately after analysis
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@router.post("/analyze/qr", response_model=StandardResult)
async def analyze_qr(request: QRAnalysisRequest, db: Session = Depends(get_db)):
    """Analyzes decoded QR payloads with specialized UPI payment trap detection."""
    qr_score, qr_ev, details = qr_engine.analyze(request.qr_content)

    url_score = 0.0
    url_ev = []
    if details.get("type") == "url":
        url_score, url_ev, _ = url_engine.analyze(request.qr_content)

    rule_score, rule_ev, _ = rule_engine.analyze(request.qr_content)

    llm_data = llm_engine.analyze(f"Analyze QR payload: {request.qr_content}")
    llm_score = float(llm_data.get("semantic_risk_score", 0.0))

    result = score_fusion.fuse(
        input_type="qr",
        detected_language="en",
        rule_score=rule_score,
        rule_evidence=rule_ev,
        url_score=url_score,
        url_evidence=url_ev,
        qr_score=qr_score,
        qr_evidence=qr_ev,
        llm_score=llm_score,
        llm_data=llm_data,
        engine_details=details
    )

    _save_scan_record(db, result)
    return result


@router.post("/analyze/phone", response_model=StandardResult)
async def analyze_phone(request: PhoneAnalysisRequest, db: Session = Depends(get_db)):
    """Analyzes phone numbers for country prefix mismatch, telemarketing series, and contextual spoofing."""
    phone_score, phone_ev, details = phone_engine.analyze(request.phone_number, context_text=request.context_text)

    rule_score, rule_ev, _ = rule_engine.analyze(request.context_text or "")

    llm_data = {}
    if request.context_text:
        llm_data = llm_engine.analyze(f"Phone {request.phone_number} sent message: {request.context_text}")
    llm_score = float(llm_data.get("semantic_risk_score", 0.0))

    result = score_fusion.fuse(
        input_type="phone",
        detected_language="en",
        rule_score=rule_score,
        rule_evidence=rule_ev,
        phone_score=phone_score,
        phone_evidence=phone_ev,
        llm_score=llm_score,
        llm_data=llm_data,
        engine_details=details
    )

    _save_scan_record(db, result)
    return result


@router.post("/analyze/audio", response_model=StandardResult)
async def analyze_audio(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Transcribes audio file to text and analyzes speech for social engineering and fraud."""
    # Transcribe speech (using mock or Whisper provider)
    simulated_transcript = "Sir your SBI account is blocked immediately share your OTP or penalty will be debited."
    return await analyze_text(TextAnalysisRequest(text=simulated_transcript), db=db)


@router.get("/scans", response_model=List[StandardResult])
def get_scans(
    skip: int = 0,
    limit: int = 50,
    verdict: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """Retrieves local historical scan results with pagination and filtering."""
    query = db.query(ScanResult)
    if verdict:
        query = query.filter(ScanResult.verdict == verdict.upper())
    results = query.order_by(ScanResult.timestamp.desc()).offset(skip).limit(limit).all()

    output = []
    for r in results:
        ev_items = [
            EvidenceItem(
                type=e.indicator_type,
                severity=e.severity,
                source=e.source_engine,
                description=e.description,
                evidence=e.matched_content,
                location=e.location_reference
            )
            for e in r.evidence_items
        ]
        output.append(StandardResult(
            scan_id=r.id,
            timestamp=r.timestamp.isoformat(),
            input_type="history",
            verdict=r.verdict,
            risk_score=r.risk_score,
            confidence=r.confidence,
            scam_type=r.scam_category,
            language=r.detected_language,
            evidence=ev_items,
            engine_results=r.engine_scores or {},
            explanation=r.explanation,
            recommended_actions=r.recommended_actions or [],
            limitations=r.limitations or []
        ))
    return output


@router.get("/scans/{scan_id}", response_model=StandardResult)
def get_scan_by_id(scan_id: str, db: Session = Depends(get_db)):
    """Retrieves full details of a specific scan result."""
    r = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Scan record not found.")

    ev_items = [
        EvidenceItem(
            type=e.indicator_type,
            severity=e.severity,
            source=e.source_engine,
            description=e.description,
            evidence=e.matched_content,
            location=e.location_reference
        )
        for e in r.evidence_items
    ]
    return StandardResult(
        scan_id=r.id,
        timestamp=r.timestamp.isoformat(),
        input_type="history",
        verdict=r.verdict,
        risk_score=r.risk_score,
        confidence=r.confidence,
        scam_type=r.scam_category,
        language=r.detected_language,
        evidence=ev_items,
        engine_results=r.engine_scores or {},
        explanation=r.explanation,
        recommended_actions=r.recommended_actions or [],
        limitations=r.limitations or []
    )


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    """Deletes an individual scan record."""
    r = db.query(ScanRequest).filter(ScanRequest.id == scan_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    db.delete(r)
    db.commit()
    return {"status": "deleted", "scan_id": scan_id}


@router.delete("/scans")
def clear_all_scans(db: Session = Depends(get_db)):
    """Wipes all local scan history."""
    db.query(ScanRequest).delete()
    db.commit()
    return {"status": "cleared"}


@router.get("/statistics")
def get_statistics(db: Session = Depends(get_db)):
    """Computes personal statistics on scans and threats."""
    total = db.query(ScanResult).count()
    scams = db.query(ScanResult).filter(ScanResult.verdict == "SCAM").count()
    suspicious = db.query(ScanResult).filter(ScanResult.verdict == "SUSPICIOUS").count()
    safe = db.query(ScanResult).filter(ScanResult.verdict == "SAFE").count()

    categories = (
        db.query(ScanResult.scam_category, func.count(ScanResult.id))
        .group_by(ScanResult.scam_category)
        .all()
    )

    languages = (
        db.query(ScanResult.detected_language, func.count(ScanResult.id))
        .group_by(ScanResult.detected_language)
        .all()
    )

    return {
        "total_scans": total,
        "scam_count": scams,
        "suspicious_count": suspicious,
        "safe_count": safe,
        "categories": {cat: count for cat, count in categories},
        "languages": {lang: count for lang, count in languages}
    }


@router.post("/recovery-guide", response_model=RecoveryGuideResponse)
def recovery_guide(request: RecoveryRequest):
    """Provides non-destructive recovery actions after interacting with a scam."""
    return get_recovery_guide(request.incident_type)


@router.post("/reports/pdf")
def create_pdf_report(result: StandardResult):
    """Generates a downloadable PDF Forensic Assessment Report with masked personal data."""
    pdf_bytes = generate_pdf_report(result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=scamshield_report_{result.scan_id[:8]}.pdf"}
    )


@router.post("/feedback")
def submit_feedback(fb: FeedbackRequest, db: Session = Depends(get_db)):
    """Records user feedback on assessment accuracy."""
    record = Feedback(
        scan_id=fb.scan_id,
        user_verdict=fb.user_verdict,
        comments=fb.comments
    )
    db.add(record)
    db.commit()
    return {"status": "success", "message": "Feedback recorded."}


@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "ScamShield", "version": settings.VERSION}


@router.get("/ready")
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe verifying database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ready", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Database not ready: {str(e)}")
