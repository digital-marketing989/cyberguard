"""
Phishing analysis router
POST /api/phishing/analyze  — text/email body analysis
POST /api/phishing/analyze-file — .eml file upload
"""
from __future__ import annotations

import io
import logging
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.engines.explainer import generate_explanation
from app.engines.phishing_engine import get_phishing_engine
from app.engines.risk_scorer import RiskScorer, get_mitre_tag, score_to_level
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import DetectionResult, PhishingTextRequest, RiskLevel
from app.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/phishing", tags=["Phishing"])


async def _run_phishing_analysis(
    text: str,
    sender: str | None,
    subject: str | None,
    db: Session,
    raw_summary: str = "",
) -> DetectionResult:
    engine = get_phishing_engine()
    result = engine.analyze(text, sender=sender, subject=subject)

    # Combine sub-scores
    risk_score = RiskScorer.score_phishing(
        ml_score=result["ml_score"],
        rule_score=result["rule_score"],
        url_score=result["url_score"],
    )
    risk_level = score_to_level(risk_score)
    indicators = result["indicators"]
    confidence = result["confidence"]

    # LLM explanation
    explanation = await generate_explanation(
        threat_type="Phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
    )

    # Recommended actions
    actions = recommend_actions("Phishing", risk_level)
    mitre = get_mitre_tag("Phishing")

    # Persist to DB
    event = ThreatEvent(
        threat_type="Phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=raw_summary[:500] if raw_summary else text[:200],
        mitre_tag=mitre,
        extra_data={
            "ml_score": result["ml_score"],
            "rule_score": result["rule_score"],
            "url_score": result["url_score"],
            "urls_found": result["urls_found"][:10],
        },
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    # Broadcast to WebSocket clients
    await ws_manager.broadcast({
        "event_id": event.id,
        "threat_type": "Phishing",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.utcnow().isoformat(),
        "summary": indicators[0] if indicators else "Phishing analysis complete",
    })

    return DetectionResult(
        threat_type="Phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        mitre_tag=mitre,
        timestamp=event.created_at or datetime.utcnow(),
        extra_data={
            "event_id": event.id,
            "ml_score": result["ml_score"],
            "rule_score": result["rule_score"],
            "url_score": result["url_score"],
            "urls_found": result["urls_found"][:10],
        },
    )


@router.post("/analyze", response_model=DetectionResult)
async def analyze_phishing_text(
    request: PhishingTextRequest,
    db: Session = Depends(get_db),
):
    """Analyze pasted email/SMS text for phishing indicators."""
    return await _run_phishing_analysis(
        text=request.text,
        sender=request.sender,
        subject=request.subject,
        db=db,
        raw_summary=request.text,
    )


@router.post("/analyze-file", response_model=DetectionResult)
async def analyze_phishing_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a .eml or .txt file for phishing analysis."""
    allowed_types = {"message/rfc822", "text/plain", "application/octet-stream"}
    if file.content_type not in allowed_types and not (
        file.filename or ""
    ).lower().endswith((".eml", ".txt", ".msg")):
        raise HTTPException(
            status_code=415,
            detail="Only .eml, .msg, or .txt files are accepted for phishing analysis",
        )

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size")

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Could not decode file: {exc}")

    # Extract subject/sender from .eml headers if present
    sender = None
    subject = None
    lines = text.split("\n")
    body_lines = []
    in_body = False
    for line in lines:
        if in_body:
            body_lines.append(line)
        elif line.strip() == "":
            in_body = True
        elif line.lower().startswith("from:"):
            sender = line[5:].strip()
        elif line.lower().startswith("subject:"):
            subject = line[8:].strip()

    body = "\n".join(body_lines) if body_lines else text

    return await _run_phishing_analysis(
        text=body,
        sender=sender,
        subject=subject,
        db=db,
        raw_summary=text[:500],
    )


def _decode_qr_image(image_bytes: bytes) -> list[str]:
    """
    Decodes QR codes from raw image bytes.
    Attempts pyzbar first, then gracefully falls back to OpenCV QRCodeDetector.
    """
    decoded: list[str] = []

    # 1. Attempt pyzbar
    try:
        # pyrefly: ignore [missing-import]
        from pyzbar.pyzbar import decode as pyzbar_decode
        from PIL import Image
        pil_img = Image.open(io.BytesIO(image_bytes))
        results = pyzbar_decode(pil_img)
        for r in results:
            if r.data:
                decoded.append(r.data.decode("utf-8", errors="replace"))
    except Exception as exc:
        logger.debug("pyzbar decoding failed or not available: %s", exc)

    # 2. Fallback to OpenCV QRCodeDetector
    if not decoded:
        try:
            import cv2
            import numpy as np
            nparr = np.frombuffer(image_bytes, np.uint8)
            cv_img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
            if cv_img is not None:
                detector = cv2.QRCodeDetector()
                val, _, _ = detector.detectAndDecode(cv_img)
                if val:
                    decoded.append(val)
                elif hasattr(detector, "detectAndDecodeMulti"):
                    retval, multi_texts, _, _ = detector.detectAndDecodeMulti(cv_img)
                    if retval and multi_texts:
                        for mt in multi_texts:
                            if mt:
                                decoded.append(mt)
        except Exception as exc:
            logger.debug("OpenCV QRCodeDetector fallback failed: %s", exc)

    return [t.strip() for t in decoded if t.strip()]


@router.post("/analyze-qr", response_model=DetectionResult)
async def analyze_phishing_qr(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Analyze an uploaded image for QR code phishing (quishing).
    Decodes the QR code, scans any contained URL for malicious indicators,
    and returns a standard DetectionResult contract.
    If no QR code is found, returns a safe DetectionResult rather than an error.
    """
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size")

    decoded_texts = _decode_qr_image(content)

    # Clear response if no QR code is detected
    if not decoded_texts:
        return DetectionResult(
            threat_type="qr_phishing",
            risk_level=RiskLevel.SAFE,
            risk_score=0.0,
            confidence=1.0,
            indicators=["No QR code detected in the uploaded image"],
            explanation="No readable QR code was detected in the uploaded image. Please ensure the image is clear and contains a valid QR code.",
            recommended_actions=["No action required"],
            mitre_tag=None,
            timestamp=datetime.utcnow(),
            extra_data={"filename": file.filename or "", "status": "no_qr_detected"},
        )

    qr_content = decoded_texts[0]
    # Check if decoded payload contains or represents a URL
    is_url = bool(re.search(r"https?://|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", qr_content))
    target_url = qr_content if qr_content.startswith(("http://", "https://")) else f"http://{qr_content}"

    if is_url:
        from app.routers.url_scan import analyze_url
        (typo_score, tld_score, ip_score, subdomain_score,
         ssl_score, kw_score, url_indicators) = analyze_url(target_url)

        risk_score = RiskScorer.score_url(
            typosquatting=typo_score,
            suspicious_tld=tld_score,
            ip_as_domain=ip_score,
            excessive_subdomains=subdomain_score,
            ssl_missing=ssl_score,
            keyword_match=kw_score,
        )
        risk_level = score_to_level(risk_score)
        confidence = round(min(0.95, risk_score / 100 + 0.1), 3)
        indicators = [f"Decoded QR code URL: {qr_content}"] + url_indicators
        extra_data = {
            "qr_content": qr_content,
            "target_url": target_url,
            "filename": file.filename or "",
            "typosquatting_score": typo_score,
            "tld_score": tld_score,
            "ip_domain_score": ip_score,
        }
    else:
        risk_score = 15.0
        risk_level = score_to_level(risk_score)
        confidence = 0.8
        indicators = [f"Decoded QR code text: {qr_content}", "Payload contains non-URL text"]
        extra_data = {"qr_content": qr_content, "filename": file.filename or ""}

    explanation = await generate_explanation(
        threat_type="qr_phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
        extra_context=f"Embedded QR code payload: {qr_content}",
    )
    actions = recommend_actions("qr_phishing", risk_level)
    mitre = get_mitre_tag("qr_phishing") or "T1566.002 – Spearphishing Link (QR/Quishing)"

    event = ThreatEvent(
        threat_type="qr_phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=f"QR Image: {file.filename or 'upload'} | Content: {qr_content[:200]}",
        mitre_tag=mitre,
        extra_data=extra_data,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    await ws_manager.broadcast({
        "event_id": event.id,
        "threat_type": "qr_phishing",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.utcnow().isoformat(),
        "summary": f"QR Phishing scan: {qr_content[:40]}",
    })

    return DetectionResult(
        threat_type="qr_phishing",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        mitre_tag=mitre,
        timestamp=event.created_at or datetime.utcnow(),
        extra_data={"event_id": event.id, **extra_data},
    )

