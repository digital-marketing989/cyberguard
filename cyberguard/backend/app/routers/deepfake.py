"""
Deepfake analysis router
POST /api/deepfake/analyze  — image/audio/video file upload
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.engines.deepfake_engine import get_deepfake_engine
from app.engines.explainer import generate_explanation
from app.engines.risk_scorer import get_mitre_tag, score_to_level
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import DetectionResult
from app.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/deepfake", tags=["Deepfake"])

ALLOWED_MEDIA_TYPES = (
    settings.ALLOWED_IMAGE_TYPES
    + settings.ALLOWED_AUDIO_TYPES
    + settings.ALLOWED_VIDEO_TYPES
)

THREAT_TYPE_MAP = {
    "image": "Deepfake Image",
    "audio": "Deepfake Audio",
    "video": "Deepfake Video",
}


@router.post("/analyze", response_model=DetectionResult)
async def analyze_deepfake(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """
    Analyze an uploaded image, audio, or video file for deepfake indicators.
    Accepts: JPEG, PNG, WebP, WAV, MP3, OGG, FLAC, MP4, AVI, MOV, WebM.
    """
    content_type = (file.content_type or "").lower()
    filename = file.filename or "upload"

    # Guess from extension if content_type is generic
    if content_type in {"application/octet-stream", ""}:
        ext = filename.rsplit(".", 1)[-1].lower()
        ext_map = {
            "jpg": "image/jpeg", "jpeg": "image/jpeg", "png": "image/png",
            "webp": "image/webp", "gif": "image/gif",
            "wav": "audio/wav", "mp3": "audio/mpeg", "ogg": "audio/ogg",
            "flac": "audio/flac",
            "mp4": "video/mp4", "avi": "video/avi", "mov": "video/mov",
            "webm": "video/webm",
        }
        content_type = ext_map.get(ext, content_type)

    if content_type not in ALLOWED_MEDIA_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported media type: {content_type}. Accepted: image, audio, video files.",
        )

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    data = await file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail="File exceeds maximum allowed size")

    # Determine media category
    if "image" in content_type:
        media_cat = "image"
    elif "audio" in content_type:
        media_cat = "audio"
    else:
        media_cat = "video"

    threat_type = THREAT_TYPE_MAP[media_cat]

    # Run detection
    engine = get_deepfake_engine(content_type)
    result = engine.analyze(data, filename)

    risk_score = result["risk_score"]
    risk_level = score_to_level(risk_score)
    confidence = result["confidence"]
    indicators = result["indicators"]

    explanation = await generate_explanation(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
        extra_context=f"Media type: {content_type}, file: {filename}",
    )
    actions = recommend_actions(threat_type, risk_level)
    mitre = get_mitre_tag("Deepfake Image")  # same MITRE tag for all deepfake types

    event = ThreatEvent(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=f"{media_cat.capitalize()} file: {filename} ({len(data)} bytes)",
        mitre_tag=mitre,
        extra_data={
            "filename": filename,
            "content_type": content_type,
            "authenticity_score": result.get("authenticity_score"),
            "file_size_bytes": len(data),
        },
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    await ws_manager.broadcast({
        "event_id": event.id,
        "threat_type": threat_type,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.utcnow().isoformat(),
        "summary": f"Deepfake {media_cat} analysis: {filename[:40]}",
    })

    return DetectionResult(
        threat_type=threat_type,
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
            "authenticity_score": result.get("authenticity_score"),
            "filename": filename,
        },
    )
