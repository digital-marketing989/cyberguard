"""
Network anomaly router
POST /api/network/analyze  — JSON or CSV network logs
GET  /api/network/sample   — use built-in synthetic dataset
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.engines.anomaly_engine import get_anomaly_engine
from app.engines.explainer import generate_explanation
from app.engines.risk_scorer import get_mitre_tag, score_to_level
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import DetectionResult, NetworkAnalysisRequest
from app.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/network", tags=["Network"])

DATA_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "data"


async def _run_network_analysis(logs: list, db: Session) -> DetectionResult:
    engine = get_anomaly_engine()
    result = engine.analyze_network_logs(logs)

    risk_score = result["final_score"]
    risk_level = score_to_level(risk_score)
    indicators = result["indicators"]
    confidence = result["confidence"]
    threat_type = result.get("threat_type", "Network Anomaly")

    explanation = await generate_explanation(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
    )
    actions = recommend_actions(threat_type, risk_level)
    mitre = get_mitre_tag(threat_type)

    event = ThreatEvent(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=f"{threat_type} log analysis: {result.get('stats', {}).get('total_events', result.get('stats', {}).get('total_requests', len(logs)))} events",
        mitre_tag=mitre,
        extra_data={"stats": result.get("stats", {})},
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
        "summary": indicators[0] if indicators else f"{threat_type} analysis complete",
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
        extra_data={"event_id": event.id},
    )


@router.post("/analyze", response_model=DetectionResult)
async def analyze_network(
    request: NetworkAnalysisRequest,
    db: Session = Depends(get_db),
):
    if request.use_sample:
        return await _load_and_analyze_sample(db)

    logs = request.logs or []
    return await _run_network_analysis(logs, db)


@router.post("/upload", response_model=DetectionResult)
async def upload_network_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Only .csv files accepted")
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="File too large")
    reader = csv.DictReader(io.StringIO(content.decode("utf-8", errors="replace")))
    logs = list(reader)
    return await _run_network_analysis(logs, db)


@router.get("/sample", response_model=DetectionResult)
async def analyze_sample_network(db: Session = Depends(get_db)):
    return await _load_and_analyze_sample(db)


async def _load_and_analyze_sample(db: Session) -> DetectionResult:
    csv_path = DATA_DIR / "sample_network_logs.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Sample network log data not found")
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        logs = list(reader)
    return await _run_network_analysis(logs, db)


@router.post("/analyze-api", response_model=DetectionResult)
async def analyze_api_logs(
    request: NetworkAnalysisRequest,
    db: Session = Depends(get_db),
):
    """
    Analyze API logs for rate abuse, unauthorized admin endpoint probing,
    and abnormal calling sequence anomalies. Returns threat_type="api_abuse".
    """
    if request.use_sample or not request.logs:
        return await _load_and_analyze_sample_api(db)
    return await _run_network_analysis(request.logs, db)


@router.get("/sample-api", response_model=DetectionResult)
async def analyze_sample_api(db: Session = Depends(get_db)):
    """Run API abuse detection on synthetic API access logs."""
    return await _load_and_analyze_sample_api(db)


async def _load_and_analyze_sample_api(db: Session) -> DetectionResult:
    csv_path = DATA_DIR / "sample_api_logs.csv"
    if not csv_path.exists():
        csv_path = DATA_DIR / "sample_network_logs.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Sample API log data not found")
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        logs = list(reader)
    return await _run_network_analysis(logs, db)
