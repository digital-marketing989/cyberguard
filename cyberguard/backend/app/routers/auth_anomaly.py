"""
Auth Anomaly router
POST /api/auth/analyze  — JSON array of login events
POST /api/auth/upload   — CSV upload of login events
GET  /api/auth/sample   — analyze the built-in sample data
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
from app.engines.risk_scorer import RiskScorer, get_mitre_tag, score_to_level
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import AuthAnalysisRequest, DetectionResult
from app.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Auth Anomaly"])

DATA_DIR = __import__("pathlib").Path(__file__).resolve().parent.parent.parent / "data"


async def _run_analysis(logs: list, db: Session) -> DetectionResult:
    engine = get_anomaly_engine()
    result = engine.analyze_auth_logs(logs)

    threat_type = result["threat_type"]
    sub_scores = result.get("sub_scores", {})

    risk_score = RiskScorer.score_auth_anomaly(
        failed_login_rate=sub_scores.get("failed_login_rate", 0),
        impossible_travel=sub_scores.get("impossible_travel", 0),
        new_device=sub_scores.get("new_device", 0),
        brute_force=sub_scores.get("brute_force", 0),
        password_spray=sub_scores.get("password_spray", 0),
    )
    risk_level = score_to_level(risk_score)
    indicators = result["indicators"]
    confidence = result["confidence"]

    explanation = await generate_explanation(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
    )
    actions = recommend_actions(threat_type, risk_level)
    mitre = get_mitre_tag(threat_type)

    stats = result.get("stats", {})
    event = ThreatEvent(
        threat_type=threat_type,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=f"Auth log analysis: {stats.get('total_events', 0)} events, "
                          f"{stats.get('unique_users', 0)} users, "
                          f"{stats.get('unique_ips', 0)} IPs",
        mitre_tag=mitre,
        extra_data={"stats": stats, "sub_scores": sub_scores},
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
        "summary": indicators[0] if indicators else "Auth anomaly analysis complete",
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
        extra_data={"event_id": event.id, "stats": stats},
    )


@router.post("/analyze", response_model=DetectionResult)
async def analyze_auth_logs(
    request: AuthAnalysisRequest,
    db: Session = Depends(get_db),
):
    """Analyze a JSON array of login events for account-takeover indicators."""
    logs = [entry.model_dump() for entry in request.logs]
    return await _run_analysis(logs, db)


@router.post("/upload", response_model=DetectionResult)
async def upload_auth_csv(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Upload a CSV file of login events for analysis."""
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Only .csv files are accepted")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="File too large")

    text = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    logs = []
    for row in reader:
        row["success"] = str(row.get("success", "true")).lower() not in {"false", "0", "fail", "no"}
        for float_col in ["latitude", "longitude"]:
            try:
                row[float_col] = float(row[float_col]) if row.get(float_col) else None
            except ValueError:
                row[float_col] = None
        logs.append(row)

    if not logs:
        raise HTTPException(status_code=400, detail="CSV file is empty or has no valid rows")

    return await _run_analysis(logs, db)


@router.get("/sample", response_model=DetectionResult)
async def analyze_sample_auth_logs(db: Session = Depends(get_db)):
    """Run analysis on the built-in synthetic auth log dataset."""
    csv_path = DATA_DIR / "sample_auth_logs.csv"
    if not csv_path.exists():
        raise HTTPException(status_code=404, detail="Sample auth log data not found")

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        logs = []
        for row in reader:
            row["success"] = str(row.get("success", "true")).lower() not in {"false", "0", "fail", "no"}
            for float_col in ["latitude", "longitude"]:
                try:
                    row[float_col] = float(row[float_col]) if row.get(float_col) else None
                except ValueError:
                    row[float_col] = None
            logs.append(row)

    return await _run_analysis(logs, db)
