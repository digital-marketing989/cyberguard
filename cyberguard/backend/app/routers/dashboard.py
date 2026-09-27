"""
Dashboard router
GET /api/dashboard/summary  — aggregate stats
GET /api/dashboard/timeline — recent events (paginated)
GET /api/dashboard/top-targets — most targeted users/services
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import ThreatEvent, Incident
from app.schemas import DashboardSummary

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Return aggregate statistics for the command dashboard."""
    total = db.query(func.count(ThreatEvent.id)).scalar() or 0
    threats = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.risk_level.notin_(["Safe"])
    ).scalar() or 0
    phishing = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.threat_type == "Phishing"
    ).scalar() or 0
    impersonation = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.threat_type == "Impersonation"
    ).scalar() or 0
    deepfakes = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.threat_type.like("Deepfake%")
    ).scalar() or 0
    account_takeover = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.threat_type.in_(["Account Takeover", "Brute Force", "Password Spray", "Impossible Travel"])
    ).scalar() or 0
    api_abuse = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.threat_type.in_(["api_abuse", "API Abuse"])
    ).scalar() or 0
    critical = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.risk_level == "Critical"
    ).scalar() or 0
    high = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.risk_level == "High"
    ).scalar() or 0

    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = db.query(func.count(ThreatEvent.id)).filter(
        ThreatEvent.created_at >= since_24h
    ).scalar() or 0

    return DashboardSummary(
        total_events=total,
        threats_detected=threats,
        phishing_attempts=phishing,
        impersonation_attempts=impersonation,
        suspected_deepfakes=deepfakes,
        account_takeover_attempts=account_takeover,
        api_abuse_attempts=api_abuse,
        critical_count=critical,
        high_count=high,
        events_last_24h=last_24h,
    )


@router.get("/timeline")
def get_timeline(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    risk_level: Optional[str] = Query(None),
    threat_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return recent threat events for the live timeline (most recent first)."""
    q = db.query(ThreatEvent)
    if risk_level:
        q = q.filter(ThreatEvent.risk_level == risk_level)
    if threat_type:
        q = q.filter(ThreatEvent.threat_type == threat_type)

    events = q.order_by(desc(ThreatEvent.created_at)).offset(offset).limit(limit).all()

    return [
        {
            "id": e.id,
            "threat_type": e.threat_type,
            "risk_level": e.risk_level,
            "risk_score": e.risk_score,
            "confidence": e.confidence,
            "indicators": e.indicators or [],
            "explanation": e.explanation,
            "recommended_actions": e.recommended_actions or [],
            "raw_input_summary": e.raw_input_summary,
            "source_ip": e.source_ip,
            "target_user": e.target_user,
            "target_service": e.target_service,
            "mitre_tag": e.mitre_tag,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "incident_status": e.incident.status if e.incident else "Open",
        }
        for e in events
    ]


@router.get("/top-targets")
def get_top_targets(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Return most frequently targeted users and services."""
    user_counts = (
        db.query(ThreatEvent.target_user, func.count(ThreatEvent.id).label("count"))
        .filter(ThreatEvent.target_user.isnot(None))
        .filter(ThreatEvent.target_user != "")
        .group_by(ThreatEvent.target_user)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    service_counts = (
        db.query(ThreatEvent.target_service, func.count(ThreatEvent.id).label("count"))
        .filter(ThreatEvent.target_service.isnot(None))
        .filter(ThreatEvent.target_service != "")
        .group_by(ThreatEvent.target_service)
        .order_by(desc("count"))
        .limit(limit)
        .all()
    )
    return {
        "top_users": [{"name": u, "count": c} for u, c in user_counts],
        "top_services": [{"name": s, "count": c} for s, c in service_counts],
    }


@router.get("/threat-distribution")
def get_threat_distribution(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Counts by threat_type for charts."""
    rows = (
        db.query(ThreatEvent.threat_type, func.count(ThreatEvent.id).label("count"))
        .group_by(ThreatEvent.threat_type)
        .order_by(desc("count"))
        .all()
    )
    return [{"threat_type": tt, "count": c} for tt, c in rows]


@router.get("/risk-distribution")
def get_risk_distribution(db: Session = Depends(get_db)) -> List[Dict[str, Any]]:
    """Counts by risk_level for charts."""
    rows = (
        db.query(ThreatEvent.risk_level, func.count(ThreatEvent.id).label("count"))
        .group_by(ThreatEvent.risk_level)
        .all()
    )
    return [{"risk_level": rl, "count": c} for rl, c in rows]
