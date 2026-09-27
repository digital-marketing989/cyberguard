"""
Incidents router — CRUD + status lifecycle management
GET    /api/incidents/
GET    /api/incidents/{id}
POST   /api/incidents/
PATCH  /api/incidents/{id}
DELETE /api/incidents/{id}
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Incident, ThreatEvent
from app.schemas import IncidentCreate, IncidentResponse, IncidentUpdate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("/", response_model=List[Dict[str, Any]])
def list_incidents(
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List incidents with optional status filter."""
    q = db.query(Incident).join(ThreatEvent, Incident.event_id == ThreatEvent.id)
    if status:
        q = q.filter(Incident.status == status)
    incidents = q.order_by(Incident.created_at.desc()).offset(offset).limit(limit).all()

    return [
        {
            "id": inc.id,
            "event_id": inc.event_id,
            "status": inc.status,
            "assigned_to": inc.assigned_to,
            "notes": inc.notes,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
            "event": {
                "threat_type": inc.event.threat_type,
                "risk_level": inc.event.risk_level,
                "risk_score": inc.event.risk_score,
                "indicators": inc.event.indicators or [],
                "explanation": inc.event.explanation,
                "recommended_actions": inc.event.recommended_actions or [],
                "mitre_tag": inc.event.mitre_tag,
                "created_at": inc.event.created_at.isoformat() if inc.event.created_at else None,
            },
        }
        for inc in incidents
    ]


@router.get("/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {
        "id": inc.id,
        "event_id": inc.event_id,
        "status": inc.status,
        "assigned_to": inc.assigned_to,
        "notes": inc.notes,
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        "event": {
            "threat_type": inc.event.threat_type,
            "risk_level": inc.event.risk_level,
            "risk_score": inc.event.risk_score,
            "confidence": inc.event.confidence,
            "indicators": inc.event.indicators or [],
            "explanation": inc.event.explanation,
            "recommended_actions": inc.event.recommended_actions or [],
            "raw_input_summary": inc.event.raw_input_summary,
            "mitre_tag": inc.event.mitre_tag,
            "extra_data": inc.event.extra_data,
            "created_at": inc.event.created_at.isoformat() if inc.event.created_at else None,
        },
    }


@router.post("/", response_model=IncidentResponse)
def create_incident(payload: IncidentCreate, db: Session = Depends(get_db)):
    """Manually create an incident for an existing event."""
    event = db.query(ThreatEvent).filter(ThreatEvent.id == payload.event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="ThreatEvent not found")
    existing = db.query(Incident).filter(Incident.event_id == payload.event_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Incident already exists for this event")

    inc = Incident(
        event_id=payload.event_id,
        assigned_to=payload.assigned_to,
        notes=payload.notes,
        status="Open",
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return inc


@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    db: Session = Depends(get_db),
):
    """Update incident status, assignee, or notes."""
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")

    if payload.status is not None:
        inc.status = payload.status
    if payload.assigned_to is not None:
        inc.assigned_to = payload.assigned_to
    if payload.notes is not None:
        inc.notes = payload.notes

    db.commit()
    db.refresh(inc)
    return inc


@router.delete("/{incident_id}")
def delete_incident(incident_id: int, db: Session = Depends(get_db)):
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.delete(inc)
    db.commit()
    return {"message": f"Incident {incident_id} deleted"}
