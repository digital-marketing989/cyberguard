"""
Impersonation analysis router
POST /api/impersonation/analyze
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.engines.explainer import generate_explanation
from app.engines.impersonation_engine import get_impersonation_engine
from app.engines.risk_scorer import RiskScorer, get_mitre_tag, score_to_level
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import DetectionResult, ImpersonationRequest
from app.websocket_manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/impersonation", tags=["Impersonation"])


@router.post("/analyze", response_model=DetectionResult)
async def analyze_impersonation(
    request: ImpersonationRequest,
    db: Session = Depends(get_db),
):
    """Analyze a message for digital impersonation indicators."""
    engine = get_impersonation_engine()
    result = engine.analyze(
        display_name=request.display_name,
        email_address=request.email_address,
        claimed_role=request.claimed_role,
        claimed_organisation=request.claimed_organisation,
        message_body=request.message_body,
        subject=request.subject,
    )

    risk_score = RiskScorer.score_impersonation(
        domain_mismatch=result["domain_mismatch_score"],
        authority_claim=result["authority_claim_score"],
        urgency=result["urgency_score"],
        style_deviation=result["style_deviation_score"],
    )
    risk_level = score_to_level(risk_score)
    indicators = result["indicators"]
    confidence = result["confidence"]

    explanation = await generate_explanation(
        threat_type="Impersonation",
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
    )
    actions = recommend_actions("Impersonation", risk_level)
    mitre = get_mitre_tag("Impersonation")

    event = ThreatEvent(
        threat_type="Impersonation",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=f"From: {request.display_name} <{request.email_address or 'unknown'}> | {request.message_body[:200]}",
        target_user=request.display_name,
        mitre_tag=mitre,
        extra_data={
            "domain_mismatch_score": result["domain_mismatch_score"],
            "authority_claim_score": result["authority_claim_score"],
            "urgency_score": result["urgency_score"],
            "style_deviation_score": result["style_deviation_score"],
        },
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    await ws_manager.broadcast({
        "event_id": event.id,
        "threat_type": "Impersonation",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.utcnow().isoformat(),
        "summary": f"Impersonation attempt by '{request.display_name}'",
    })

    return DetectionResult(
        threat_type="Impersonation",
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
