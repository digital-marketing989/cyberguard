"""
Pydantic request/response schemas for CyberGuard API
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum


# ─── Enums ────────────────────────────────────────────────────────────────────

class RiskLevel(str, Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class IncidentStatus(str, Enum):
    OPEN = "Open"
    ACKNOWLEDGED = "Acknowledged"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    ESCALATED = "Escalated"
    FALSE_POSITIVE = "False Positive"


# ─── Standard Detection Response ──────────────────────────────────────────────

class DetectionResult(BaseModel):
    """Standard response contract returned by every detection engine."""
    threat_type: str
    risk_level: RiskLevel
    risk_score: float = Field(ge=0, le=100)
    confidence: float = Field(ge=0, le=1)
    indicators: List[str] = []
    explanation: str = ""
    recommended_actions: List[str] = []
    mitre_tag: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    extra_data: Dict[str, Any] = {}


# ─── Phishing ─────────────────────────────────────────────────────────────────

class PhishingTextRequest(BaseModel):
    text: str = Field(..., min_length=5, max_length=50000, description="Email/SMS body to analyze")
    sender: Optional[str] = Field(None, description="Sender email address or phone")
    subject: Optional[str] = Field(None, description="Email subject line")


class URLScanRequest(BaseModel):
    url: str = Field(..., description="URL to analyze")


# ─── Impersonation ────────────────────────────────────────────────────────────

class ImpersonationRequest(BaseModel):
    display_name: str = Field(..., description="Claimed sender name")
    email_address: Optional[str] = None
    claimed_role: Optional[str] = None
    claimed_organisation: Optional[str] = None
    message_body: str = Field(..., min_length=5)
    subject: Optional[str] = None


# ─── Auth Anomaly ─────────────────────────────────────────────────────────────

class AuthLogEntry(BaseModel):
    username: str
    timestamp: str
    ip_address: str
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    device_fingerprint: Optional[str] = None
    success: bool = True
    failure_reason: Optional[str] = None
    user_agent: Optional[str] = None


class AuthAnalysisRequest(BaseModel):
    logs: List[AuthLogEntry]


# ─── Incident Management ──────────────────────────────────────────────────────

class IncidentCreate(BaseModel):
    event_id: int
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class IncidentUpdate(BaseModel):
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class IncidentResponse(BaseModel):
    id: int
    event_id: int
    status: IncidentStatus
    assigned_to: Optional[str]
    notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class ThreatEventResponse(BaseModel):
    id: int
    threat_type: str
    risk_level: str
    risk_score: float
    confidence: float
    indicators: List[str]
    explanation: Optional[str]
    recommended_actions: List[str]
    raw_input_summary: Optional[str]
    source_ip: Optional[str]
    target_user: Optional[str]
    target_service: Optional[str]
    mitre_tag: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ─── Dashboard ────────────────────────────────────────────────────────────────

class DashboardSummary(BaseModel):
    total_events: int
    threats_detected: int
    phishing_attempts: int
    impersonation_attempts: int
    suspected_deepfakes: int
    account_takeover_attempts: int
    api_abuse_attempts: int = 0
    critical_count: int
    high_count: int
    events_last_24h: int


class NetworkAnalysisRequest(BaseModel):
    logs: Optional[List[Dict[str, Any]]] = None
    use_sample: bool = True
