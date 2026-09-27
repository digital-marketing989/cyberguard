"""SQLAlchemy ORM Models for CyberGuard"""
from sqlalchemy import (
    Column, Integer, String, Float, Text, DateTime, Boolean,
    ForeignKey, JSON, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import enum
from app.database import Base


class RiskLevel(str, enum.Enum):
    SAFE = "Safe"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class ThreatType(str, enum.Enum):
    PHISHING = "Phishing"
    MALICIOUS_URL = "Malicious URL"
    DEEPFAKE_IMAGE = "Deepfake Image"
    DEEPFAKE_AUDIO = "Deepfake Audio"
    DEEPFAKE_VIDEO = "Deepfake Video"
    IMPERSONATION = "Impersonation"
    ACCOUNT_TAKEOVER = "Account Takeover"
    BRUTE_FORCE = "Brute Force"
    PASSWORD_SPRAY = "Password Spray"
    IMPOSSIBLE_TRAVEL = "Impossible Travel"
    NETWORK_ANOMALY = "Network Anomaly"
    UNKNOWN = "Unknown"


class IncidentStatus(str, enum.Enum):
    OPEN = "Open"
    ACKNOWLEDGED = "Acknowledged"
    INVESTIGATING = "Investigating"
    RESOLVED = "Resolved"
    ESCALATED = "Escalated"
    FALSE_POSITIVE = "False Positive"


class ThreatEvent(Base):
    """
    Core record for every threat detection event.
    Every analysis call creates one ThreatEvent.
    """
    __tablename__ = "threat_events"

    id = Column(Integer, primary_key=True, index=True)
    threat_type = Column(String(64), nullable=False)
    risk_level = Column(String(16), nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    indicators = Column(JSON, default=list)
    explanation = Column(Text, nullable=True)
    recommended_actions = Column(JSON, default=list)
    raw_input_summary = Column(Text, nullable=True)  # truncated preview of input
    source_ip = Column(String(64), nullable=True)
    target_user = Column(String(128), nullable=True)
    target_service = Column(String(128), nullable=True)
    mitre_tag = Column(String(128), nullable=True)
    extra_data = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationship to incident
    incident = relationship("Incident", back_populates="event", uselist=False)


class Incident(Base):
    """
    Incident lifecycle tracking (Acknowledge / Escalate / Resolve).
    One-to-one with ThreatEvent.
    """
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("threat_events.id"), unique=True, nullable=False)
    status = Column(String(32), default=IncidentStatus.OPEN)
    assigned_to = Column(String(128), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    event = relationship("ThreatEvent", back_populates="incident")


class AuthLog(Base):
    """
    Simulated / uploaded authentication log entries.
    """
    __tablename__ = "auth_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), nullable=False, index=True)
    ip_address = Column(String(64), nullable=True)
    geo_country = Column(String(64), nullable=True)
    geo_city = Column(String(128), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    device_fingerprint = Column(String(256), nullable=True)
    success = Column(Boolean, default=True)
    failure_reason = Column(String(128), nullable=True)
    user_agent = Column(String(512), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    is_synthetic = Column(Boolean, default=True)


class KnownContact(Base):
    """
    Reference table for impersonation detection.
    Maps display names / roles to legitimate email domains.
    """
    __tablename__ = "known_contacts"

    id = Column(Integer, primary_key=True, index=True)
    display_name = Column(String(256), nullable=False)
    email_address = Column(String(256), nullable=True)
    domain = Column(String(256), nullable=False)
    role = Column(String(128), nullable=True)
    organisation = Column(String(256), nullable=True)
    is_executive = Column(Boolean, default=False)


class DashboardStats(Base):
    """
    Cached hourly stats for the dashboard (avoid expensive aggregation on each request).
    """
    __tablename__ = "dashboard_stats"

    id = Column(Integer, primary_key=True, index=True)
    stat_key = Column(String(128), unique=True, nullable=False)
    stat_value = Column(Float, default=0)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
