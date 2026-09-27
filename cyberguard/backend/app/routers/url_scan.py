"""
URL Scan router
POST /api/url/scan
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import List, Tuple

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.engines.explainer import generate_explanation
from app.engines.risk_scorer import RiskScorer, get_mitre_tag, score_to_level, clamp
from app.models import ThreatEvent
from app.response.action_recommender import recommend_actions
from app.schemas import DetectionResult, URLScanRequest
from app.websocket_manager import ws_manager

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

try:
    from Levenshtein import distance as levenshtein_distance
    _HAS_LEVENSHTEIN = True
except ImportError:
    _HAS_LEVENSHTEIN = False

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/url", tags=["URL Scan"])

KNOWN_BRANDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "ebay", "chase",
    "bankofamerica", "wellsfargo", "citibank", "dropbox", "adobe",
    "outlook", "yahoo", "icloud", "americanexpress", "dhl", "fedex",
    "ups", "irs",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
    ".online", ".site", ".work", ".click", ".link", ".download",
    ".zip", ".mov",
}

PHISHING_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update",
    "banking", "confirm", "wallet", "password", "credential",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link",
    "buff.ly", "rb.gy", "cutt.ly",
}

IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _extract_domain(url: str) -> str:
    if _HAS_TLDEXTRACT:
        ext = tldextract.extract(url)
        return f"{ext.domain}.{ext.suffix}".lower()
    # fallback
    match = re.search(r"https?://([^/?\s]+)", url)
    return match.group(1).lower() if match else url.lower()


def _get_hostname(url: str) -> str:
    match = re.search(r"https?://([^/?\s:]+)", url)
    return match.group(1).lower() if match else url.lower()


def analyze_url(url: str) -> Tuple[float, float, float, float, float, float, List[str]]:
    """
    Returns (typosquatting, suspicious_tld, ip_as_domain, excessive_subdomains,
             ssl_missing, keyword_match, indicators)
    Each score 0-100.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    indicators: List[str] = []
    hostname = _get_hostname(url)
    domain = _extract_domain(url)
    parts = hostname.split(".")
    url_lower = url.lower()

    # ── IP as domain ────────────────────────────────────────────────────────
    ip_score = 0.0
    if IP_RE.match(hostname):
        ip_score = 90.0
        indicators.append(f"URL uses raw IP address instead of domain: {hostname}")

    # ── Suspicious TLD ─────────────────────────────────────────────────────
    tld_score = 0.0
    for tld in SUSPICIOUS_TLDS:
        if url_lower.endswith(tld) or ("." + tld.lstrip(".")) in domain:
            tld_score = 60.0
            indicators.append(f"Suspicious TLD detected: {tld}")
            break

    # ── Typosquatting ──────────────────────────────────────────────────────
    typo_score = 0.0
    domain_part = domain.split(".")[0]
    if _HAS_LEVENSHTEIN:
        for brand in KNOWN_BRANDS:
            if domain_part == brand:
                break  # exact match is fine
            dist = levenshtein_distance(domain_part, brand)
            if 0 < dist <= 3 and len(brand) >= 4:
                typo_score = min(80.0, 40 + (4 - dist) * 10)
                indicators.append(
                    f"Typosquatting detected: '{domain_part}' ≈ '{brand}' (edit distance: {dist})"
                )
                break

    # ── Excessive subdomains ───────────────────────────────────────────────
    subdomain_score = 0.0
    if len(parts) > 4:
        subdomain_score = min(50.0, (len(parts) - 4) * 10)
        indicators.append(f"Excessive subdomains ({len(parts)}): {hostname[:60]}")

    # ── SSL check ─────────────────────────────────────────────────────────
    ssl_score = 0.0
    if url.startswith("http://") and not hostname.startswith("localhost"):
        ssl_score = 30.0
        indicators.append("URL uses HTTP instead of HTTPS — no SSL encryption")

    # ── Phishing keyword match ─────────────────────────────────────────────
    kw_score = 0.0
    matched_kw = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if matched_kw:
        kw_score = min(50.0, len(matched_kw) * 10)
        indicators.append(f"Phishing keywords in URL: {', '.join(matched_kw[:4])}")

    # ── URL shortener ──────────────────────────────────────────────────────
    for sh in URL_SHORTENERS:
        if sh in hostname:
            indicators.append(f"URL shortener detected ({sh}) — destination obscured")
            kw_score = max(kw_score, 30.0)
            break

    # ── Long URL with many parameters (obfuscation) ────────────────────────
    if len(url) > 200:
        indicators.append(f"Suspiciously long URL ({len(url)} characters)")
        kw_score = min(100.0, kw_score + 15)

    return (
        clamp(typo_score),
        clamp(tld_score),
        clamp(ip_score),
        clamp(subdomain_score),
        clamp(ssl_score),
        clamp(kw_score),
        indicators,
    )


@router.post("/scan", response_model=DetectionResult)
async def scan_url(
    request: URLScanRequest,
    db: Session = Depends(get_db),
):
    """Scan a URL for malicious indicators."""
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    (typo_score, tld_score, ip_score, subdomain_score,
     ssl_score, kw_score, indicators) = analyze_url(url)

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

    explanation = await generate_explanation(
        threat_type="Malicious URL",
        risk_level=risk_level,
        risk_score=risk_score,
        indicators=indicators,
    )
    actions = recommend_actions("Malicious URL", risk_level)
    mitre = get_mitre_tag("Malicious URL")

    event = ThreatEvent(
        threat_type="Malicious URL",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        raw_input_summary=url[:500],
        mitre_tag=mitre,
        extra_data={
            "url": url,
            "typosquatting_score": typo_score,
            "tld_score": tld_score,
            "ip_domain_score": ip_score,
        },
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    await ws_manager.broadcast({
        "event_id": event.id,
        "threat_type": "Malicious URL",
        "risk_level": risk_level,
        "risk_score": risk_score,
        "timestamp": event.created_at.isoformat() if event.created_at else datetime.utcnow().isoformat(),
        "summary": f"URL scan: {url[:60]}",
    })

    return DetectionResult(
        threat_type="Malicious URL",
        risk_level=risk_level,
        risk_score=risk_score,
        confidence=confidence,
        indicators=indicators,
        explanation=explanation,
        recommended_actions=actions,
        mitre_tag=mitre,
        timestamp=event.created_at or datetime.utcnow(),
        extra_data={"event_id": event.id, "url": url},
    )
