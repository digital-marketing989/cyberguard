"""
CyberGuard Unified Risk Scorer
Converts raw sub-scores from engines into a normalised risk_score (0-100)
and a categorical risk_level (Safe / Low / Medium / High / Critical).

Thresholds (documented in README):
    Safe:     0  – 15
    Low:     16  – 35
    Medium:  36  – 60
    High:    61  – 80
    Critical:81  – 100
"""
from __future__ import annotations
from typing import Dict, Optional
from app.config import settings


RISK_THRESHOLDS = [
    (settings.RISK_SAFE_MAX,    "Safe"),
    (settings.RISK_LOW_MAX,     "Low"),
    (settings.RISK_MEDIUM_MAX,  "Medium"),
    (settings.RISK_HIGH_MAX,    "High"),
    (101,                       "Critical"),
]

# MITRE ATT&CK static mapping (prototype)
MITRE_MAP: Dict[str, str] = {
    "Phishing":           "T1566 – Phishing",
    "Malicious URL":      "T1189 – Drive-by Compromise",
    "Deepfake Image":     "T1036 – Masquerading",
    "Deepfake Audio":     "T1036 – Masquerading",
    "Deepfake Video":     "T1036 – Masquerading",
    "Impersonation":      "T1656 – Impersonation",
    "Account Takeover":   "T1078 – Valid Accounts",
    "Brute Force":        "T1110 – Brute Force",
    "Password Spray":     "T1110.003 – Password Spraying",
    "Impossible Travel":  "T1078 – Valid Accounts",
    "Network Anomaly":    "T1046 – Network Service Discovery",
    "qr_phishing":        "T1566.002 – Spearphishing Link (QR/Quishing)",
    "QR Phishing":        "T1566.002 – Spearphishing Link (QR/Quishing)",
    "api_abuse":          "T1059 – Command and Scripting Interpreter (API Abuse)",
    "API Abuse":          "T1059 – Command and Scripting Interpreter (API Abuse)",
}


def score_to_level(score: float) -> str:
    """Convert numeric score to categorical risk level."""
    score = max(0.0, min(100.0, float(score)))
    for threshold, label in RISK_THRESHOLDS:
        if score <= threshold:
            return label
    return "Critical"


def compute_weighted_score(
    sub_scores: Dict[str, float],
    weights: Optional[Dict[str, float]] = None,
) -> float:
    """
    Compute a weighted average of sub-scores.

    Args:
        sub_scores: dict of { component_name: score_0_to_100 }
        weights:    optional dict of { component_name: weight }
                    If None, uniform weighting is used.

    Returns:
        Final score 0-100 (float).
    """
    if not sub_scores:
        return 0.0

    if weights is None:
        weights = {k: 1.0 for k in sub_scores}

    total_weight = sum(weights.get(k, 1.0) for k in sub_scores)
    if total_weight == 0:
        return 0.0

    weighted_sum = sum(
        sub_scores[k] * weights.get(k, 1.0) for k in sub_scores
    )
    return round(weighted_sum / total_weight, 2)


def get_mitre_tag(threat_type: str) -> Optional[str]:
    return MITRE_MAP.get(threat_type)


def clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


class RiskScorer:
    """
    Single entry-point for converting engine-specific sub-scores
    to the standard { risk_score, risk_level } output.
    """

    @staticmethod
    def score_phishing(
        ml_score: float,
        rule_score: float,
        url_score: float = 0.0,
    ) -> float:
        """Phishing: ML model (40%) + rule indicators (40%) + URL checks (20%)."""
        return compute_weighted_score(
            {"ml": ml_score, "rule": rule_score, "url": url_score},
            {"ml": 0.40, "rule": 0.40, "url": 0.20},
        )

    @staticmethod
    def score_url(
        typosquatting: float,
        suspicious_tld: float,
        ip_as_domain: float,
        excessive_subdomains: float,
        ssl_missing: float,
        keyword_match: float,
    ) -> float:
        """URL: weighted combination of heuristic checks."""
        return compute_weighted_score(
            {
                "typosquatting": typosquatting,
                "suspicious_tld": suspicious_tld,
                "ip_as_domain": ip_as_domain,
                "excessive_subdomains": excessive_subdomains,
                "ssl_missing": ssl_missing,
                "keyword_match": keyword_match,
            },
            {
                "typosquatting": 0.30,
                "suspicious_tld": 0.20,
                "ip_as_domain": 0.20,
                "excessive_subdomains": 0.10,
                "ssl_missing": 0.10,
                "keyword_match": 0.10,
            },
        )

    @staticmethod
    def score_deepfake(artifact_score: float, cnn_score: float = 0.0) -> float:
        """Deepfake: heuristic artifacts (60%) + CNN if available (40%)."""
        if cnn_score == 0.0:
            return clamp(artifact_score)
        return compute_weighted_score(
            {"artifact": artifact_score, "cnn": cnn_score},
            {"artifact": 0.60, "cnn": 0.40},
        )

    @staticmethod
    def score_impersonation(
        domain_mismatch: float,
        authority_claim: float,
        urgency: float,
        style_deviation: float,
    ) -> float:
        """Impersonation: domain mismatch (35%) + authority (25%) + urgency (20%) + style (20%)."""
        return compute_weighted_score(
            {
                "domain_mismatch": domain_mismatch,
                "authority_claim": authority_claim,
                "urgency": urgency,
                "style_deviation": style_deviation,
            },
            {
                "domain_mismatch": 0.35,
                "authority_claim": 0.25,
                "urgency": 0.20,
                "style_deviation": 0.20,
            },
        )

    @staticmethod
    def score_auth_anomaly(
        failed_login_rate: float,
        impossible_travel: float,
        new_device: float,
        brute_force: float,
        password_spray: float,
    ) -> float:
        """Auth anomaly: weighted combination of login behaviour signals."""
        return compute_weighted_score(
            {
                "failed_login_rate": failed_login_rate,
                "impossible_travel": impossible_travel,
                "new_device": new_device,
                "brute_force": brute_force,
                "password_spray": password_spray,
            },
            {
                "failed_login_rate": 0.20,
                "impossible_travel": 0.25,
                "new_device": 0.15,
                "brute_force": 0.20,
                "password_spray": 0.20,
            },
        )
