"""
Intelligent Response Recommender
Maps threat_type + risk_level -> ordered list of recommended response actions.
"""
from __future__ import annotations
from typing import List, Tuple, Dict

# ─── Standard Action Library ───────────────────────────────────────────────────
BLOCK_URL = "Block suspicious URL"
QUARANTINE_EMAIL = "Quarantine email"
WARN_USER = "Warn the user"
REQUIRE_AUTH = "Require additional authentication"
REVOKE_SESSION = "Revoke active session"
BLOCK_DEVICE = "Block suspicious IP/device"
FLAG_MULTIMEDIA = "Flag multimedia for manual verification"
REPORT_IMPERSONATION = "Report impersonation"
NOTIFY_SOC = "Notify administrator/SOC"
ESCALATE = "Escalate the incident for investigation"

# Additional contextual helpers
PRESERVE_EVIDENCE = "Preserve logs, screenshots, and metadata as evidence"
ENABLE_MONITORING = "Enable enhanced monitoring for 72 hours"
NO_ACTION = "No action required"


# ─── Action Rule Table ────────────────────────────────────────────────────────
# Key: (threat_type_substring, risk_level) -> ordered action list
_RULES: List[Tuple[Tuple[str, str], List[str]]] = [
    # ── Phishing ──────────────────────────────────────────────────────────────
    (("Phishing", "Safe"),     [ENABLE_MONITORING]),
    (("Phishing", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("Phishing", "Medium"),   [QUARANTINE_EMAIL, WARN_USER, BLOCK_URL]),
    (("Phishing", "High"),     [QUARANTINE_EMAIL, BLOCK_URL, WARN_USER, REQUIRE_AUTH, NOTIFY_SOC]),
    (("Phishing", "Critical"), [QUARANTINE_EMAIL, BLOCK_URL, BLOCK_DEVICE, REQUIRE_AUTH, NOTIFY_SOC, ESCALATE]),

    # ── QR-Code Phishing ──────────────────────────────────────────────────────
    (("qr_phishing", "Safe"),     [NO_ACTION]),
    (("qr_phishing", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("qr_phishing", "Medium"),   [BLOCK_URL, WARN_USER, FLAG_MULTIMEDIA]),
    (("qr_phishing", "High"),     [BLOCK_URL, BLOCK_DEVICE, WARN_USER, NOTIFY_SOC]),
    (("qr_phishing", "Critical"), [BLOCK_URL, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),
    (("QR Phishing", "Safe"),     [NO_ACTION]),
    (("QR Phishing", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("QR Phishing", "Medium"),   [BLOCK_URL, WARN_USER, FLAG_MULTIMEDIA]),
    (("QR Phishing", "High"),     [BLOCK_URL, BLOCK_DEVICE, WARN_USER, NOTIFY_SOC]),
    (("QR Phishing", "Critical"), [BLOCK_URL, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),

    # ── Malicious URL ─────────────────────────────────────────────────────────
    (("Malicious URL", "Safe"),     [NO_ACTION]),
    (("Malicious URL", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("Malicious URL", "Medium"),   [BLOCK_URL, WARN_USER]),
    (("Malicious URL", "High"),     [BLOCK_URL, BLOCK_DEVICE, WARN_USER, NOTIFY_SOC]),
    (("Malicious URL", "Critical"), [BLOCK_URL, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),

    # ── Deepfake ──────────────────────────────────────────────────────────────
    (("Deepfake", "Safe"),     [NO_ACTION]),
    (("Deepfake", "Low"),      [FLAG_MULTIMEDIA, WARN_USER]),
    (("Deepfake", "Medium"),   [FLAG_MULTIMEDIA, REPORT_IMPERSONATION, WARN_USER]),
    (("Deepfake", "High"),     [FLAG_MULTIMEDIA, REPORT_IMPERSONATION, NOTIFY_SOC]),
    (("Deepfake", "Critical"), [FLAG_MULTIMEDIA, REPORT_IMPERSONATION, NOTIFY_SOC, ESCALATE]),

    # ── Impersonation ─────────────────────────────────────────────────────────
    (("Impersonation", "Safe"),     [NO_ACTION]),
    (("Impersonation", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("Impersonation", "Medium"),   [WARN_USER, REPORT_IMPERSONATION]),
    (("Impersonation", "High"),     [QUARANTINE_EMAIL, REPORT_IMPERSONATION, WARN_USER, NOTIFY_SOC]),
    (("Impersonation", "Critical"), [QUARANTINE_EMAIL, BLOCK_DEVICE, REPORT_IMPERSONATION, NOTIFY_SOC, ESCALATE]),

    # ── Account Takeover ──────────────────────────────────────────────────────
    (("Account Takeover", "Safe"),     [NO_ACTION]),
    (("Account Takeover", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("Account Takeover", "Medium"),   [REQUIRE_AUTH, WARN_USER]),
    (("Account Takeover", "High"),     [REVOKE_SESSION, REQUIRE_AUTH, BLOCK_DEVICE, NOTIFY_SOC]),
    (("Account Takeover", "Critical"), [REVOKE_SESSION, REQUIRE_AUTH, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),

    # ── Brute Force ───────────────────────────────────────────────────────────
    (("Brute Force", "Safe"),     [NO_ACTION]),
    (("Brute Force", "Low"),      [ENABLE_MONITORING]),
    (("Brute Force", "Medium"),   [BLOCK_DEVICE, REQUIRE_AUTH]),
    (("Brute Force", "High"),     [BLOCK_DEVICE, REQUIRE_AUTH, NOTIFY_SOC]),
    (("Brute Force", "Critical"), [BLOCK_DEVICE, REVOKE_SESSION, REQUIRE_AUTH, NOTIFY_SOC, ESCALATE]),

    # ── Password Spray ────────────────────────────────────────────────────────
    (("Password Spray", "Safe"),     [NO_ACTION]),
    (("Password Spray", "Low"),      [ENABLE_MONITORING]),
    (("Password Spray", "Medium"),   [BLOCK_DEVICE, REQUIRE_AUTH, WARN_USER]),
    (("Password Spray", "High"),     [BLOCK_DEVICE, REQUIRE_AUTH, NOTIFY_SOC]),
    (("Password Spray", "Critical"), [BLOCK_DEVICE, REVOKE_SESSION, REQUIRE_AUTH, NOTIFY_SOC, ESCALATE]),

    # ── Impossible Travel ─────────────────────────────────────────────────────
    (("Impossible Travel", "Safe"),     [NO_ACTION]),
    (("Impossible Travel", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("Impossible Travel", "Medium"),   [REQUIRE_AUTH, WARN_USER]),
    (("Impossible Travel", "High"),     [REVOKE_SESSION, REQUIRE_AUTH, BLOCK_DEVICE, NOTIFY_SOC]),
    (("Impossible Travel", "Critical"), [REVOKE_SESSION, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),

    # ── Network Anomaly / Intrusion ───────────────────────────────────────────
    (("Network Anomaly", "Safe"),     [NO_ACTION]),
    (("Network Anomaly", "Low"),      [ENABLE_MONITORING]),
    (("Network Anomaly", "Medium"),   [BLOCK_DEVICE, WARN_USER]),
    (("Network Anomaly", "High"),     [BLOCK_DEVICE, NOTIFY_SOC]),
    (("Network Anomaly", "Critical"), [BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),
    (("network_intrusion", "Safe"),     [NO_ACTION]),
    (("network_intrusion", "Low"),      [ENABLE_MONITORING]),
    (("network_intrusion", "Medium"),   [BLOCK_DEVICE, WARN_USER]),
    (("network_intrusion", "High"),     [BLOCK_DEVICE, NOTIFY_SOC]),
    (("network_intrusion", "Critical"), [BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),

    # ── API Abuse ─────────────────────────────────────────────────────────────
    (("api_abuse", "Safe"),     [NO_ACTION]),
    (("api_abuse", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("api_abuse", "Medium"),   [REQUIRE_AUTH, REVOKE_SESSION, WARN_USER]),
    (("api_abuse", "High"),     [REVOKE_SESSION, BLOCK_DEVICE, REQUIRE_AUTH, NOTIFY_SOC]),
    (("api_abuse", "Critical"), [REVOKE_SESSION, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),
    (("API Abuse", "Safe"),     [NO_ACTION]),
    (("API Abuse", "Low"),      [WARN_USER, ENABLE_MONITORING]),
    (("API Abuse", "Medium"),   [REQUIRE_AUTH, REVOKE_SESSION, WARN_USER]),
    (("API Abuse", "High"),     [REVOKE_SESSION, BLOCK_DEVICE, REQUIRE_AUTH, NOTIFY_SOC]),
    (("API Abuse", "Critical"), [REVOKE_SESSION, BLOCK_DEVICE, NOTIFY_SOC, ESCALATE]),
]

_DEFAULT_ACTIONS: Dict[str, List[str]] = {
    "Safe":     [NO_ACTION],
    "Low":      [WARN_USER, ENABLE_MONITORING],
    "Medium":   [WARN_USER, NOTIFY_SOC],
    "High":     [NOTIFY_SOC, PRESERVE_EVIDENCE],
    "Critical": [NOTIFY_SOC, ESCALATE, PRESERVE_EVIDENCE],
}


def recommend_actions(threat_type: str, risk_level: str) -> List[str]:
    """
    Return an ordered list of recommended response actions
    for the given threat_type and risk_level.

    Higher risk levels (High/Critical) will always include "Notify administrator/SOC"
    and Critical will also include "Escalate the incident for investigation".
    """
    tt_lower = (threat_type or "").strip().lower()
    rl_title = (risk_level or "Medium").strip().capitalize()

    matched: List[str] | None = None

    # 1. Exact match on threat_type + risk_level
    for (rule_tt, rule_rl), actions in _RULES:
        if rule_tt.lower() in tt_lower and rule_rl.lower() == rl_title.lower():
            matched = list(actions)
            break

    # 2. Fallback: match threat_type only with matching risk_level
    if matched is None:
        for (rule_tt, rule_rl), actions in _RULES:
            if rule_tt.lower() in tt_lower:
                matched = list(actions)
                break

    # 3. Fallback to default by risk level
    if matched is None:
        matched = list(_DEFAULT_ACTIONS.get(rl_title, [WARN_USER, NOTIFY_SOC]))

    # Enforce mandatory rules:
    # High/Critical must always include "Notify administrator/SOC"
    if rl_title in ("High", "Critical") and NOTIFY_SOC not in matched:
        matched.append(NOTIFY_SOC)

    # Critical must always include "Escalate the incident for investigation"
    if rl_title == "Critical" and ESCALATE not in matched:
        matched.append(ESCALATE)

    return matched
