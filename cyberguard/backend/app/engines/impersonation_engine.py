"""
CyberGuard Impersonation Detection Engine
──────────────────────────────────────────
Compares message metadata against a "known contacts" reference table and
flags mismatches using:
  - Domain mismatch (claimed org vs actual sender domain)
  - Authority + external-domain combination
  - Urgent financial/credential requests from unknown senders
  - Simple stylometry deviation (TF-IDF cosine similarity vs message history)
  - Lookalike display-name detection (Levenshtein)
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from Levenshtein import distance as levenshtein_distance
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

# ─── Known legitimate contacts / officials reference table ────────────────────
# In production, this would be loaded from the DB (KnownContact model).
# For the prototype, we ship a built-in reference table.
KNOWN_CONTACTS: List[Dict[str, Any]] = [
    {"display_name": "IT Department",      "domain": "company.com",    "role": "IT",       "is_executive": False},
    {"display_name": "HR Department",      "domain": "company.com",    "role": "HR",       "is_executive": False},
    {"display_name": "CEO",                "domain": "company.com",    "role": "CEO",      "is_executive": True},
    {"display_name": "CFO",                "domain": "company.com",    "role": "CFO",      "is_executive": True},
    {"display_name": "Security Team",      "domain": "company.com",    "role": "Security", "is_executive": False},
    {"display_name": "Payroll",            "domain": "company.com",    "role": "Payroll",  "is_executive": False},
    {"display_name": "Support",            "domain": "support.company.com", "role": "Support", "is_executive": False},
    {"display_name": "Microsoft Support",  "domain": "microsoft.com",  "role": "Support",  "is_executive": False},
    {"display_name": "Apple Support",      "domain": "apple.com",      "role": "Support",  "is_executive": False},
    {"display_name": "PayPal",             "domain": "paypal.com",     "role": "Service",  "is_executive": False},
    {"display_name": "Google",             "domain": "google.com",     "role": "Service",  "is_executive": False},
    {"display_name": "Amazon",             "domain": "amazon.com",     "role": "Service",  "is_executive": False},
    {"display_name": "IRS",                "domain": "irs.gov",        "role": "Government", "is_executive": False},
    {"display_name": "DHL",                "domain": "dhl.com",        "role": "Shipping", "is_executive": False},
    {"display_name": "FedEx",              "domain": "fedex.com",      "role": "Shipping", "is_executive": False},
]

# ─── Authority role keywords ──────────────────────────────────────────────────
AUTHORITY_KEYWORDS = [
    "ceo", "cfo", "cto", "coo", "president", "director", "manager", "vp",
    "vice president", "head of", "chief", "executive", "hr", "payroll",
    "it department", "security team", "finance", "legal", "compliance",
    "irs", "government", "tax authority", "police", "fbi", "interpol",
]

# ─── Urgent financial/credential request patterns ─────────────────────────────
FINANCIAL_URGENCY = [
    "wire transfer", "bank transfer", "gift card", "bitcoin", "cryptocurrency",
    "send money", "urgent payment", "invoice", "account number", "routing number",
    "password", "credentials", "login details", "access code", "verification code",
    "urgent", "immediately", "asap", "right away", "without delay", "today only",
]

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "mail.com", "aol.com", "yandex.com",
}


class ImpersonationEngine:
    """Pluggable digital impersonation detection engine."""

    def analyze(
        self,
        display_name: str,
        email_address: Optional[str],
        claimed_role: Optional[str],
        claimed_organisation: Optional[str],
        message_body: str,
        subject: Optional[str] = None,
        known_contacts: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Returns:
            domain_mismatch_score (0-100), authority_claim_score (0-100),
            urgency_score (0-100), style_deviation_score (0-100),
            indicators (list[str]), confidence (0-1)
        """
        contacts = known_contacts or KNOWN_CONTACTS
        indicators: List[str] = []
        combined_text = " ".join(filter(None, [subject, display_name, message_body])).lower()

        # 1. Domain mismatch analysis
        domain_score, domain_indicators = self._check_domain_mismatch(
            display_name, email_address, claimed_role, claimed_organisation, contacts
        )
        indicators.extend(domain_indicators)

        # 2. Authority claim score
        authority_score, authority_indicators = self._check_authority_claim(
            display_name, claimed_role, combined_text
        )
        indicators.extend(authority_indicators)

        # 3. Urgency + financial request
        urgency_score, urgency_indicators = self._check_urgency(combined_text)
        indicators.extend(urgency_indicators)

        # 4. Style deviation (placeholder — in prod, compare against historical messages)
        style_score = self._style_deviation(message_body)
        if style_score > 30:
            indicators.append(f"Writing style deviates significantly from typical messages (deviation: {style_score:.0f}/100)")

        # 5. Lookalike display name
        lookalike_score, lookalike_indicators = self._check_lookalike_name(display_name, contacts)
        indicators.extend(lookalike_indicators)
        if lookalike_score > 0:
            domain_score = max(domain_score, lookalike_score)

        confidence = round(min(0.95, (domain_score + authority_score + urgency_score) / 300 + 0.2), 3)

        return {
            "domain_mismatch_score": domain_score,
            "authority_claim_score": authority_score,
            "urgency_score": urgency_score,
            "style_deviation_score": style_score,
            "indicators": list(dict.fromkeys(indicators)),
            "confidence": confidence,
        }

    def _check_domain_mismatch(
        self,
        display_name: str,
        email_address: Optional[str],
        claimed_role: Optional[str],
        claimed_organisation: Optional[str],
        contacts: List[Dict],
    ) -> Tuple[float, List[str]]:
        indicators: List[str] = []

        if not email_address:
            return 0.0, indicators

        # Extract actual sending domain
        domain_match = re.search(r"@([\w.\-]+)", email_address)
        if not domain_match:
            return 10.0, ["Email address format is invalid"]

        actual_domain = domain_match.group(1).lower()

        # Check against known contacts
        name_lower = display_name.lower()
        for contact in contacts:
            contact_name = contact["display_name"].lower()
            expected_domain = contact["domain"].lower()

            # Name similarity
            dist = levenshtein_distance(name_lower, contact_name)
            threshold = max(2, len(contact_name) // 4)

            if dist <= threshold:
                # Name matches — check domain
                if actual_domain != expected_domain and not actual_domain.endswith("." + expected_domain):
                    score = 70.0 if contact.get("is_executive") else 50.0
                    indicators.append(
                        f"Display name '{display_name}' matches known contact '{contact['display_name']}' "
                        f"but email domain '{actual_domain}' ≠ expected '{expected_domain}'"
                    )
                    if actual_domain in FREE_EMAIL_PROVIDERS:
                        score = min(100.0, score + 20)
                        indicators.append(
                            f"Sender uses free email provider '{actual_domain}' "
                            f"while claiming to be '{contact['display_name']}'"
                        )
                    return score, indicators

        # Free email claiming authority role
        if actual_domain in FREE_EMAIL_PROVIDERS and claimed_role:
            if any(kw in claimed_role.lower() for kw in AUTHORITY_KEYWORDS):
                return 60.0, [
                    f"Authority role '{claimed_role}' claimed from free email provider '{actual_domain}'"
                ]

        return 0.0, indicators

    def _check_authority_claim(
        self,
        display_name: str,
        claimed_role: Optional[str],
        combined_text: str,
    ) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        score = 0.0

        name_lower = display_name.lower()
        role_lower = (claimed_role or "").lower()
        text_lower = combined_text.lower()

        authority_in_name = any(kw in name_lower for kw in AUTHORITY_KEYWORDS)
        authority_in_role = any(kw in role_lower for kw in AUTHORITY_KEYWORDS)
        authority_in_text = any(kw in text_lower for kw in AUTHORITY_KEYWORDS)

        if authority_in_name or authority_in_role:
            score += 40.0
            entity = display_name if authority_in_name else claimed_role
            indicators.append(f"High-authority entity claimed: '{entity}'")

        if authority_in_text and not (authority_in_name or authority_in_role):
            score += 20.0
            indicators.append("Message invokes authority figures to pressure compliance")

        return min(100.0, score), indicators

    def _check_urgency(self, text_lower: str) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        hits = [phrase for phrase in FINANCIAL_URGENCY if phrase in text_lower]

        if not hits:
            return 0.0, []

        score = min(100.0, len(hits) * 12)
        indicators.append(f"Urgent/financial pressure language: {', '.join(hits[:4])}")
        return score, indicators

    def _style_deviation(self, message_body: str) -> float:
        """
        Simplified stylometry: compute TF-IDF similarity of the message
        against a baseline "normal business communication" corpus.
        In production this would compare against the sender's message history.
        """
        baseline_corpus = [
            "Please find attached the document for your review. Let me know if you have any questions.",
            "Following up on our meeting yesterday. Please confirm your availability for next week.",
            "The quarterly report is ready. I will share it with the team shortly.",
            "As discussed, I am forwarding the project timeline for your approval.",
            "Thank you for your email. I will get back to you shortly.",
        ]
        try:
            tfidf = TfidfVectorizer().fit_transform(baseline_corpus + [message_body])
            similarities = cosine_similarity(tfidf[-1], tfidf[:-1])
            max_similarity = float(similarities.max())
            deviation = (1 - max_similarity) * 100
            return round(deviation, 2)
        except Exception:
            return 0.0

    def _check_lookalike_name(
        self,
        display_name: str,
        contacts: List[Dict],
    ) -> Tuple[float, List[str]]:
        """Detect near-duplicate display names that don't match exactly."""
        indicators: List[str] = []
        name_lower = display_name.lower()

        for contact in contacts:
            contact_name = contact["display_name"].lower()
            if name_lower == contact_name:
                continue  # exact match, handled above
            dist = levenshtein_distance(name_lower, contact_name)
            if 0 < dist <= 2 and len(contact_name) >= 4:
                score = 55.0
                indicators.append(
                    f"Display name '{display_name}' is a lookalike of known contact "
                    f"'{contact['display_name']}' (edit distance: {dist})"
                )
                return score, indicators

        return 0.0, indicators


# ─── Singleton ────────────────────────────────────────────────────────────────
_engine_instance: Optional[ImpersonationEngine] = None


def get_impersonation_engine() -> ImpersonationEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ImpersonationEngine()
    return _engine_instance
