"""
CyberGuard Phishing Detection Engine
─────────────────────────────────────
Combines:
  1. Rule-based feature extraction (urgency, domain mismatch, credential requests, etc.)
  2. TF-IDF + Logistic Regression classifier (trained on synthetic data)
  3. URL heuristic checks on embedded URLs

Training happens once on first use (or if model file is missing);
the model is persisted to disk with joblib.
"""
from __future__ import annotations

import os
import re
import logging
import pickle
import math
from pathlib import Path
from typing import List, Tuple, Dict, Optional

import numpy as np
import pandas as pd
from Levenshtein import distance as levenshtein_distance
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import joblib

logger = logging.getLogger(__name__)

# ─── Paths ────────────────────────────────────────────────────────────────────
_BASE_DIR = Path(__file__).resolve().parent.parent.parent
_DATA_DIR = _BASE_DIR / "data"
_MODEL_PATH = _BASE_DIR / "models_cache" / "phishing_model.joblib"
_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

# ─── Known brand domains (for typosquatting detection) ────────────────────────
KNOWN_BRANDS = [
    "paypal.com", "apple.com", "microsoft.com", "google.com", "amazon.com",
    "netflix.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "ebay.com", "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "dropbox.com", "adobe.com", "office365.com", "outlook.com", "yahoo.com",
    "icloud.com", "americanexpress.com", "dhl.com", "fedex.com", "ups.com",
    "irs.gov", "gov.uk", "support.com", "helpdesk.com",
]

# ─── Urgency / social-engineering keywords ────────────────────────────────────
URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "24 hours", "48 hours", "expire",
    "suspended", "limited time", "verify now", "confirm your", "update your",
    "your account", "click here", "click the link", "click below",
    "unusual activity", "suspicious activity", "unauthorised", "unauthorized",
    "locked", "disabled", "blocked", "compromised", "verify identity",
    "validate", "security alert", "important notice", "action required",
    "final notice", "last chance", "failure to", "immediately",
]

# ─── Credential request phrases ───────────────────────────────────────────────
CREDENTIAL_PHRASES = [
    "enter your password", "confirm password", "enter your pin", "social security",
    "credit card", "card number", "cvv", "bank account", "routing number",
    "date of birth", "mother's maiden", "security question", "ssn",
    "login credentials", "username and password",
]

# ─── Suspicious TLDs ──────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club",
                   ".online", ".site", ".work", ".click", ".link", ".download"}

# ─── URL pattern ──────────────────────────────────────────────────────────────
URL_RE = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE,
)


class PhishingEngine:
    """Pluggable phishing detection engine."""

    def __init__(self):
        self._pipeline: Optional[Pipeline] = None
        self._load_or_train_model()

    # ─── Model lifecycle ──────────────────────────────────────────────────────

    def _load_or_train_model(self):
        if _MODEL_PATH.exists():
            try:
                self._pipeline = joblib.load(_MODEL_PATH)
                logger.info("Phishing model loaded from cache.")
                return
            except Exception as exc:
                logger.warning("Could not load phishing model: %s — retraining.", exc)
        self._train_model()

    def _train_model(self):
        """Train TF-IDF + Logistic Regression on synthetic data CSV."""
        csv_path = _DATA_DIR / "sample_phishing_emails.csv"
        if not csv_path.exists():
            logger.warning("Training CSV not found at %s — using minimal default model.", csv_path)
            self._pipeline = self._build_pipeline()
            # Fit on tiny dummy data so pipeline is callable
            self._pipeline.fit(["legit email text"] * 5 + ["urgent verify account"] * 5,
                                [0] * 5 + [1] * 5)
            return

        df = pd.read_csv(csv_path)
        if "text" not in df.columns or "label" not in df.columns:
            logger.error("CSV must have 'text' and 'label' columns.")
            return

        X = df["text"].fillna("").astype(str).tolist()
        y = df["label"].tolist()  # 0 = legit, 1 = phishing

        self._pipeline = self._build_pipeline()
        self._pipeline.fit(X, y)
        joblib.dump(self._pipeline, _MODEL_PATH)
        logger.info("Phishing model trained and saved. Samples: %d", len(X))

    @staticmethod
    def _build_pipeline() -> Pipeline:
        return Pipeline([
            ("tfidf", TfidfVectorizer(
                ngram_range=(1, 2),
                max_features=10000,
                sublinear_tf=True,
                strip_accents="unicode",
                analyzer="word",
                token_pattern=r"\w{2,}",
            )),
            ("clf", LogisticRegression(
                C=1.0,
                solver="lbfgs",
                max_iter=1000,
                class_weight="balanced",
            )),
        ])

    # ─── Main analysis method ─────────────────────────────────────────────────

    def analyze(
        self,
        text: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> Dict:
        """
        Full phishing analysis combining ML + rule-based detection.

        Returns dict with keys:
            ml_score (0-100), rule_score (0-100), url_score (0-100),
            indicators (list[str]), urls_found (list[str]), confidence (0-1)
        """
        combined_text = " ".join(filter(None, [subject, sender, text]))

        # 1. ML score
        ml_score, ml_confidence = self._ml_score(text)

        # 2. Rule-based score
        rule_score, indicators = self._rule_score(combined_text, sender, subject)

        # 3. URL analysis
        urls = URL_RE.findall(text)
        url_score, url_indicators = self._check_urls(urls)
        indicators.extend(url_indicators)

        # 4. Combine confidence
        confidence = round((ml_confidence + min(1.0, rule_score / 100) * 0.5) / 1.5, 3)
        confidence = max(0.1, min(0.99, confidence))

        return {
            "ml_score": ml_score,
            "rule_score": rule_score,
            "url_score": url_score,
            "indicators": indicators,
            "urls_found": urls,
            "confidence": confidence,
        }

    def _ml_score(self, text: str) -> Tuple[float, float]:
        """Returns (score_0_100, confidence_0_1)."""
        if self._pipeline is None:
            return 0.0, 0.5
        try:
            proba = self._pipeline.predict_proba([text])[0]
            phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            score = round(phishing_prob * 100, 2)
            return score, phishing_prob
        except Exception as exc:
            logger.warning("ML scoring failed: %s", exc)
            return 0.0, 0.5

    def _rule_score(
        self,
        text: str,
        sender: Optional[str],
        subject: Optional[str],
    ) -> Tuple[float, List[str]]:
        text_lower = text.lower()
        indicators: List[str] = []
        score = 0.0

        # Urgency keywords (up to 25 pts)
        urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
        if urgency_hits:
            score += min(25, len(urgency_hits) * 5)
            indicators.append(f"Urgency language detected: {', '.join(urgency_hits[:3])}")

        # Credential request phrases (up to 30 pts)
        cred_hits = [ph for ph in CREDENTIAL_PHRASES if ph in text_lower]
        if cred_hits:
            score += min(30, len(cred_hits) * 10)
            indicators.append(f"Credential request phrases detected: {', '.join(cred_hits[:2])}")

        # Sender domain mismatch
        if sender:
            mismatch, mismatch_desc = self._check_sender(sender)
            if mismatch:
                score += 20
                indicators.append(mismatch_desc)

        # Suspicious subject
        if subject:
            subj_lower = subject.lower()
            if any(kw in subj_lower for kw in ["urgent", "action required", "verify", "suspended", "locked"]):
                score += 10
                indicators.append(f"Suspicious subject line: '{subject[:60]}'")

        # Excessive exclamation marks
        excl_count = text.count("!")
        if excl_count >= 3:
            score += min(5, excl_count)
            indicators.append(f"Excessive exclamation marks ({excl_count})")

        # Generic greeting (no personalisation)
        generic_greetings = ["dear customer", "dear user", "dear account holder",
                             "dear valued", "hello user", "dear sir/madam"]
        if any(g in text_lower for g in generic_greetings):
            score += 8
            indicators.append("Generic/impersonal greeting used")

        # Misspellings of brand names (lookalike)
        lookalike = self._check_lookalike_brands(text_lower)
        if lookalike:
            score += 15
            indicators.append(f"Lookalike brand mention: {lookalike}")

        return round(min(100.0, score), 2), indicators

    def _check_sender(self, sender: str) -> Tuple[bool, str]:
        """Check for display-name vs domain mismatch."""
        domain_match = re.search(r"@([\w.\-]+)", sender)
        if not domain_match:
            return False, ""
        domain = domain_match.group(1).lower()

        # Check if domain resembles a known brand (but isn't exact)
        for brand in KNOWN_BRANDS:
            brand_domain = brand.split(".")[0]
            if brand_domain in domain and domain != brand:
                dist = levenshtein_distance(domain, brand)
                if 0 < dist <= 3:
                    return True, f"Sender domain '{domain}' closely resembles '{brand}' (edit distance: {dist})"

        # Generic free email claiming to be corporate
        free_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
        if domain in free_providers and "no-reply" not in sender.lower():
            return True, f"Message from free email provider '{domain}' claiming corporate identity"

        return False, ""

    def _check_lookalike_brands(self, text_lower: str) -> Optional[str]:
        """Detect near-misspellings of brand names in the body text."""
        words = re.findall(r"\b\w{4,}\b", text_lower)
        for word in words:
            for brand in KNOWN_BRANDS:
                brand_name = brand.split(".")[0]
                if len(brand_name) >= 4 and abs(len(word) - len(brand_name)) <= 2:
                    dist = levenshtein_distance(word, brand_name)
                    if 0 < dist <= 2:
                        return f"'{word}' ≈ '{brand_name}'"
        return None

    def _check_urls(self, urls: List[str]) -> Tuple[float, List[str]]:
        """Run heuristic checks on extracted URLs."""
        if not urls:
            return 0.0, []
        indicators: List[str] = []
        score = 0.0

        # Many URLs
        if len(urls) > 5:
            score += 10
            indicators.append(f"High number of URLs in message ({len(urls)})")

        for url in urls[:5]:  # Analyse up to 5 URLs
            url_lower = url.lower()

            # IP-address as domain
            if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_lower):
                score += 25
                indicators.append(f"URL uses raw IP address: {url[:60]}")

            # Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if tld in url_lower:
                    score += 15
                    indicators.append(f"Suspicious TLD '{tld}' in URL: {url[:60]}")
                    break

            # Typosquatting brand in URL
            domain_part = re.sub(r"https?://", "", url_lower).split("/")[0]
            for brand in KNOWN_BRANDS:
                brand_name = brand.split(".")[0]
                if brand_name in domain_part and domain_part != brand:
                    dist = levenshtein_distance(domain_part.replace("www.", ""), brand)
                    if 0 < dist <= 4:
                        score += 20
                        indicators.append(f"URL domain typosquats '{brand}': {domain_part[:60]}")
                        break

            # Excessive subdomains
            parts = domain_part.split(".")
            if len(parts) > 4:
                score += 10
                indicators.append(f"Excessive subdomains in URL: {domain_part[:60]}")

            # URL shortener
            shorteners = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link"}
            for sh in shorteners:
                if sh in url_lower:
                    score += 10
                    indicators.append(f"URL shortener detected: {sh}")
                    break

        return round(min(100.0, score), 2), indicators


# ─── Module-level singleton ───────────────────────────────────────────────────
_engine_instance: Optional[PhishingEngine] = None


def get_phishing_engine() -> PhishingEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PhishingEngine()
    return _engine_instance
