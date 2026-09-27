"""
CyberGuard Classifier Evaluation Script
────────────────────────────────────────
Evaluates the phishing text classifier and URL heuristic detector
on a held-out 20% test split of the synthetic data.

Usage:
    python scripts/evaluate.py

SYNTHETIC DATA — for demonstration/evaluation purposes only.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure backend root is on path
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix

DATA_DIR = _BACKEND_ROOT / "data"


def evaluate_phishing_classifier():
    """Evaluate TF-IDF + Logistic Regression on phishing email dataset."""
    print("=" * 60)
    print("PHISHING EMAIL CLASSIFIER EVALUATION")
    print("=" * 60)

    csv_path = DATA_DIR / "sample_phishing_emails.csv"
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. Run seed.py first.")
        return

    df = pd.read_csv(csv_path)
    X = df["text"].fillna("").astype(str).tolist()
    y = df["label"].tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # Train the pipeline directly here for evaluation
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(
            ngram_range=(1, 2), max_features=10000,
            sublinear_tf=True, strip_accents="unicode",
        )),
        ("clf", LogisticRegression(C=1.0, solver="lbfgs", max_iter=1000, class_weight="balanced")),
    ])
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print(f"\nAccuracy: {accuracy_score(y_test, y_pred):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legit", "Phishing"]))
    print("Confusion Matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y_test, y_pred))


def evaluate_url_classifier():
    """Evaluate rule-based URL heuristic detector on URL dataset."""
    print("\n" + "=" * 60)
    print("URL HEURISTIC DETECTOR EVALUATION")
    print("=" * 60)

    csv_path = DATA_DIR / "sample_urls.csv"
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. Run seed.py first.")
        return

    df = pd.read_csv(csv_path).drop_duplicates(subset=["url"])
    X = df["url"].tolist()
    y = df["label"].tolist()

    from app.routers.url_scan import analyze_url
    from app.engines.risk_scorer import RiskScorer, score_to_level

    predictions = []
    for url in X:
        try:
            (typo, tld, ip, sub, ssl, kw, _) = analyze_url(url)
            score = RiskScorer.score_url(typo, tld, ip, sub, ssl, kw)
            # threshold: > 30 = malicious
            pred = 1 if score > 30 else 0
        except Exception:
            pred = 0
        predictions.append(pred)

    print(f"Total URLs: {len(X)}")
    print(f"\nAccuracy: {accuracy_score(y, predictions):.4f}")
    print("\nClassification Report:")
    print(classification_report(y, predictions, target_names=["Safe", "Malicious"]))
    print("Confusion Matrix (rows=actual, cols=predicted):")
    print(confusion_matrix(y, predictions))


def evaluate_auth_anomaly():
    """Evaluate anomaly engine on auth log data."""
    print("\n" + "=" * 60)
    print("AUTH ANOMALY DETECTOR EVALUATION")
    print("=" * 60)

    csv_path = DATA_DIR / "sample_auth_logs.csv"
    if not csv_path.exists():
        print(f"ERROR: {csv_path} not found. Run seed.py first.")
        return

    import pandas as pd
    df = pd.read_csv(csv_path)
    print(f"Total log entries: {len(df)}")
    print(f"Label distribution:\n{df['label'].value_counts().to_string()}")

    from app.engines.anomaly_engine import AnomalyEngine

    engine = AnomalyEngine()

    # Test on brute force subset
    bf_logs = df[df["label"] == "brute_force"].to_dict(orient="records")
    for r in bf_logs:
        r["success"] = str(r.get("success", "true")).lower() not in {"false", "0"}
    if bf_logs:
        result = engine.analyze_auth_logs(bf_logs)
        print(f"\nBrute Force detection — risk_score: {result['final_score']:.1f}, "
              f"threat_type: {result['threat_type']}")
        print(f"Indicators: {result['indicators'][:2]}")

    # Test on password spray subset
    spray_logs = df[df["label"] == "password_spray"].to_dict(orient="records")
    for r in spray_logs:
        r["success"] = str(r.get("success", "true")).lower() not in {"false", "0"}
    if spray_logs:
        result = engine.analyze_auth_logs(spray_logs)
        print(f"\nPassword Spray detection — risk_score: {result['final_score']:.1f}, "
              f"threat_type: {result['threat_type']}")
        print(f"Indicators: {result['indicators'][:2]}")

    # Test on impossible travel subset
    travel_logs = df[df["label"] == "impossible_travel"].to_dict(orient="records")
    for r in travel_logs:
        r["success"] = str(r.get("success", "true")).lower() not in {"false", "0"}
        for col in ["latitude", "longitude"]:
            try:
                r[col] = float(r[col]) if r.get(col) else None
            except (ValueError, TypeError):
                r[col] = None
    if travel_logs:
        result = engine.analyze_auth_logs(travel_logs)
        print(f"\nImpossible Travel detection — risk_score: {result['final_score']:.1f}, "
              f"threat_type: {result['threat_type']}")
        print(f"Indicators: {result['indicators'][:2]}")


if __name__ == "__main__":
    print("CyberGuard — Classifier Evaluation")
    print("SYNTHETIC DATA — for demonstration only\n")

    # First generate the CSVs if missing
    from scripts.seed import (
        generate_phishing_emails_csv,
        generate_urls_csv,
        generate_auth_logs_csv,
        generate_network_logs_csv,
    )
    generate_phishing_emails_csv()
    generate_urls_csv()
    generate_auth_logs_csv()
    generate_network_logs_csv()

    evaluate_phishing_classifier()
    evaluate_url_classifier()
    evaluate_auth_anomaly()

    print("\n" + "=" * 60)
    print("Evaluation complete.")
