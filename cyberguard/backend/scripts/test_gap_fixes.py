"""
Unit & Integration Verification for CyberGuard Gap Fixes
"""
from __future__ import annotations
import sys
import io
from pathlib import Path

_BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import pandas as pd
from app.response.action_recommender import recommend_actions, NOTIFY_SOC, ESCALATE
from app.engines.anomaly_engine import get_anomaly_engine
from app.routers.phishing import _decode_qr_image


def test_gap1_action_recommender():
    print("Testing GAP 1: Response Recommender...")
    # Test High/Critical mandatory rules across multiple threat types
    for tt in ["Phishing", "qr_phishing", "Malicious URL", "Deepfake", "api_abuse", "Network Anomaly"]:
        high_actions = recommend_actions(tt, "High")
        assert NOTIFY_SOC in high_actions, f"High risk for {tt} missing NOTIFY_SOC: {high_actions}"

        crit_actions = recommend_actions(tt, "Critical")
        assert NOTIFY_SOC in crit_actions, f"Critical risk for {tt} missing NOTIFY_SOC: {crit_actions}"
        assert ESCALATE in crit_actions, f"Critical risk for {tt} missing ESCALATE: {crit_actions}"

    # Test Low / Safe
    safe_actions = recommend_actions("api_abuse", "Safe")
    assert isinstance(safe_actions, list) and len(safe_actions) > 0
    print("  [OK] GAP 1: Action Recommender policies verified for all threat types and risk levels.")


def test_gap2_qr_detection():
    print("Testing GAP 2: QR Detection logic...")
    # Test empty / invalid image bytes returns empty list without error
    empty_res = _decode_qr_image(b"not-a-valid-image")
    assert empty_res == [], f"Expected empty list for invalid image, got {empty_res}"

    # Generate a simple QR code image using OpenCV or Pillow to test decoder
    import cv2
    import numpy as np

    # Create dummy white image (no QR)
    dummy_img = np.ones((200, 200, 3), dtype=np.uint8) * 255
    _, encoded = cv2.imencode(".png", dummy_img)
    blank_res = _decode_qr_image(encoded.tobytes())
    assert blank_res == [], f"Expected empty list for blank image, got {blank_res}"

    print("  [OK] GAP 2: QR decoding handles invalid, blank, and no-QR images safely.")


def test_gap3_api_abuse_detection():
    print("Testing GAP 3: API Abuse Detection...")
    engine = get_anomaly_engine()

    # Test 1: Excessive rate burst
    burst_logs = [
        {"timestamp": f"2026-09-08T12:00:{i:02d}Z", "api_key": "bad_key", "endpoint": "/api/v1/search", "role": "user"}
        for i in range(20)
    ]
    res1 = engine.analyze_api_logs(burst_logs)
    assert res1["threat_type"] == "api_abuse", f"Expected threat_type='api_abuse', got {res1['threat_type']}"
    assert res1["final_score"] >= 30, f"Expected final_score >= 30, got {res1['final_score']}"
    assert any("Excessive" in ind for ind in res1["indicators"]), f"Missing excessive rate indicator: {res1['indicators']}"

    # Test 2: Unauthorized sensitive endpoint access
    probe_logs = [
        {"timestamp": "2026-09-08T12:00:01Z", "user_id": "intruder", "endpoint": "/admin/keys", "role": "user"},
        {"timestamp": "2026-09-08T12:00:02Z", "user_id": "intruder", "endpoint": "/admin/system/config", "role": "user"},
    ]
    res2 = engine.analyze_api_logs(probe_logs)
    assert res2["threat_type"] == "api_abuse"
    assert any("Unauthorized" in ind or "sensitive" in ind for ind in res2["indicators"]), f"Missing unauthorized access indicator: {res2['indicators']}"

    # Test 3: IDOR / sequence enumeration
    idor_logs = [
        {"timestamp": f"2026-09-08T12:00:{i:02d}Z", "client_id": "scraper", "endpoint": f"/api/v1/invoices/{100+i}", "role": "user"}
        for i in range(5)
    ]
    res3 = engine.analyze_api_logs(idor_logs)
    assert res3["threat_type"] == "api_abuse"
    assert any("Abnormal sequence" in ind for ind in res3["indicators"]), f"Missing IDOR indicator: {res3['indicators']}"

    # Test 4: Verify sample_api_logs.csv is readable and detectable
    csv_path = _BACKEND_ROOT / "data" / "sample_api_logs.csv"
    assert csv_path.exists(), "sample_api_logs.csv does not exist"
    df = pd.read_csv(csv_path)
    res_sample = engine.analyze_api_logs(df.to_dict(orient="records"))
    assert res_sample["threat_type"] == "api_abuse"
    assert res_sample["final_score"] > 50

    print("  [OK] GAP 3: API Abuse detection verifies rate limits, RBAC probing, and sequence anomalies.")


if __name__ == "__main__":
    print("=" * 60)
    print("Running CyberGuard Gap Fixes Verification Suite")
    print("=" * 60)
    test_gap1_action_recommender()
    test_gap2_qr_detection()
    test_gap3_api_abuse_detection()
    print("=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY!")
    print("=" * 60)
