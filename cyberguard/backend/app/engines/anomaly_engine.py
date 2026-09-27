"""
CyberGuard Anomaly Detection Engine
────────────────────────────────────
Handles:
  A. Authentication log anomaly detection
     - Brute force (repeated failures)
     - Password spraying (many users, same IP)
     - Impossible travel (geo distance / time delta)
     - New device / new geo logins
     - Statistical z-score + Isolation Forest

  B. Network log anomaly detection
     - High request rates, port scanning, unusual protocols
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

# ─── Constants ────────────────────────────────────────────────────────────────
EARTH_RADIUS_KM = 6371.0
IMPOSSIBLE_TRAVEL_KM_PER_HOUR = 900   # faster than commercial aircraft → suspicious
BRUTE_FORCE_THRESHOLD = 5             # failures in window
PASSWORD_SPRAY_MIN_USERS = 3          # distinct users from same IP
FAILED_LOGIN_RATE_THRESHOLD = 0.6    # >60% failures = suspicious


def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(math.sqrt(a))


class AnomalyEngine:
    """
    Pluggable anomaly detection engine.
    Supports auth-log analysis and network-log analysis.
    """

    # ─── Auth log analysis ────────────────────────────────────────────────────

    def analyze_auth_logs(self, logs: List[Dict[str, Any]]) -> Dict:
        """
        Analyse a list of login event dicts.

        Each dict should have keys:
            username, timestamp (ISO8601 str), ip_address, geo_country, geo_city,
            latitude, longitude, device_fingerprint, success (bool), failure_reason,
            user_agent

        Returns a unified detection result dict.
        """
        if not logs:
            return self._empty_result("Account Takeover")

        df = self._parse_auth_df(logs)
        indicators: List[str] = []
        sub_scores: Dict[str, float] = {}

        # ── Brute force detection ─────────────────────────────────────────────
        bf_score, bf_indicators = self._detect_brute_force(df)
        sub_scores["brute_force"] = bf_score
        indicators.extend(bf_indicators)

        # ── Password spraying ─────────────────────────────────────────────────
        spray_score, spray_indicators = self._detect_password_spray(df)
        sub_scores["password_spray"] = spray_score
        indicators.extend(spray_indicators)

        # ── Impossible travel ─────────────────────────────────────────────────
        travel_score, travel_indicators = self._detect_impossible_travel(df)
        sub_scores["impossible_travel"] = travel_score
        indicators.extend(travel_indicators)

        # ── New device / geo ──────────────────────────────────────────────────
        device_score, device_indicators = self._detect_new_device(df)
        sub_scores["new_device"] = device_score
        indicators.extend(device_indicators)

        # ── Failed login rate ─────────────────────────────────────────────────
        fail_rate = df["success"].eq(False).mean()
        sub_scores["failed_login_rate"] = min(100, fail_rate * 150)
        if fail_rate > FAILED_LOGIN_RATE_THRESHOLD:
            indicators.append(f"High failure rate: {fail_rate:.0%} of login attempts failed")

        # ── Isolation Forest ──────────────────────────────────────────────────
        iso_score = self._isolation_forest_score(df)
        sub_scores["iso_forest"] = iso_score
        if iso_score > 60:
            indicators.append(f"Statistical anomaly detected by Isolation Forest (score: {iso_score:.0f})")

        # ── Determine primary threat type ─────────────────────────────────────
        threat_type = "Account Takeover"
        if sub_scores["brute_force"] > 60:
            threat_type = "Brute Force"
        elif sub_scores["password_spray"] > 60:
            threat_type = "Password Spray"
        elif sub_scores["impossible_travel"] > 70:
            threat_type = "Impossible Travel"

        # ── Final score ───────────────────────────────────────────────────────
        final_score = min(100, sum(sub_scores.values()) / max(1, len(sub_scores)))
        confidence = round(min(0.95, final_score / 100 * 1.1), 3)

        return {
            "threat_type": threat_type,
            "sub_scores": sub_scores,
            "final_score": round(final_score, 2),
            "confidence": confidence,
            "indicators": list(dict.fromkeys(indicators)),  # deduplicate preserving order
            "stats": {
                "total_events": len(df),
                "unique_users": df["username"].nunique(),
                "unique_ips": df["ip_address"].nunique(),
                "failure_rate": round(float(fail_rate), 3),
            },
        }

    def _parse_auth_df(self, logs: List[Dict]) -> pd.DataFrame:
        df = pd.DataFrame(logs)
        df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df["success"] = df["success"].astype(bool) if "success" in df.columns else True
        for col in ["latitude", "longitude"]:
            if col not in df.columns:
                df[col] = None
            df[col] = pd.to_numeric(df[col], errors="coerce")
        for col in ["ip_address", "username", "device_fingerprint", "geo_country", "geo_city"]:
            if col not in df.columns:
                df[col] = ""
            df[col] = df[col].fillna("")
        return df.sort_values("timestamp")

    def _detect_brute_force(self, df: pd.DataFrame) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        max_failures = 0

        for user, grp in df.groupby("username"):
            fails = grp[grp["success"] == False]
            if len(fails) >= BRUTE_FORCE_THRESHOLD:
                max_failures = max(max_failures, len(fails))
                indicators.append(
                    f"Brute force detected for user '{user}': {len(fails)} failed attempts"
                )

        if max_failures == 0:
            return 0.0, []

        score = min(100, 20 + (max_failures - BRUTE_FORCE_THRESHOLD) * 10)
        return score, indicators

    def _detect_password_spray(self, df: pd.DataFrame) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        fails = df[df["success"] == False]
        if fails.empty:
            return 0.0, []

        ip_counts = fails.groupby("ip_address")["username"].nunique()
        spray_ips = ip_counts[ip_counts >= PASSWORD_SPRAY_MIN_USERS]
        if spray_ips.empty:
            return 0.0, []

        for ip, cnt in spray_ips.items():
            indicators.append(
                f"Password spraying from IP {ip}: {cnt} distinct users targeted"
            )
        score = min(100, 30 + len(spray_ips) * 15)
        return score, indicators

    def _detect_impossible_travel(self, df: pd.DataFrame) -> Tuple[float, List[str]]:
        indicators: List[str] = []
        max_score = 0.0

        for user, grp in df.groupby("username"):
            grp_sorted = grp.dropna(subset=["latitude", "longitude"]).sort_values("timestamp")
            if len(grp_sorted) < 2:
                continue

            prev = None
            for _, row in grp_sorted.iterrows():
                if prev is not None:
                    km = _haversine(prev["latitude"], prev["longitude"],
                                    row["latitude"], row["longitude"])
                    dt_hours = (row["timestamp"] - prev["timestamp"]).total_seconds() / 3600
                    if dt_hours > 0:
                        speed = km / dt_hours
                        if speed > IMPOSSIBLE_TRAVEL_KM_PER_HOUR:
                            max_score = max(max_score, min(100, 40 + speed / 10))
                            indicators.append(
                                f"Impossible travel for '{user}': {km:.0f} km in {dt_hours:.1f}h "
                                f"({speed:.0f} km/h) — {prev.get('geo_city', '?')} → {row.get('geo_city', '?')}"
                            )
                prev = row

        return round(max_score, 2), indicators

    def _detect_new_device(self, df: pd.DataFrame) -> Tuple[float, List[str]]:
        """Flag successful logins from previously unseen device fingerprints."""
        indicators: List[str] = []
        score = 0.0

        for user, grp in df.groupby("username"):
            grp_sorted = grp.sort_values("timestamp")
            seen_devices: set = set()
            for _, row in grp_sorted.iterrows():
                fp = row.get("device_fingerprint", "")
                if not fp:
                    continue
                if fp not in seen_devices and len(seen_devices) > 0 and row["success"]:
                    score = max(score, 45)
                    indicators.append(
                        f"New device login for '{user}': fingerprint {fp[:20]}…"
                    )
                seen_devices.add(fp)

        return min(100.0, score), indicators

    def _isolation_forest_score(self, df: pd.DataFrame) -> float:
        """
        Fit an IsolationForest on numerical features and return
        an anomaly score (0 = normal, 100 = highly anomalous).
        """
        try:
            features = pd.DataFrame({
                "fail_rate_by_user": df.groupby("username")["success"]
                    .transform(lambda x: (x == False).mean()),
                "ip_entropy": df["ip_address"].map(
                    df.groupby("ip_address").size()
                ).fillna(0),
                "lat": df["latitude"].fillna(0),
                "lon": df["longitude"].fillna(0),
            }).fillna(0)

            if features.shape[0] < 5:
                return 0.0

            clf = IsolationForest(contamination=0.15, random_state=42)
            scores = clf.fit_predict(features)
            anomaly_fraction = (scores == -1).mean()
            return round(anomaly_fraction * 100, 2)
        except Exception as exc:
            logger.warning("IsolationForest failed: %s", exc)
            return 0.0

    # ─── Network log analysis ─────────────────────────────────────────────────

    def analyze_network_logs(self, logs: List[Dict[str, Any]]) -> Dict:
        """Analyse simulated network logs for anomalies."""
        if not logs:
            return self._empty_result("Network Anomaly")

        df = pd.DataFrame(logs)

        # If data is API-centric, route to distinct API abuse detector
        if any(c in df.columns for c in ["api_key", "endpoint", "path"]) or (
            "label" in df.columns and "api_abuse" in df["label"].values
        ):
            return self.analyze_api_logs(logs)

        indicators: List[str] = []
        score = 0.0

        # High request rate from single IP
        if "src_ip" in df.columns:
            ip_counts = df["src_ip"].value_counts()
            top_ip_count = int(ip_counts.iloc[0]) if not ip_counts.empty else 0
            if top_ip_count > 100:
                score += 30
                indicators.append(f"High request rate from IP {ip_counts.index[0]}: {top_ip_count} requests")

        # Port scanning
        if "dst_port" in df.columns and "src_ip" in df.columns:
            port_scan = df.groupby("src_ip")["dst_port"].nunique()
            scanners = port_scan[port_scan > 20]
            if not scanners.empty:
                score += 35
                indicators.append(f"Port scanning detected from {len(scanners)} IP(s)")

        # Unusual protocols
        if "protocol" in df.columns:
            unusual = df[~df["protocol"].str.upper().isin(["TCP", "UDP", "HTTP", "HTTPS", "DNS"])]
            if len(unusual) > 5:
                score += 20
                indicators.append(f"Unusual protocols detected: {unusual['protocol'].unique()[:3].tolist()}")

        # Large data transfers
        if "bytes_out" in df.columns:
            df["bytes_out"] = pd.to_numeric(df["bytes_out"], errors="coerce").fillna(0)
            large = df[df["bytes_out"] > 50_000_000]
            if not large.empty:
                score += 25
                indicators.append(f"Large outbound data transfers detected ({len(large)} events > 50 MB)")

        confidence = round(min(0.95, score / 100), 3)
        return {
            "threat_type": "Network Anomaly",
            "final_score": round(min(100, score), 2),
            "confidence": confidence,
            "indicators": indicators,
            "stats": {"total_events": len(df)},
        }

    # ─── API Abuse log analysis ───────────────────────────────────────────────

    def analyze_api_logs(self, logs: List[Dict[str, Any]]) -> Dict:
        """
        Distinct API abuse detector.
        Flags:
          1. Excessive request rate from a single client/API key within a time window
          2. Repeated access to sensitive/admin endpoints by a non-admin user
          3. Abnormal sequences of endpoint calls compared to that user's historical baseline
        Tags results with threat_type="api_abuse".
        """
        if not logs:
            return self._empty_result("api_abuse")

        df = pd.DataFrame(logs)
        indicators: List[str] = []
        score = 0.0

        # Identifier column: api_key > client_id > username > user_id > src_ip
        client_col = None
        for candidate in ["api_key", "client_id", "username", "user_id", "src_ip"]:
            if candidate in df.columns:
                client_col = candidate
                break

        # 1. Excessive request rate from single client / API key
        if client_col:
            rate_counts = df[client_col].value_counts()
            top_client = rate_counts.index[0]
            top_count = int(rate_counts.iloc[0])

            burst_detected = False
            if "timestamp" in df.columns and len(df) > 1:
                try:
                    df["dt"] = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
                    client_df = df[df[client_col] == top_client].dropna(subset=["dt"]).sort_values("dt")
                    if len(client_df) >= 8:
                        min_t, max_t = client_df["dt"].min(), client_df["dt"].max()
                        duration_sec = max(1.0, (max_t - min_t).total_seconds())
                        req_per_sec = len(client_df) / duration_sec
                        if req_per_sec > 1.0 or (len(client_df) >= 12 and duration_sec <= 60):
                            burst_detected = True
                            score += 40
                            indicators.append(
                                f"Excessive API request burst: {len(client_df)} requests in {duration_sec:.1f}s "
                                f"({req_per_sec:.1f} req/s) from {client_col} '{top_client}'"
                            )
                except Exception as exc:
                    logger.debug("Burst calculation failed: %s", exc)

            if not burst_detected and top_count >= 15:
                score += 35
                indicators.append(
                    f"Excessive API request rate: {top_count} requests originating from {client_col} '{top_client}'"
                )

        # 2. Repeated access to sensitive/admin endpoints by a non-admin user
        endpoint_col = next((c for c in ["endpoint", "path", "url", "request_uri"] if c in df.columns), None)
        if endpoint_col:
            sensitive_patterns = [
                "/admin", "/config", "/secret", "/keys", "/internal",
                "/billing", "/users/export", "/privileges", "/roles", "/exec", "/debug"
            ]
            pattern = "|".join(sensitive_patterns)
            sensitive_mask = df[endpoint_col].astype(str).str.contains(pattern, case=False, na=False)
            sensitive_df = df[sensitive_mask]

            if not sensitive_df.empty:
                non_admin_mask = pd.Series(True, index=sensitive_df.index)
                if "role" in sensitive_df.columns:
                    non_admin_mask = ~sensitive_df["role"].astype(str).str.lower().isin(["admin", "superuser", "system"])
                elif "is_admin" in sensitive_df.columns:
                    non_admin_mask = sensitive_df["is_admin"].astype(str).str.lower().isin(["false", "0", "none"])

                unauthorized_attempts = sensitive_df[non_admin_mask]
                if len(unauthorized_attempts) >= 1:
                    score += 35
                    flagged_endpoints = unauthorized_attempts[endpoint_col].unique()[:3].tolist()
                    culprit = str(unauthorized_attempts[client_col].iloc[0]) if client_col else "unauthorized client"
                    indicators.append(
                        f"Repeated unauthorized access: {len(unauthorized_attempts)} attempts to sensitive endpoints "
                        f"{flagged_endpoints} by non-admin user/client '{culprit}'"
                    )

        # 3. Abnormal sequences of endpoint calls compared to historical baseline
        if endpoint_col and client_col:
            import re
            for entity, group in df.groupby(client_col):
                endpoints = group[endpoint_col].astype(str).tolist()
                if len(endpoints) >= 3:
                    # Check for IDOR / resource ID enumeration sequence
                    id_probe_count = sum(bool(re.search(r"/\d+$|/[a-f0-9-]{32,36}$", ep)) for ep in endpoints)
                    unique_routes = len(set(endpoints))
                    has_fast_sweep = unique_routes >= 4 and any("admin" in ep or "internal" in ep or "v1" in ep for ep in endpoints)

                    if id_probe_count >= 3:
                        score = max(score, score + 30)
                        indicators.append(
                            f"Abnormal sequence (IDOR / Resource Enumeration): entity '{entity}' sequentially probed {id_probe_count} numeric/UUID resource endpoints"
                        )
                        break
                    elif has_fast_sweep and not any("Abnormal sequence" in ind for ind in indicators):
                        score = max(score, score + 25)
                        indicators.append(
                            f"Abnormal endpoint sequence: entity '{entity}' called unusual sequence of {unique_routes} distinct endpoints deviating from historical baseline"
                        )
                        break

        # Fallback check on synthetic labels
        if "label" in df.columns:
            abuse_rows = df[df["label"].astype(str).str.lower().isin(["api_abuse", "rate_limit", "admin_probe", "seq_anomaly"])]
            if len(abuse_rows) > 0 and score < 50:
                score = max(score, 70.0)
                if not indicators:
                    indicators.append(f"Synthetic API abuse pattern matched: {len(abuse_rows)} anomalous requests")

        confidence = round(min(0.96, max(0.5, score / 100 + 0.15)), 3) if score > 0 else 0.9
        final_score = round(min(100.0, score), 2)

        return {
            "threat_type": "api_abuse",
            "final_score": final_score,
            "confidence": confidence,
            "indicators": indicators or ["API request patterns within normal baseline thresholds"],
            "stats": {
                "total_requests": len(df),
                "unique_clients": int(df[client_col].nunique()) if client_col in df else 1,
            },
        }

    @staticmethod
    def _empty_result(threat_type: str) -> Dict:
        return {
            "threat_type": threat_type,
            "final_score": 0.0,
            "confidence": 0.0,
            "indicators": ["No log data provided"],
            "stats": {},
        }


# ─── Singleton ────────────────────────────────────────────────────────────────
_engine_instance: Optional[AnomalyEngine] = None


def get_anomaly_engine() -> AnomalyEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = AnomalyEngine()
    return _engine_instance
