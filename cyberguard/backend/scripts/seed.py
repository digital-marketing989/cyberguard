"""
Synthetic Demo Data Generator + DB Seeder
─────────────────────────────────────────
SYNTHETIC DATA — FOR DEMONSTRATION PURPOSES ONLY.
NOT REAL USER DATA. Generated programmatically for the CyberGuard capstone demo.

Generates and saves sample CSVs (if not already present),
then seeds the SQLite database with realistic-looking threat events.
"""
from __future__ import annotations

import csv
import os
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure backend root is on path
_BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_BACKEND_ROOT))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DATA_DIR = _BACKEND_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def rand_ip():
    return f"{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def rand_ts(days_back=30):
    base = datetime.now(timezone.utc) - timedelta(days=days_back)
    delta = timedelta(seconds=random.randint(0, days_back * 86400))
    return (base + delta).isoformat()

USERS = ["alice@company.com","bob@company.com","charlie@company.com","diana@company.com",
         "eve@company.com","frank@company.com","grace@company.com","henry@company.com"]

COUNTRIES = [
    ("US", "New York", 40.71, -74.01),
    ("US", "Los Angeles", 34.05, -118.24),
    ("GB", "London", 51.51, -0.13),
    ("DE", "Berlin", 52.52, 13.40),
    ("CN", "Beijing", 39.91, 116.39),
    ("RU", "Moscow", 55.75, 37.62),
    ("BR", "São Paulo", -23.55, -46.63),
    ("IN", "Mumbai", 19.08, 72.88),
    ("AU", "Sydney", -33.87, 151.21),
    ("NG", "Lagos", 6.52, 3.38),
]

DEVICES = [f"dev-{uuid.uuid4().hex[:8]}" for _ in range(20)]


# ─── CSV generators ───────────────────────────────────────────────────────────

def generate_phishing_emails_csv():
    path = DATA_DIR / "sample_phishing_emails.csv"
    if path.exists():
        return

    PHISHING = [
        ("URGENT: Verify your PayPal account immediately or it will be suspended. Click here: http://paypa1.secure-login.xyz/verify", 1),
        ("Dear valued customer, your Apple ID has been locked. Please verify your credentials: http://apple-id.support-login.tk", 1),
        ("Action Required: Your Microsoft account shows suspicious activity. Update your password now: http://microsoft-secure.cf/update", 1),
        ("Your bank account has been compromised. Verify your identity within 24 hours: http://192.168.1.1/bank-verify", 1),
        ("Congratulations! You've won a $1000 Amazon gift card. Click here to claim: http://amaz0n-gifts.ml/claim", 1),
        ("IMPORTANT: Your Netflix subscription will expire. Update billing: http://netflix-billing.xyz/update", 1),
        ("IRS Notice: You owe $2,340 in back taxes. Pay immediately to avoid arrest: http://irs-payment.tk/pay", 1),
        ("Security Alert: Unauthorized login from Russia. Verify your Google account: http://google-security.ml/verify", 1),
        ("Dear User, your DHL package is on hold. Confirm your address: http://dhl-delivery.cf/confirm", 1),
        ("Your password will expire in 24 hours. Click to renew: http://office365.secure-portal.xyz/renew", 1),
        ("Please enter your username and password to access the secure portal immediately.", 1),
        ("FINAL NOTICE: Your account is suspended! Verify credit card details now to restore access.", 1),
        ("Win a FREE iPhone 15! Limited time offer — click here to enter now!", 1),
        ("Dear account holder, unusual activity detected. Confirm your routing number and SSN.", 1),
        ("Your session expired. Enter your login credentials to continue: http://bit.ly/secure-login", 1),
    ]
    LEGIT = [
        ("Hi team, please find attached the Q3 financial report for your review. Let me know if you have questions.", 0),
        ("Following up on our meeting from last Tuesday — can we schedule a call this week to discuss the roadmap?", 0),
        ("Your order #12345 has shipped! Expected delivery: Friday, September 6. Track at fedex.com/tracking.", 0),
        ("Welcome to the team! Your onboarding schedule is attached. Looking forward to working with you.", 0),
        ("Reminder: All hands meeting tomorrow at 2pm in Conference Room B. Agenda attached.", 0),
        ("Your monthly statement is ready. Log in at chase.com to view your transactions.", 0),
        ("Thank you for your purchase. Your receipt is attached. Contact support@company.com with questions.", 0),
        ("The project deadline has been moved to October 15. Please update your timelines accordingly.", 0),
        ("Please review and sign the attached NDA before our partnership discussion next week.", 0),
        ("Happy to help! I have forwarded your request to the appropriate team. Expect a response within 2 business days.", 0),
        ("Our offices will be closed on Monday for the public holiday. Regular hours resume Tuesday.", 0),
        ("Congratulations on completing the training module! Your certificate is attached.", 0),
        ("Your subscription has been renewed successfully. Next billing date: October 1, 2026.", 0),
        ("The server maintenance window is scheduled for this Saturday 2am-4am UTC.", 0),
        ("Please find the updated project timeline in the shared drive. All milestones have been reviewed.", 0),
    ]

    # Augment to ~200 rows
    data = list(PHISHING) * 7 + list(LEGIT) * 7
    random.shuffle(data)

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        for text, label in data:
            # Add minor noise
            if random.random() < 0.2:
                text = text + " " + random.choice(["!", "Please respond.", "Act now."])
            w.writerow([text, label])

    print(f"✓ Generated {path} ({len(data)} rows)")


def generate_urls_csv():
    path = DATA_DIR / "sample_urls.csv"
    if path.exists():
        return

    rows = [
        # label: 1=malicious, 0=safe
        ("https://paypa1.secure-login.xyz/verify-account", 1),
        ("http://192.168.100.25/admin/login", 1),
        ("https://microsoft-secure-update.tk/reset-password", 1),
        ("http://gooogle.com/login", 1),
        ("https://amaz0n-gifts.ml/claim-prize", 1),
        ("http://bit.ly/secure-bank-verify", 1),
        ("https://netflix.biling-update.cf/payment", 1),
        ("http://apple-id-support.online/verify", 1),
        ("https://dhl-delivery-confirm.xyz/track", 1),
        ("http://login.paypal.secure-verify.work/signin", 1),
        ("https://irs-refund.tk/collect", 1),
        ("https://facebook-login.club/signin", 1),
        ("http://123.45.67.89/phishing-page", 1),
        ("https://dropboxx.top/shared-file", 1),
        ("http://update-windows-now.download/patch", 1),
        ("https://www.google.com/search?q=python", 0),
        ("https://github.com/openai/openai-python", 0),
        ("https://docs.python.org/3/library/os.html", 0),
        ("https://www.amazon.com/dp/B08N5WRWNW", 0),
        ("https://en.wikipedia.org/wiki/Phishing", 0),
        ("https://stackoverflow.com/questions/12345", 0),
        ("https://www.microsoft.com/en-us/windows", 0),
        ("https://support.apple.com/en-us/HT204974", 0),
        ("https://accounts.google.com/signin", 0),
        ("https://www.linkedin.com/in/someone", 0),
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label"])
        for url, label in rows * 6:
            w.writerow([url, label])

    print(f"✓ Generated {path} ({len(rows)*6} rows)")


def generate_auth_logs_csv():
    path = DATA_DIR / "sample_auth_logs.csv"
    if path.exists():
        return

    rows = []

    # Normal logins (label: benign)
    for _ in range(100):
        user = random.choice(USERS)
        country = random.choice(COUNTRIES[:4])  # US/GB only for normal
        device = random.choice(DEVICES[:5])
        rows.append({
            "username": user,
            "timestamp": rand_ts(30),
            "ip_address": rand_ip(),
            "geo_country": country[0],
            "geo_city": country[1],
            "latitude": country[2] + random.uniform(-0.5, 0.5),
            "longitude": country[3] + random.uniform(-0.5, 0.5),
            "device_fingerprint": device,
            "success": "true",
            "failure_reason": "",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "label": "benign",
        })

    # Brute force attack on alice
    base_ts = datetime.now(timezone.utc) - timedelta(hours=2)
    for i in range(20):
        rows.append({
            "username": "alice@company.com",
            "timestamp": (base_ts + timedelta(seconds=i * 15)).isoformat(),
            "ip_address": "185.220.101.45",
            "geo_country": "RU",
            "geo_city": "Moscow",
            "latitude": 55.75,
            "longitude": 37.62,
            "device_fingerprint": "unknown-device-abc",
            "success": "false",
            "failure_reason": "Invalid password",
            "user_agent": "python-requests/2.28",
            "label": "brute_force",
        })

    # Password spray (same IP, many users)
    spray_ts = datetime.now(timezone.utc) - timedelta(hours=5)
    for i, user in enumerate(USERS):
        rows.append({
            "username": user,
            "timestamp": (spray_ts + timedelta(minutes=i * 2)).isoformat(),
            "ip_address": "103.45.67.89",
            "geo_country": "CN",
            "geo_city": "Beijing",
            "latitude": 39.91,
            "longitude": 116.39,
            "device_fingerprint": "spray-device-xyz",
            "success": "false",
            "failure_reason": "Invalid password",
            "user_agent": "curl/7.85.0",
            "label": "password_spray",
        })

    # Impossible travel — bob logs in from NY, then Moscow 30 minutes later
    travel_ts = datetime.now(timezone.utc) - timedelta(hours=10)
    rows.append({
        "username": "bob@company.com",
        "timestamp": travel_ts.isoformat(),
        "ip_address": "72.14.200.1",
        "geo_country": "US",
        "geo_city": "New York",
        "latitude": 40.71,
        "longitude": -74.01,
        "device_fingerprint": "bob-laptop-001",
        "success": "true",
        "failure_reason": "",
        "user_agent": "Mozilla/5.0 Safari/537.36",
        "label": "impossible_travel",
    })
    rows.append({
        "username": "bob@company.com",
        "timestamp": (travel_ts + timedelta(minutes=30)).isoformat(),
        "ip_address": "91.108.56.100",
        "geo_country": "RU",
        "geo_city": "Moscow",
        "latitude": 55.75,
        "longitude": 37.62,
        "device_fingerprint": "unknown-device-russia",
        "success": "true",
        "failure_reason": "",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/120",
        "label": "impossible_travel",
    })

    # Sort by timestamp
    rows.sort(key=lambda r: r["timestamp"])

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"✓ Generated {path} ({len(rows)} rows)")


def generate_network_logs_csv():
    path = DATA_DIR / "sample_network_logs.csv"
    if path.exists():
        return

    rows = []
    # Normal traffic
    for _ in range(150):
        rows.append({
            "timestamp": rand_ts(7),
            "src_ip": rand_ip(),
            "dst_ip": rand_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_port": random.choice([80, 443, 22, 8080, 3306]),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"]),
            "bytes_in": random.randint(100, 50000),
            "bytes_out": random.randint(100, 50000),
            "action": "ALLOW",
            "label": "normal",
        })

    # Port scan attack
    scanner_ip = "45.33.32.156"
    scan_ts = datetime.now(timezone.utc) - timedelta(hours=1)
    for port in random.sample(range(1, 65535), 50):
        rows.append({
            "timestamp": (scan_ts + timedelta(milliseconds=random.randint(0, 60000))).isoformat(),
            "src_ip": scanner_ip,
            "dst_ip": "10.0.1.50",
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "bytes_in": 64,
            "bytes_out": 0,
            "action": "DENY",
            "label": "port_scan",
        })

    # High-volume DDoS-style flood
    ddos_ip = "198.51.100.42"
    for _ in range(100):
        rows.append({
            "timestamp": rand_ts(1),
            "src_ip": ddos_ip,
            "dst_ip": "10.0.0.1",
            "src_port": random.randint(1024, 65535),
            "dst_port": 80,
            "protocol": "HTTP",
            "bytes_in": 500,
            "bytes_out": 0,
            "action": "ALLOW",
            "label": "ddos",
        })

    # Large data exfil
    for _ in range(5):
        rows.append({
            "timestamp": rand_ts(3),
            "src_ip": "10.0.1.100",
            "dst_ip": rand_ip(),
            "src_port": random.randint(1024, 65535),
            "dst_port": 443,
            "protocol": "HTTPS",
            "bytes_in": random.randint(1000, 5000),
            "bytes_out": random.randint(60_000_000, 200_000_000),
            "action": "ALLOW",
            "label": "data_exfil",
        })

    # API abuse traffic
    api_abuser_ip = "192.0.2.77"
    for ep_port in [443, 8443]:
        for _ in range(12):
            rows.append({
                "timestamp": rand_ts(2),
                "src_ip": api_abuser_ip,
                "dst_ip": "10.0.1.5",
                "src_port": random.randint(1024, 65535),
                "dst_port": ep_port,
                "protocol": "HTTPS",
                "bytes_in": 1200,
                "bytes_out": 450,
                "action": "DENY",
                "label": "api_abuse",
            })

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"✓ Generated {path} ({len(rows)} rows)")


def generate_api_logs_csv():
    path = DATA_DIR / "sample_api_logs.csv"
    if path.exists():
        return

    rows = []
    # Normal API requests
    normal_endpoints = ["/api/v1/profile", "/api/v1/dashboard", "/api/v1/items", "/api/v1/notifications"]
    for _ in range(80):
        rows.append({
            "timestamp": rand_ts(5),
            "client_ip": rand_ip(),
            "api_key": f"key_std_{random.randint(100, 999)}",
            "user_id": f"user_{random.randint(1, 50)}@company.com",
            "role": "user",
            "endpoint": random.choice(normal_endpoints),
            "method": "GET",
            "status_code": 200,
            "response_time_ms": random.randint(25, 120),
            "label": "normal",
        })

    # Pattern 1: Excessive rate burst from single API key
    burst_ts = datetime.now(timezone.utc) - timedelta(minutes=15)
    burst_key = "key_attacker_burst_999"
    burst_ip = "198.51.100.88"
    for i in range(25):
        rows.append({
            "timestamp": (burst_ts + timedelta(milliseconds=i * 400)).isoformat(),
            "client_ip": burst_ip,
            "api_key": burst_key,
            "user_id": "malicious_script@external.io",
            "role": "user",
            "endpoint": "/api/v1/orders/search",
            "method": "POST",
            "status_code": 429 if i >= 10 else 200,
            "response_time_ms": 15,
            "label": "api_abuse",
        })

    # Pattern 2: Repeated access to sensitive/admin endpoints by non-admin user
    admin_probe_ip = "203.0.113.15"
    admin_endpoints = ["/admin/users/export", "/admin/system/config", "/admin/keys/rotate", "/admin/audit/logs"]
    for ep in admin_endpoints:
        for _ in range(3):
            rows.append({
                "timestamp": rand_ts(1),
                "client_ip": admin_probe_ip,
                "api_key": "key_intern_read_01",
                "user_id": "intern_dev_03@company.com",
                "role": "user",
                "endpoint": ep,
                "method": "GET",
                "status_code": 403,
                "response_time_ms": 45,
                "label": "api_abuse",
            })

    # Pattern 3: Abnormal sequence / IDOR enumeration
    idor_ip = "192.0.2.140"
    for obj_id in range(1001, 1010):
        rows.append({
            "timestamp": rand_ts(1),
            "client_ip": idor_ip,
            "api_key": "key_idor_probe_55",
            "user_id": "recon_bot_44@shadow.net",
            "role": "user",
            "endpoint": f"/api/v1/invoices/{obj_id}",
            "method": "GET",
            "status_code": 200,
            "response_time_ms": 30,
            "label": "api_abuse",
        })

    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

    print(f"✓ Generated {path} ({len(rows)} rows)")


# ─── DB seeder ────────────────────────────────────────────────────────────────

SEED_EVENTS = [
    # Phishing events
    {"threat_type": "Phishing", "risk_level": "Critical", "risk_score": 92.5, "confidence": 0.97,
     "indicators": ["Urgency language: 'verify immediately'", "Domain 'paypa1.com' ≈ 'paypal.com'",
                    "Credential request: 'enter your password'", "Suspicious URL with .xyz TLD"],
     "explanation": "Critical Risk: This message exhibits multiple high-confidence phishing indicators including a typosquatted PayPal domain, urgent credential request, and a suspicious .xyz TLD URL. Immediate quarantine and user notification is recommended.",
     "recommended_actions": ["Quarantine the email", "Block the malicious URL", "Notify the affected user"],
     "raw_input_summary": "URGENT: Your PayPal account will be suspended. Verify at http://paypa1.secure-login.xyz",
     "target_user": "alice@company.com", "mitre_tag": "T1566 – Phishing"},
    {"threat_type": "Phishing", "risk_level": "High", "risk_score": 73.2, "confidence": 0.88,
     "indicators": ["Free email (gmail) claiming corporate identity", "Action required subject line",
                    "Generic greeting: 'Dear valued customer'"],
     "explanation": "High Risk: Sender uses a free Gmail account while impersonating corporate IT support, combined with urgency language and a generic impersonal greeting.",
     "recommended_actions": ["Quarantine email", "Warn user", "Flag for review"],
     "raw_input_summary": "Dear valued customer, your account requires urgent attention.",
     "target_user": "bob@company.com", "mitre_tag": "T1566 – Phishing"},
    {"threat_type": "Phishing", "risk_level": "Medium", "risk_score": 52.0, "confidence": 0.71,
     "indicators": ["URL shortener: bit.ly — destination obscured", "Urgency: 'act now'"],
     "explanation": "Medium Risk: Message contains an obfuscated URL shortener link combined with urgency language.",
     "recommended_actions": ["Warn user", "Flag for review"],
     "raw_input_summary": "Click here to claim your prize: http://bit.ly/abc123",
     "target_user": "charlie@company.com", "mitre_tag": "T1566 – Phishing"},
    # URL Scans
    {"threat_type": "Malicious URL", "risk_level": "Critical", "risk_score": 88.0, "confidence": 0.94,
     "indicators": ["URL uses raw IP address: 192.168.1.1", "HTTP (no SSL)", "Phishing keywords: login, verify"],
     "explanation": "Critical Risk: The URL uses a raw IP address as its domain, lacks SSL encryption, and contains multiple phishing-related keywords.",
     "recommended_actions": ["Block URL at web gateway", "Notify SOC"],
     "raw_input_summary": "http://192.168.1.1/admin/verify-password",
     "target_service": "Web Gateway", "mitre_tag": "T1189 – Drive-by Compromise"},
    {"threat_type": "Malicious URL", "risk_level": "High", "risk_score": 71.5, "confidence": 0.85,
     "indicators": ["Typosquatting: 'microsoft-secure-update' ≈ 'microsoft'", "Suspicious TLD: .tk"],
     "explanation": "High Risk: Domain closely resembles Microsoft with a suspicious free TLD, typical of credential harvesting infrastructure.",
     "recommended_actions": ["Block URL", "Warn user"],
     "raw_input_summary": "https://microsoft-secure-update.tk/reset-password",
     "target_service": "Email Gateway", "mitre_tag": "T1189 – Drive-by Compromise"},
    # Impersonation events
    {"threat_type": "Impersonation", "risk_level": "Critical", "risk_score": 91.0, "confidence": 0.95,
     "indicators": ["'CEO' display name matches known contact but email domain 'gmail.com' ≠ 'company.com'",
                    "Authority role 'CEO' claimed from free email", "Urgent wire transfer request"],
     "explanation": "Critical Risk: This message impersonates the company CEO using a personal Gmail address, requests an urgent wire transfer, and employs pressure tactics — classic BEC (Business Email Compromise) pattern.",
     "recommended_actions": ["Quarantine email", "Report impersonation", "Notify SOC", "Escalate"],
     "raw_input_summary": "From: CEO <ceo@gmail.com> | Please wire $50,000 to this account immediately.",
     "target_user": "finance@company.com", "mitre_tag": "T1656 – Impersonation"},
    {"threat_type": "Impersonation", "risk_level": "High", "risk_score": 68.3, "confidence": 0.82,
     "indicators": ["'IT Department' domain mismatch: gmail.com vs company.com",
                    "Credential request: 'enter your password'"],
     "explanation": "High Risk: Sender claims to be IT Department but uses a free Gmail account and requests user credentials.",
     "recommended_actions": ["Quarantine email", "Warn user"],
     "raw_input_summary": "From: IT Department <helpdesk@gmail.com> | Please verify your network password.",
     "target_user": "grace@company.com", "mitre_tag": "T1656 – Impersonation"},
    # Deepfake events
    {"threat_type": "Deepfake Image", "risk_level": "High", "risk_score": 72.0, "confidence": 0.81,
     "indicators": ["No EXIF metadata present — typical of AI-generated images",
                    "Frequency-domain anomaly detected (FFT radial variance: 3.14)",
                    "Unusually uniform noise floor"],
     "explanation": "High Risk: Image lacks EXIF metadata and exhibits frequency-domain patterns consistent with GAN-generated images. Authenticity cannot be verified.",
     "recommended_actions": ["Report impersonation", "Notify SOC", "Preserve evidence"],
     "raw_input_summary": "Image file: profile_photo.jpg (2.1 MB)",
     "mitre_tag": "T1036 – Masquerading"},
    {"threat_type": "Deepfake Video", "risk_level": "Critical", "risk_score": 84.0, "confidence": 0.89,
     "indicators": ["Average per-frame deepfake score: 76.3/100",
                    "High frame-to-frame inconsistency (std: 23.1)",
                    "Unnatural facial region consistency across frames"],
     "explanation": "Critical Risk: Video exhibits high per-frame deepfake signatures with significant temporal inconsistency, strongly indicating face-swap manipulation.",
     "recommended_actions": ["Report impersonation", "Notify SOC", "Escalate", "Preserve evidence"],
     "raw_input_summary": "Video file: executive_statement.mp4 (45.3 MB, 32s)",
     "mitre_tag": "T1036 – Masquerading"},
    # Account takeover events
    {"threat_type": "Brute Force", "risk_level": "Critical", "risk_score": 90.0, "confidence": 0.96,
     "indicators": ["Brute force detected for user 'alice@company.com': 20 failed attempts from 185.220.101.45",
                    "High failure rate: 87% of login attempts failed",
                    "Statistical anomaly detected by Isolation Forest"],
     "explanation": "Critical Risk: Sustained brute-force attack detected with 20 consecutive failed attempts from a single IP address associated with Tor exit nodes.",
     "recommended_actions": ["Block IP at firewall", "Require MFA", "Reset credentials", "Notify SOC", "Escalate"],
     "raw_input_summary": "Auth log: 20 failed logins for alice@company.com from 185.220.101.45 in 5 minutes",
     "target_user": "alice@company.com", "source_ip": "185.220.101.45",
     "mitre_tag": "T1110 – Brute Force"},
    {"threat_type": "Password Spray", "risk_level": "High", "risk_score": 74.0, "confidence": 0.87,
     "indicators": ["Password spraying from IP 103.45.67.89: 8 distinct users targeted",
                    "All attempts use common passwords within 20-minute window"],
     "explanation": "High Risk: Single IP attempting authentication against 8 distinct user accounts in a short window, consistent with automated password spraying.",
     "recommended_actions": ["Block IP", "Require MFA", "Reset credentials", "Notify SOC"],
     "raw_input_summary": "Auth log: 8 users targeted by password spray from 103.45.67.89",
     "source_ip": "103.45.67.89", "mitre_tag": "T1110.003 – Password Spraying"},
    {"threat_type": "Impossible Travel", "risk_level": "High", "risk_score": 78.0, "confidence": 0.91,
     "indicators": ["Impossible travel for 'bob@company.com': 7,500 km in 0.5h (15,000 km/h) — New York → Moscow",
                    "New device login from unknown fingerprint"],
     "explanation": "High Risk: Account logged in from New York then Moscow within 30 minutes — physically impossible travel distance indicates credential compromise.",
     "recommended_actions": ["Revoke session", "Require MFA", "Reset credentials", "Block IP", "Notify SOC"],
     "raw_input_summary": "Login: bob@company.com | New York → Moscow in 30 minutes",
     "target_user": "bob@company.com", "source_ip": "91.108.56.100",
     "mitre_tag": "T1078 – Valid Accounts"},
    # Network anomaly events
    {"threat_type": "Network Anomaly", "risk_level": "High", "risk_score": 65.0, "confidence": 0.79,
     "indicators": ["Port scanning detected: 50 unique ports from 45.33.32.156",
                    "High request rate: 150 requests from single IP"],
     "explanation": "High Risk: Network logs show systematic port scanning activity from an external IP with concurrent high-rate HTTP requests.",
     "recommended_actions": ["Block IP at firewall", "Notify SOC", "Preserve evidence"],
     "raw_input_summary": "Network scan: 50 ports probed from 45.33.32.156",
     "source_ip": "45.33.32.156", "target_service": "Internal Network",
     "mitre_tag": "T1046 – Network Service Discovery"},
    {"threat_type": "Network Anomaly", "risk_level": "Critical", "risk_score": 85.0, "confidence": 0.92,
     "indicators": ["Large outbound data transfers: 5 events > 50 MB each",
                    "Unusual destination IPs during off-hours"],
     "explanation": "Critical Risk: Sustained large outbound data transfers detected, potentially indicating data exfiltration from a compromised internal host.",
     "recommended_actions": ["Block IP", "Notify SOC", "Escalate", "Preserve evidence"],
     "raw_input_summary": "Data exfil detected: 200 MB outbound from 10.0.1.100",
     "target_service": "Internal Servers", "mitre_tag": "T1046 – Network Service Discovery"},
    # Safe/Low events for variety
    {"threat_type": "Phishing", "risk_level": "Safe", "risk_score": 8.0, "confidence": 0.95,
     "indicators": [],
     "explanation": "Safe: No phishing indicators detected. The message appears to be legitimate business communication.",
     "recommended_actions": ["No action required"],
     "raw_input_summary": "Please find attached the Q3 report for your review.",
     "target_user": "henry@company.com", "mitre_tag": "T1566 – Phishing"},
    {"threat_type": "Malicious URL", "risk_level": "Low", "risk_score": 28.0, "confidence": 0.62,
     "indicators": ["URL shortener detected (bit.ly) — destination obscured"],
     "explanation": "Low Risk: URL uses a shortener service which obscures the destination. Proceed with caution.",
     "recommended_actions": ["Monitor and log", "Warn user if suspicious context"],
     "raw_input_summary": "https://bit.ly/company-report-q3",
     "mitre_tag": "T1189 – Drive-by Compromise"},
    # API Abuse events
    {"threat_type": "api_abuse", "risk_level": "Critical", "risk_score": 86.0, "confidence": 0.94,
     "indicators": ["Excessive API request burst: 25 requests in 10.0s (2.5 req/s) from api_key 'key_attacker_burst_999'",
                    "Unauthorized access to sensitive endpoints: 12 attempts to ['/admin/users/export', '/admin/system/config'] by non-admin 'intern_dev_03@company.com'"],
     "explanation": "Critical Risk: High-frequency burst queries detected from an API key with concurrent unauthorized probes into privileged admin endpoints.",
     "recommended_actions": ["Revoke active session", "Block suspicious IP/device", "Notify administrator/SOC", "Escalate the incident for investigation"],
     "raw_input_summary": "API Abuse: 25 burst requests + unauthorized /admin/users/export probing",
     "source_ip": "198.51.100.88", "target_service": "API Gateway / Admin Service",
     "mitre_tag": "T1059 – Command and Scripting Interpreter (API Abuse)"},
    {"threat_type": "api_abuse", "risk_level": "High", "risk_score": 72.0, "confidence": 0.89,
     "indicators": ["Abnormal sequence (IDOR / Resource Enumeration): 'recon_bot_44@shadow.net' sequentially probed 9 numeric resource endpoints",
                    "Repeated 403 Forbidden responses on restricted endpoints"],
     "explanation": "High Risk: Sequential ID enumeration (IDOR probe) detected across invoice records without authorization.",
     "recommended_actions": ["Revoke active session", "Block suspicious IP/device", "Require additional authentication", "Notify administrator/SOC"],
     "raw_input_summary": "API Abuse: Sequential IDOR enumeration on /api/v1/invoices/{id}",
     "source_ip": "192.0.2.140", "target_service": "API Gateway",
     "mitre_tag": "T1059 – Command and Scripting Interpreter (API Abuse)"},
    # QR Phishing event
    {"threat_type": "qr_phishing", "risk_level": "High", "risk_score": 75.0, "confidence": 0.91,
     "indicators": ["Decoded QR code URL: http://paypa1-secure-auth.xyz/login",
                    "Typosquatting: 'paypa1-secure-auth' ≈ 'paypal'", "Suspicious .xyz TLD"],
     "explanation": "High Risk: QR code embeds a typosquatted credential harvesting destination designed to bypass perimeter email URL filters.",
     "recommended_actions": ["Block suspicious URL", "Block suspicious IP/device", "Warn the user", "Notify administrator/SOC"],
     "raw_input_summary": "QR Image scan: Embedded URL http://paypa1-secure-auth.xyz/login",
     "target_service": "Mobile / Endpoint", "mitre_tag": "T1566.002 – Spearphishing Link (QR/Quishing)"},
]


def seed_all(db):
    """Seed the database with synthetic threat events and incidents."""
    from app.models import ThreatEvent, Incident

    now = datetime.now(timezone.utc)

    for i, seed in enumerate(SEED_EVENTS):
        # Spread events over the last 30 days
        created_at = now - timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59),
        )

        event = ThreatEvent(
            threat_type=seed["threat_type"],
            risk_level=seed["risk_level"],
            risk_score=seed["risk_score"],
            confidence=seed["confidence"],
            indicators=seed["indicators"],
            explanation=seed["explanation"],
            recommended_actions=seed["recommended_actions"],
            raw_input_summary=seed.get("raw_input_summary", ""),
            source_ip=seed.get("source_ip"),
            target_user=seed.get("target_user"),
            target_service=seed.get("target_service"),
            mitre_tag=seed.get("mitre_tag"),
        )
        db.add(event)
        db.flush()

        # Create incident for non-Safe events
        if seed["risk_level"] != "Safe":
            status_options = ["Open", "Investigating", "Acknowledged", "Resolved", "Escalated"]
            status = random.choice(status_options)
            incident = Incident(
                event_id=event.id,
                status=status,
                assigned_to=random.choice(["SOC Team", "Alice Smith", "Bob Jones", None]),
                notes=f"Auto-created from synthetic demo data. Status: {status}.",
            )
            db.add(incident)

    db.commit()
    print(f"✓ Seeded {len(SEED_EVENTS)} synthetic threat events into database")


if __name__ == "__main__":
    print("Generating synthetic CSV data files…")
    generate_phishing_emails_csv()
    generate_urls_csv()
    generate_auth_logs_csv()
    generate_network_logs_csv()
    generate_api_logs_csv()
    print("\nAll synthetic data files generated.")
    print("Run the FastAPI app to seed the database automatically on first start.")
