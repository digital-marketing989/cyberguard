# CyberGuard

> **AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System**
> Final-Year Computer Science Capstone Project

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     CyberGuard Architecture                      │
├──────────────────┬──────────────────────────────────────────────┤
│  React Frontend  │              FastAPI Backend                  │
│  (Vite + Tailwind│                                              │
│   CSS)           │  ┌─────────────────────────────────────────┐ │
│                  │  │           Detection Engines              │ │
│  ┌────────────┐  │  │  ┌────────────┐  ┌──────────────────┐  │ │
│  │ Dashboard  │◄─┼─►│  │  Phishing  │  │   Deepfake CV    │  │ │
│  │ (Charts +  │  │  │  │  Engine    │  │  (OpenCV + PIL)  │  │ │
│  │  WS Feed)  │  │  │  │ TF-IDF+LR │  └──────────────────┘  │ │
│  └────────────┘  │  │  └────────────┘  ┌──────────────────┐  │ │
│  ┌────────────┐  │  │  ┌────────────┐  │  Impersonation   │  │ │
│  │ Phishing   │  │  │  │  Anomaly   │  │  Engine          │  │ │
│  │   Scan     │  │  │  │  Engine    │  │  (Levenshtein +  │  │ │
│  └────────────┘  │  │  │(IsoForest) │  │   Stylometry)   │  │ │
│  ┌────────────┐  │  │  └────────────┘  └──────────────────┘  │ │
│  │ Deepfake   │  │  └─────────────────────────────────────────┘ │
│  │   Scan     │  │  ┌─────────────────────────────────────────┐ │
│  └────────────┘  │  │           Support Layer                  │ │
│  ┌────────────┐  │  │  ┌──────────┐ ┌───────────┐ ┌─────────┐ │ │
│  │Impersonation│ │  │  │  Risk    │ │ Response  │ │ OpenRtr │ │ │
│  │   Scan     │  │  │  │  Scorer  │ │Recommender│ │   LLM   │ │ │
│  └────────────┘  │  │  └──────────┘ └───────────┘ └─────────┘ │ │
│  ┌────────────┐  │  │  ┌──────────────────────┐ ┌───────────┐ │ │
│  │  Auth +    │  │  │  │ WebSocket Manager    │ │ SQLite DB │ │ │
│  │  Network   │  │  │  │ (Live Event Feed)    │ │ (Storage) │ │ │
│  └────────────┘  │  │  └──────────────────────┘ └───────────┘ │ │
│  ┌────────────┐  │  └─────────────────────────────────────────┘ │
│  │ Incidents  │  │                                               │
│  └────────────┘  │  REST API + WebSocket (/ws/timeline)         │
└──────────────────┴──────────────────────────────────────────────┘
```

---

## Setup & Run Instructions

### Prerequisites
- Python 3.11+
- Node.js 18+
- pip

### 1. Backend

```bash
cd cyberguard/backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate        # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY

# Generate synthetic data CSVs
python scripts/seed.py

# Start the server (DB seeded automatically on first run)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at: http://localhost:8000/docs

### 2. Frontend

```bash
cd cyberguard/frontend
npm install
npm run dev
```

Frontend available at: http://localhost:5173

### 3. OpenRouter API Key

1. Sign up at https://openrouter.ai
2. Generate an API key
3. Add to `backend/.env`:
   ```
   OPENROUTER_API_KEY=your_key_here
   ```
4. Without a key, the system falls back to template-based explanations — the demo still works fully.

---

## Models & Algorithms by Module

| Module | Algorithm / Model | Library |
|--------|-------------------|---------|
| Phishing Detection | TF-IDF + Logistic Regression | scikit-learn |
| Phishing Rules | Levenshtein distance, regex patterns | python-Levenshtein |
| QR Phishing Detection | QR Code decoding + URL Heuristic Scoring | pyzbar, OpenCV, tldextract |
| URL Scanner | Heuristic scoring (typosquatting, TLD, SSL) | tldextract |
| Deepfake Image | FFT analysis, noise floor, EXIF check | OpenCV, Pillow |
| Deepfake Audio | Spectral flatness, MFCC, F0 continuity | librosa |
| Deepfake Video | Frame sampling + per-frame image analysis | OpenCV |
| Impersonation | Levenshtein + TF-IDF cosine similarity | scikit-learn |
| Auth Anomaly | Isolation Forest + z-score heuristics | scikit-learn |
| Network Anomaly | Rule-based heuristics (port scan, rate) | pandas |
| API Abuse Detection | Burst rate calculation, sensitive endpoint RBAC checks, sequence deviation | pandas, regex |
| Risk Scoring | Weighted sub-score aggregation | custom |
| Explainer AI | OpenRouter LLM (GPT-4o-mini) | openai SDK |
| Response Recommender | Rule table mapping + mandatory SOC/escalation policies | custom |

---

## Risk Scoring Thresholds

```
Score Range | Risk Level
0  – 15    | Safe      (green)
16 – 35    | Low       (blue)
36 – 60    | Medium    (yellow)
61 – 80    | High      (orange)
81 – 100   | Critical  (red)
```

Weighted sub-score contributions (example for phishing):
- ML classifier probability: 40%
- Rule-based indicator score: 40%
- URL heuristic score: 20%

---

## Synthetic Data

All data files in `backend/data/` are **100% synthetic** and generated programmatically for demonstration purposes only. They contain **no real user data**.

- `sample_phishing_emails.csv` — 200 synthetic email examples (phishing + legitimate), labeled 0/1
- `sample_urls.csv` — 150 synthetic URLs with labels
- `sample_auth_logs.csv` — 200 simulated login events (normal + brute force + password spray + impossible travel)
- `sample_network_logs.csv` — 305 simulated network flows (normal + port scan + DDoS + data exfil)

---

## Classifier Evaluation Results

Run: `python scripts/evaluate.py`

Expected approximate results on synthetic data:

**Phishing Classifier (TF-IDF + LogReg):**
- Accuracy: ~0.95+
- Precision (Phishing): ~0.94
- Recall (Phishing): ~0.97
- F1 (Phishing): ~0.95

**URL Heuristic Detector:**
- Accuracy: ~0.90+

*Note: Results are on synthetic/generated data for demonstration. Performance on real-world data may differ.*

---

## Docker Deployment

```bash
# Build and run both services
cp backend/.env.example backend/.env
# Edit backend/.env with your OPENROUTER_API_KEY

docker-compose up --build

# Backend:  http://localhost:8000
# Frontend: http://localhost:80
```

---

## Scalability & Deployment Notes

### Containerization
The provided `docker-compose.yml` runs both services in Docker containers. For production:

1. **Database**: Swap SQLite → PostgreSQL (change `DATABASE_URL` in `.env`)
2. **Message Queue**: Add Celery + Redis/RabbitMQ for high-volume asynchronous log ingestion
3. **Detection Microservices**: Deploy each engine (`phishing_engine`, `deepfake_engine`, etc.) as independent FastAPI microservices behind an API gateway
4. **Model Storage**: Store trained models in S3/GCS instead of local `models_cache/`
5. **Real Data Sources**: Replace synthetic CSVs with:
   - SIEM integrations (Splunk, Elastic SIEM)
   - Email gateway connectors (Microsoft 365, Google Workspace)
   - EDR/MDR platform feeds
6. **WebSocket Scaling**: Use Redis Pub/Sub to fan out WebSocket events across multiple server instances
7. **Authentication**: Add JWT/OAuth2 for multi-user SOC access control

---

## API Endpoints Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/phishing/analyze` | Analyze email/SMS text |
| POST | `/api/phishing/analyze-file` | Upload .eml file |
| POST | `/api/phishing/analyze-qr` | Upload QR image for quishing detection |
| POST | `/api/url/scan` | Scan a URL |
| POST | `/api/deepfake/analyze` | Analyze image/audio/video |
| POST | `/api/impersonation/analyze` | Detect impersonation |
| POST | `/api/auth/analyze` | Analyze auth log JSON |
| POST | `/api/auth/upload` | Upload auth log CSV |
| GET | `/api/auth/sample` | Run on built-in sample data |
| POST | `/api/network/analyze` | Analyze network logs |
| POST | `/api/network/analyze-api` | Analyze API logs for abuse/rate/probes |
| GET | `/api/network/sample-api` | Run API abuse detection on sample data |
| GET | `/api/dashboard/summary` | Dashboard stats |
| GET | `/api/dashboard/timeline` | Recent events |
| GET | `/api/incidents/` | List incidents |
| PATCH | `/api/incidents/{id}` | Update incident status |
| WS | `/ws/timeline` | Live event feed |

---

*CyberGuard — Built as a Final-Year Capstone by [Your Name], [Institution], [Year]*
