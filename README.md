# Brand Intelligence Backend (BIB) - ABIAE-IHCY1

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=Python&logoColor=white)](https://www.python.org)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0+-D71F00.svg?style=flat&logo=SQLAlchemy&logoColor=white)](https://www.sqlalchemy.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg?style=flat&logo=Docker&logoColor=white)](https://www.docker.com)

**Brand Intelligence Backend** is an autonomous brand protection and anti-impersonation engine. It bridges domain squatting discovery with explainable AI deep URL threat analysis, generating structured security case dossiers and dispatching actionable takedown incidents to downstream enforcement platforms.

---

## 1. Architecture Overview

The system unifies two open-source intelligence tools:
1. **`opensquat/opensquat`**: Monitors Newly Registered Domains (NRDs) and certificate streams, generating lookalike permutations (homoglyphs, omissions, transpositions, keyword insertions) and calculating Levenshtein similarity scores against protected brands.
2. **`abhishekayu/trustlens-ai`**: An explainable AI-powered multi-engine URL inspection service that evaluates live targets across SSL validity, DNS resolution, MX records, visual DOM rendering, and credential harvesting forms to produce a 0–100 trust score and visual screenshot evidence.

```
+-----------------------------------------------------------------------------------+
|                        Brand Intelligence Backend (FastAPI)                       |
|                                                                                   |
|  +--------------------+      +-----------------------+      +------------------+  |
|  |  openSquat Runner  | ---> | DomainThreat Ingestion| ---> |  TrustLens-AI    |  |
|  | (NRD/Lookalikes)   |      |  (PENDING_ANALYSIS)   |      |  Client (/analyze)|  |
|  +--------------------+      +-----------------------+      +------------------+  |
|            |                                                         |            |
|            v                                                         v            |
|     [ data/*.json ]                                           [ Trust Scores & ]  |
|                                                               [ Visual Evidence]  |
|                                                                      |            |
|                                                                      v            |
|                                                      +-------------------------+  |
|                                                      |   Risk Scoring Engine   |  |
|                                                      |  (Squat + TrustLens)    |  |
|                                                      +-------------------------+  |
|                                                                      |            |
|                                                                      v            |
|  +--------------------+      +-----------------------+      +------------------+  |
|  |  REST API (/cases) | <--- |   PostgreSQL Database | <--- | Case Creation    |  |
|  |  REST API (/scans) |      | (Threats, Cases, Scans|      +------------------+  |
|  +--------------------+      +-----------------------+               |            |
+----------------------------------------------------------------------|------------+
                                                                       | (Score >= 70)
                                                                       v
                                                        +-----------------------------+
                                                        |  Antigravity Platform       |
                                                        |  POST /api/brand-risk-events|
                                                        +-----------------------------+
```

---

## 2. End-to-End Data Flow

1. **Discovery (openSquat)**:
   - The scheduler (or manual REST trigger) executes openSquat against the configured `BRAND_LIST`.
   - Discovered lookalikes are saved to `data/scan_<id>_opensquat.json`.
2. **Threat Ingestion**:
   - The ingestion worker reads candidate domains, creates `DomainThreat` entries in PostgreSQL, and flags them as `PENDING_ANALYSIS`.
3. **Deep URL Inspection (TrustLens-AI)**:
   - The backend calls `POST {TRUSTLENS_BASE_URL}/analyze` with `https://<domain>`.
   - TrustLens returns the trust score ($0-100$), risk level (`LOW`/`MEDIUM`/`HIGH`), explainable reasons, screenshot URL, DOM snapshot, and engine telemetry.
4. **Case Synthesis & Risk Scoring**:
   - The `RiskScorer` engine computes a unified 0–100 risk score combining domain squat similarity ($45\%$) and TrustLens trust inversion ($55\%$), plus multipliers for credential inputs and external reputation flags.
   - A `Case` record is persisted with structured visual and network evidence.
5. **Antigravity Alerting**:
   - If `risk_score >= RISK_THRESHOLD_FOR_ANTIGRAVITY` (default: `70`), the `AntigravityClient` dispatches a structured incident to `POST {ANTIGRAVITY_BASE_URL}/api/brand-risk-events` with Bearer auth.
   - The returned `event_id` is linked to `Case.antigravity_event_id` for end-to-end traceability.

---

## 3. Configuration

Create a `.env` file from the provided `.env.example`:

```bash
cp .env.example .env
```

### Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite+aiosqlite:///./data/brand_intel.db` | Async database URI (`postgresql+asyncpg://...` or SQLite) |
| `TRUSTLENS_BASE_URL` | `http://localhost:8001` | Base URL of the TrustLens-AI service |
| `TRUSTLENS_TIMEOUT_SECONDS`| `30.0` | HTTP request timeout for deep URL analysis |
| `ANTIGRAVITY_BASE_URL` | `https://antigravity.example.com` | Base URL of the Antigravity takedown platform |
| `ANTIGRAVITY_API_KEY` | `ag_sec_key_demo123456789` | Bearer token for authenticating with Antigravity |
| `RISK_THRESHOLD_FOR_ANTIGRAVITY` | `70` | Minimum combined risk score (0–100) to trigger Antigravity dispatch |
| `BRAND_LIST` | `["google", "microsoft", "paypal"]` | JSON array or comma-separated list of brand keywords to protect |
| `OPENSQUAT_CRON_SCHEDULE` | `0 0 * * *` | APScheduler cron schedule for periodic domain scans |
| `DATA_DIR` | `./data` | Local directory for raw openSquat scan files |

---

## 4. Running with Docker Compose

The easiest way to run the entire stack (FastAPI backend, PostgreSQL, TrustLens-AI engine, and background worker):

```bash
docker-compose up --build
```

### Services Included in Docker Compose:
- **`bib`**: Main FastAPI application on `http://localhost:8000` (Interactive Swagger docs: `http://localhost:8000/docs`).
- **`db`**: PostgreSQL 16 database on port `5432`.
- **`trustlens_service`**: TrustLens-AI engine on `http://localhost:8001`.
- **`worker`**: Background folder watcher and scheduler worker.

To run in the background:
```bash
docker-compose up -d
```

---

## 5. Running Locally (Without Docker)

### 1. Install Dependencies
```bash
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Start the Reference / Mock TrustLens-AI Engine
```bash
python mock_trustlens/main.py
```

### 3. Start the FastAPI Application
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### 4. Run the openSquat Worker (Optional / Background)
```bash
python workers/opensquat_job.py --watch
```

---

## 6. REST API Endpoints

### Scans API (`/scans`)

#### 1. Trigger Immediate Scan
```http
POST /scans/domains
Content-Type: application/json

{
  "brand_list": ["paypal", "apple"],
  "confidence_threshold": 0.75
}
```
**Response (202 Accepted):**
```json
{
  "scan_id": "c1f7a8b4-52d3-4a11-a889-123456789abc",
  "status": "RUNNING",
  "brand_list": ["paypal", "apple"],
  "message": "Brand scan queued for 2 brands. Analysis in progress."
}
```

#### 2. Get Scan Details & Raw Threat Findings
```http
GET /scans/{scan_id}
```

---

### Cases API (`/cases`)

#### 1. List Security Cases (with Filtering & Pagination)
```http
GET /cases?risk_level=HIGH&min_score=75&page=1&page_size=20
```
**Response (200 OK):**
```json
{
  "total": 14,
  "page": 1,
  "page_size": 20,
  "items": [
    {
      "id": "e93a0b81-a6b1-4f99-8cf6-c3d5e2a90123",
      "threat_id": "b73a0b81-a6b1-4f99-8cf6-c3d5e2a90456",
      "channel": "web_domain",
      "target": "https://paypa1-security-login.com",
      "risk_score": 89,
      "risk_level": "HIGH",
      "reasons": [
        "Critical brand lookalike domain detected (88% Levenshtein match for 'paypal')",
        "Credential harvesting form detected on landing page",
        "Mismatched SSL certificate subject alternative names (SAN)"
      ],
      "evidence": {
        "screenshot_url": "https://evidence.storage/screenshots/12345.png",
        "html_snapshot_url": "https://evidence.storage/dom/12345.html",
        "ssl": { "valid": true, "issuer": "Let's Encrypt Authority X3" },
        "dns": { "resolved": true, "ip": "198.51.100.42" }
      },
      "antigravity_event_id": "ag_evt_8f192b0c1122",
      "created_at": "2026-08-22T00:30:00Z"
    }
  ]
}
```

#### 2. Get Case Dossier
```http
GET /cases/{case_id}
```

#### 3. Re-Evaluate Case
```http
POST /cases/{case_id}/re-evaluate
```

---

## 7. Antigravity Event Payload Specification

When a case satisfies `risk_score >= RISK_THRESHOLD_FOR_ANTIGRAVITY`, the client transmits the following JSON payload:

```json
{
  "event_type": "brand_impersonation_detected",
  "case_id": "e93a0b81-a6b1-4f99-8cf6-c3d5e2a90123",
  "channel": "web_domain",
  "target": "https://paypa1-security-login.com",
  "risk_score": 89,
  "risk_level": "HIGH",
  "reasons": [
    "Critical brand lookalike domain detected (88% Levenshtein match for 'paypal')",
    "Credential harvesting form detected on landing page",
    "Mismatched SSL certificate subject alternative names (SAN)"
  ],
  "evidence": {
    "target_domain": "paypa1-security-login.com",
    "protected_brand": "paypal",
    "similarity_score": 0.88,
    "screenshot_url": "https://evidence.storage/screenshots/12345.png",
    "html_snapshot_url": "https://evidence.storage/dom/12345.html",
    "ssl": { "valid": true, "issuer": "Let's Encrypt Authority X3" },
    "dns": { "resolved": true, "ip": "198.51.100.42" },
    "content": { "has_password_field": true, "impersonation_detected": true }
  },
  "recommended_action": "takedown_phishing"
}
```

---

## 8. Extending to Multi-Channel Intelligence

The `brand-intelligence-backend` architecture is designed with modularity to easily scale beyond web domains:

1. **Marketplaces (`channel: "marketplace"`)**:
   - Add a marketplace scraper runner (Amazon, eBay, AliExpress, Shopee) targeting counterfeits and unauthorized brand sellers.
   - Ingest seller metadata and product listings as `MarketplaceThreat` records.
   - Use TrustLens content and OCR image engines to evaluate logo forgery and calculate listing risk score.
2. **Mobile App Stores (`channel: "mobile_app"`)**:
   - Monitor Google Play Store and Apple App Store API feeds for fake APKs/apps with squatting package names (e.g. `com.paypa1.app`).
   - Route APK URLs to TrustLens deep static analyzer to evaluate decompiled permissions, package certificates, and icons.
3. **Social Media (`channel: "social_media"`)**:
   - Ingest Twitter/X, Instagram, LinkedIn, and Telegram handle registrations matching brand patterns.
   - Analyze profile images, follower/following ratios, and bio links with TrustLens.
   - Route social impersonation takedowns with channel-specific API payloads (`takedown_social_profile`).

---

## 9. Running Tests

Execute the automated test suite with pytest:

```bash
pytest -v
```
>>>>>>> 881b775 (Implement Brand Intelligence Backend with openSquat and TrustLens-AI integration)
