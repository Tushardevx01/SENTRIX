# SENTRIX — Production & Local Deployment Guide

This guide documents the installation, configuration, operational requirements, and deployment procedures for the **SENTRIX** platform.

---

## 1. System Architecture & Topology

SENTRIX consists of three micro-services and one primary datastore:

| Service | Technology | Port | Access Boundary | Description |
| :--- | :--- | :--- | :--- | :--- |
| **`apps/web`** | Next.js 14 (App Router) | `3000` | Public Host | User interface, investigation reports, threat telemetry dashboard. |
| **`apps/api`** | Fastify 5 + TypeScript | `8000` | Public Host / Internal | API gateway, async background scanner worker, **sole owner of MongoDB**. |
| **`services/scanner`**| Python 3.11+ / FastAPI | `8001` | Private Internal Only | Stateless threat analysis engine. **Never connects to database directly.** |
| **`mongo`** | MongoDB 7.0 | `27017` | API Gateway Only | Persistent storage for scans, findings, reports, and community votes. |

In containerized deployments (Docker / Podman), port `8001` (Scanner) is intentionally unmapped to the host network to enforce internal gateway authentication.

---

## 2. Prerequisites & Environment Requirements

* **Node.js:** `v20.x` or `v22.x` LTS
* **Package Manager:** `npm` (v10+)
* **Python:** `3.11` to `3.15`
* **Container Engine:** Docker Engine 24+ or Podman 4.9+
* **MongoDB:** MongoDB Community Server 7.0+

---

## 3. Configuration & Single Root `.env` Policy

SENTRIX enforces a strict **single root `.env` policy**.
* All services (`apps/web`, `apps/api`, `services/scanner`) automatically resolve configuration from the repository root `.env`.
* **Never create per-service or nested `.env` files.**

### Environment Variables Reference

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `NODE_ENV` | Yes | `development` | Environment mode (`development`, `production`, `test`). |
| `PORT` / `API_PORT` | Yes | `8000` | HTTP port for the Fastify API gateway. |
| `SCANNER_PORT` | Yes | `8001` | HTTP port for the Python scanner service. |
| `CORS_ORIGIN` | Yes | `http://localhost:3000` | Allowed origins for API requests. |
| `NEXT_PUBLIC_API_URL` | Yes | `http://localhost:8000` | API endpoint consumed by the Next.js frontend. |
| `MONGODB_URI` | Yes | `mongodb://127.0.0.1:27017/sentrix` | MongoDB connection string. |
| `SCANNER_INTERNAL_URL`| Yes | `http://127.0.0.1:8001` | Private URL where Fastify contacts the scanner. |
| `SCANNER_API_SECRET` | Yes | *(Random 32+ hex)* | Shared secret for inter-service authentication (`X-Scanner-Secret`). |
| `JWT_SECRET` | Prod | *(Optional in dev)* | Secret for auth tokens (minimum 32 characters in production). |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Optional | `None` | Google Safe Browsing Lookup API v4 key. |
| `URLHAUS_ENABLED` | Optional | `true` | Toggle for abuse.ch URLhaus threat feed queries. |
| `URLHAUS_API_KEY` | Optional | `None` | Auth-Key from `auth.abuse.ch` for URLhaus API. |
| `LLM_API_KEY` | Optional | `None` | Optional API key for generative threat explanations. |

### Generating a Secure Root `.env`

Create a `.env` in the project root:

```bash
cat << 'EOF' > .env
NODE_ENV=development
PORT=8000
API_PORT=8000
SCANNER_PORT=8001
CORS_ORIGIN=http://localhost:3000
NEXT_PUBLIC_API_URL=http://localhost:8000
MONGODB_URI=mongodb://127.0.0.1:27017/sentrix
SCANNER_INTERNAL_URL=http://127.0.0.1:8001
SCANNER_API_SECRET=692a8e8b2b7336c572f3e8f5cb58e4695e86d0cf9becefb8ae41541ba3c78d5e
JWT_SECRET=super_secret_jwt_signing_key_at_least_32_characters_long_1234
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_ENABLED=true
URLHAUS_API_KEY=
LLM_API_KEY=
EOF
```

---

## 4. Local Development Startup (Native Node & Python)

### Step 1: Install Dependencies & Build Shared Package

```bash
# From repository root:
npm install

# Build shared types package (MANDATORY before starting API or Web)
npm run build:shared
```

### Step 2: Setup Python Virtual Environment

```bash
cd services/scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ../..
```

### Step 3: Start MongoDB

```bash
# Using Docker:
docker run -d --name sentrix-mongo -p 27017:27017 -v sentrix_data:/data/db mongo:7.0

# Or using Podman:
podman run -d --name sentrix-mongo -p 27017:27017 -v sentrix_data:/data/db docker.io/library/mongo:7.0
```

### Step 4: Apply Database Indexes & Seed Admin Account

```bash
# Check index migration plan:
npm run migrate:indexes:dry-run

# Apply compound and unique indexes:
npm run migrate:indexes

# (Optional) Provision an administrator account interactively:
npm run create:admin
```

### Step 5: Start the Platform Services

Open three terminal windows (or run in background):

```bash
# Terminal 1: Python Scanner Engine
npm run dev:scanner     # Listening on http://localhost:8001

# Terminal 2: Fastify API Gateway & Background Worker
npm run dev:api         # Listening on http://localhost:8000

# Terminal 3: Next.js Frontend
npm run dev:web         # Listening on http://localhost:3000
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 5. Containerized Deployment (Docker Compose / Podman)

SENTRIX provides a fully configured `docker-compose.yml` orchestrating all containers, volume mounts, and network boundaries:

```bash
# Build and run entire stack in background:
docker compose up --build -d

# Check running services:
docker compose ps

# Follow unified logs:
docker compose logs -f
```

### Podman Compose Support

SENTRIX is verified compatible with rootless Podman:

```bash
podman-compose up --build -d
```

---

## 6. Health Checks & Verification

Verify each component is operating correctly:

```bash
# 1. Scanner Engine Health
curl -s http://localhost:8001/health | jq .
# Expected output:
# {
#   "status": "healthy",
#   "service": "sentrix-scanner",
#   "analyzers": ["UrlAnalyzer", "DomainAnalyzer", "TlsAnalyzer", "WebSecurityAnalyzer", "ReputationAnalyzer"]
# }

# 2. Fastify API Gateway Health
curl -s http://localhost:8000/api/v1/health | jq .
# Expected output:
# {
#   "status": "healthy",
#   "service": "sentrix-api",
#   "database": "connected"
# }

# 3. Next.js Web UI
curl -I http://localhost:3000
# Expected: HTTP 200 OK
```

---

## 7. Running Test Suites

Run API gateway integration tests:
```bash
npm test
# Runs 69 integration and unit tests covering background scanning, fencing, auth, and SSRF.
```

Run Python scanner unit and security tests:
```bash
cd services/scanner
.venv/bin/pytest
# Runs 152 scanner tests covering URL, domain, TLS, DOM heuristics, Tranco, and Web3 phishing.
```

Run Full Monorepo Typecheck and Production Build:
```bash
npm run build
# Builds @sentrix/shared -> @sentrix/api -> @sentrix/web (Next.js 14 production bundle).
```

---

## 8. Operational Invariants & Security Guardrails

1. **Sole Database Ownership:** Only `apps/api` communicates with MongoDB. The Python threat scanner remains strictly stateless and credentials-free.
2. **Lease-Fenced Background Workers:** Scan jobs are claimed atomically using MongoDB atomic updates (`findAndModify`) with monotonically increasing attempt tokens (`leaseToken`). Crashed workers or expired leases are automatically reaped after 60 seconds without data contamination.
3. **Fail-Safe Security Rule:** If an analyzer encounters an internal error or network failure, the verdict degrades to `INCONCLUSIVE` or `SUSPICIOUS`, never defaulting to `BENIGN`.
4. **Credential Isolation:** The `SCANNER_API_SECRET` and API keys are never printed in client error responses or logged to console output.
