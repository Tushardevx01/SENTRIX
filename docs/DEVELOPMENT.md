# SENTRIX Development Guide

This guide explains how to set up, build, test, and run the complete SENTRIX cybersecurity platform locally.

---

## 1. Prerequisites

- **Node.js:** v20.x, v22.x, or v26.x
- **npm:** v10.x or v11.x
- **Python:** 3.11, 3.12, or 3.15
- **Docker / Podman:** Required for running containerized MongoDB and multi-service deployment.

---

## 2. Monorepo Structure

```
sentrix/
├── apps/
│   ├── web/        # Next.js 14 App Router, Tailwind, Recharts
│   └── api/        # Fastify 5, TypeScript, Mongoose ODM
├── services/
│   └── scanner/    # FastAPI, Python 3.15, Pydantic, Heuristics
├── packages/
│   └── shared/     # Shared TypeScript models, Zod schemas, utilities
├── docs/           # System, API, threat model, and database docs
├── docker-compose.yml
└── README.md
```

---

## 3. Environment Configuration

SENTRIX strictly uses actual `.env` files for each component. **Do not create `.env.example` or commit any `.env` file to git.**

### 3.1 Frontend (`apps/web/.env`)
```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
```

### 3.2 Backend (`apps/api/.env`)
```bash
PORT=8000
NODE_ENV=development
MONGODB_URI=mongodb://localhost:27017/sentrix
SCANNER_INTERNAL_URL=http://localhost:8001
SCANNER_API_SECRET=your_generated_64_char_hex_secret
CORS_ORIGIN=http://localhost:3000
```

### 3.3 Python Scanner (`services/scanner/.env`)
```bash
PORT=8001
SCANNER_API_SECRET=your_generated_64_char_hex_secret
GOOGLE_SAFE_BROWSING_API_KEY=
URLHAUS_ENABLED=true
LLM_API_KEY=
```

> **Security Note:** The `SCANNER_API_SECRET` in `apps/api/.env` and `services/scanner/.env` must match exactly. Generate one via:
> ```bash
> python3 -c "import secrets; print(secrets.token_hex(32))"
> ```

---

## 4. Local Installation & Development

### 4.1 Install Node & Workspace Dependencies
From the repository root:
```bash
npm install
npm --workspace=@sentrix/shared run build
```

### 4.2 Set Up Python Scanner Environment
```bash
cd services/scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4.3 Start Local MongoDB
Start a local MongoDB instance via Docker or Podman:
```bash
podman run -d --name sentrix-mongo -p 27017:27017 docker.io/library/mongo:7.0
# Or using docker:
# docker run -d --name sentrix-mongo -p 27017:27017 mongo:7.0
```

### 4.4 Start Services in Development Mode

**Terminal 1 — Python Threat Scanner:**
```bash
cd services/scanner
.venv/bin/uvicorn app.main:app --reload --port 8001
```

**Terminal 2 — Fastify API Gateway:**
```bash
npm --workspace=@sentrix/api run dev
# or:
# cd apps/api && npm run dev
```

**Terminal 3 — Next.js Frontend:**
```bash
npm --workspace=@sentrix/web run dev
# or:
# cd apps/web && npm run dev
```

Visit `http://localhost:3000` in your browser.

---

## 5. Running Automated Tests

### Python Scanner Tests (SSRF Guard, Analyzers, API Auth)
```bash
cd services/scanner
.venv/bin/pytest
```

### TypeScript Builds
```bash
npm --workspace=@sentrix/shared run build
npm --workspace=@sentrix/api run build
npm --workspace=@sentrix/web run build
# Or build all with one command:
npm run build
```

---

## 6. Running with Docker Compose

To run the complete platform including MongoDB, Scanner, API, and Web UI in isolated containers:
```bash
docker compose up --build
# or using podman:
podman compose up --build
```

Access points:
- **Web UI:** `http://localhost:3000`
- **Fastify API:** `http://localhost:8000`
- **Fastify Health:** `http://localhost:8000/health`
- **Scanner Service:** Internal only (port 8001 is not bound to host interface for security).
