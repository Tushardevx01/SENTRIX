# SENTRIX Persistent Engineering Memory

This document serves as the persistent engineering memory for all developers, architects, and AI coding agents working on the SENTRIX platform.

---

## 1. Current Project State

- **Current Development Phase:** Phase 2 / Foundation Complete & Architectural Baseline Established.
- **Implemented Modules:**
  - `apps/web`: Next.js 14 App Router UI (Landing, Scanner, Forensic Reports, Dashboard, Threat Intel, Community Feed, Scan History).
  - `apps/api`: Fastify 5 REST API gateway, Mongoose database models, rate-limiting, error handling, internal scanner client, and telemetry aggregation.
  - `services/scanner`: FastAPI threat engine with SSRF perimeter guard, multi-vector heuristic analyzers (URL, Domain, TLS, Web Security, Reputation), and 0–100 risk scoring engine.
  - `packages/shared`: Centralized TypeScript contracts, Zod schemas, domain types, and URL utilities.
- **Partially Implemented Modules:**
  - External threat intelligence connectors: URLhaus integrated; Google Safe Browsing and LLM explanation connectors structured with graceful fallback when API keys are not supplied.
- **Pending Modules:**
  - Background asynchronous task queue (BullMQ/Redis) for decoupled asynchronous deep scans.
  - User authentication and role-based access control (RBAC) token issuance.
- **Known Blockers:**
  - None. All foundation services, local MongoDB, health checks, and test suites are operational.

---

## 2. Technology Decisions

| Component | Technology | Version | Architectural Justification |
| :--- | :--- | :--- | :--- |
| **Monorepo Manager** | `npm` Workspaces | 11.x / standard | Standardized package manager across the monorepo; eliminates multi-tool friction and ensures deterministic workspace linking. |
| **Frontend Framework** | Next.js (App Router) | 14.2.15 | Server-side rendering, streaming forensic reports, static optimization, and standard React 18 compatibility with charting libraries. |
| **Frontend Styling** | Tailwind CSS + Lucide Icons | 3.4.x / 0.453.x | Consistent dark cybersecurity aesthetic (`#0B0F19`, `#00E5FF`), responsive grid layouts, and zero-runtime CSS overhead. |
| **Visualization** | Recharts | 2.15.x | High-performance SVG charting for threat severity distributions and dashboard telemetry. |
| **Backend API Gateway** | Fastify | 5.12.x | Low-overhead Node.js HTTP framework with high throughput, native JSON schema support, and built-in rate-limiting. |
| **Object Data Modeling** | Mongoose ODM | 8.24.x | Schema enforcement, validation hooks, population, and indexing for MongoDB 7.0 document store. |
| **Analysis Engine** | FastAPI + Python | 3.15.x / 0.162.x | Native cryptographic inspection (`cryptography`), TLS socket support, DOM parsing (`BeautifulSoup4`), and public suffix extraction (`tldextract`). |
| **Database** | MongoDB | 7.0 | Document-oriented storage optimal for polymorphic security findings and arbitrary forensic evidence trees. |
| **Validation** | Zod + Pydantic v2 | 3.25.x / 2.14.x | End-to-end type safety spanning TypeScript clients and Python services. |

---

## 3. Architecture Decisions

1. **Strict Single Root `.env` Policy:**
   - There is exactly one `.env` at repository root.
   - Eliminates configuration drift, secret duplication, and deployment mismatch.
   - Excluded in `.gitignore` via `.env` and `.env.*`.
2. **MongoDB Access Exclusivity:**
   - MongoDB is accessed exclusively through Fastify.
   - The Python threat scanner has zero direct database credentials or network access to MongoDB, preventing database compromise if the scanner sandbox is breached.
3. **Internal Authenticated Service Communication:**
   - Fastify communicates with Python via internal HTTP using the `X-Scanner-Secret` header.
   - The scanner's port (`8001`) is never mapped to host interfaces in production Docker environments.
4. **Perimeter-First SSRF Defense:**
   - Pre-flight DNS resolution and IP address validation occurs before any network probe.
   - Loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets, and cloud instance metadata (`169.254.169.254`, `metadata.google.internal`) are blocked immediately.
5. **Fail-Safe Risk Scoring:**
   - Missing or unreachable analyzer results are never treated as evidence of safety.
   - Failed probes reduce confidence ratings and generate warning findings rather than lowering threat scores.

---

## 4. Project Structure

```text
sentrix/
├── apps/
│   ├── web/
│   │   ├── Dockerfile
│   │   ├── next-env.d.ts
│   │   ├── next.config.js
│   │   ├── package.json
│   │   ├── postcss.config.js
│   │   ├── tailwind.config.js
│   │   ├── tsconfig.json
│   │   └── src/
│   │       ├── app/
│   │       │   ├── community/page.tsx
│   │       │   ├── dashboard/page.tsx
│   │       │   ├── globals.css
│   │       │   ├── history/page.tsx
│   │       │   ├── intelligence/page.tsx
│   │       │   ├── layout.tsx
│   │       │   ├── page.tsx
│   │       │   ├── reports/[id]/page.tsx
│   │       │   └── scanner/page.tsx
│   │       ├── components/
│   │       │   ├── layout/Header.tsx
│   │       │   ├── layout/Sidebar.tsx
│   │       │   ├── ui/CertificateCard.tsx
│   │       │   ├── ui/ErrorState.tsx
│   │       │   ├── ui/FindingCard.tsx
│   │       │   ├── ui/LoadingState.tsx
│   │       │   ├── ui/RiskBadge.tsx
│   │       │   └── ui/RiskScoreGauge.tsx
│   │       └── lib/
│   │           ├── api.ts
│   │           └── utils.ts
│   │
│   └── api/
│       ├── Dockerfile
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── config/index.ts
│           ├── database/index.ts
│           ├── models/
│           │   ├── Certificate.ts
│           │   ├── Finding.ts
│           │   ├── index.ts
│           │   ├── Scan.ts
│           │   ├── ThreatReport.ts
│           │   ├── ThreatVote.ts
│           │   └── User.ts
│           ├── modules/
│           │   ├── community/index.ts
│           │   ├── dashboard/index.ts
│           │   ├── reports/index.ts
│           │   ├── scans/index.ts
│           │   └── threats/index.ts
│           ├── plugins/db.ts
│           ├── services/scannerClient.ts
│           ├── utils/config.ts
│           └── server.ts
│
├── services/
│   └── scanner/
│       ├── Dockerfile
│       ├── pytest.ini
│       ├── requirements.txt
│       ├── tests/
│       │   ├── test_analyzers.py
│       │   ├── test_api.py
│       │   └── test_safety.py
│       └── app/
│           ├── analyzers/
│           │   ├── domain_analyzer.py
│           │   ├── reputation_analyzer.py
│           │   ├── tls_analyzer.py
│           │   ├── url_analyzer.py
│           │   └── web_security_analyzer.py
│           ├── config/
│           │   ├── __init__.py
│           │   └── settings.py
│           ├── intelligence/connectors.py
│           ├── safety/ssrf_guard.py
│           ├── schemas/
│           │   ├── request.py
│           │   └── response.py
│           ├── scoring/risk_engine.py
│           └── main.py
│
├── packages/
│   └── shared/
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── contracts/index.ts
│           ├── types/index.ts
│           ├── utils/index.ts
│           └── index.ts
│
├── docs/
│   ├── API.md
│   ├── DATABASE.md
│   └── THREAT-MODEL.md
│
├── ARCHITECTURE.md
├── MEMORY.md
├── README.md
├── .env                  (Excluded from Git)
├── .gitignore
├── docker-compose.yml
├── package.json
└── package-lock.json
```

---

## 5. Implemented Features

| Feature | Owning Module | Details | Relevant Files | Test Status |
| :--- | :--- | :--- | :--- | :--- |
| **SSRF Perimeter Defense** | `scanner:safety` | Resolves target DNS and rejects loopback, RFC 1918 subnets, and cloud metadata. | `services/scanner/app/safety/ssrf_guard.py` | Verified (5 Pytest unit tests passing) |
| **Lexical URL Analysis** | `scanner:analyzers` | Flags raw IPs, embedded authority credentials, punycode/IDN, excessive subdomains, length, keywords. | `services/scanner/app/analyzers/url_analyzer.py` | Verified (Pytest + Live Scan) |
| **Brand Impersonation Detection** | `scanner:analyzers` | Evaluates domain and subdomain tokens against targeted brand registries and abusive TLDs. | `services/scanner/app/analyzers/domain_analyzer.py` | Verified (Tested on PayPal impersonation) |
| **TLS/SSL Handshake Audit** | `scanner:analyzers` | Direct SSL connection, extracts X.509 cert, issuer, expiration, SHA-256 fingerprint, hostname matching. | `services/scanner/app/analyzers/tls_analyzer.py` | Verified (Live check on Cloudflare cert) |
| **Web Security & DOM Analysis** | `scanner:analyzers` | Audits HSTS, CSP, X-Frame-Options, nosniff, and checks for external credential submission forms. | `services/scanner/app/analyzers/web_security_analyzer.py` | Verified (DOM checks functional) |
| **Explainable Risk Scoring** | `scanner:scoring` | Computes 0–100 score, confidence, verdicts (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`), and MITRE ATT&CK tactics. | `services/scanner/app/scoring/risk_engine.py` | Verified (Pytest passing) |
| **Scan Persistence & Orchestration** | `api:scans` | Creates scan document, calls scanner with auth secret, persists findings and certs, updates scan. | `apps/api/src/modules/scans/index.ts` | Verified (HTTP 201 Created) |
| **Forensic Report Retrieval** | `api:reports` | Returns aggregated scan, findings, certificate, and summary. | `apps/api/src/modules/reports/index.ts` | Verified (HTTP 200 OK) |
| **Community Threat Feed & Voting** | `api:community` | Crowdsourced threat submission with SHA-256 hash de-duplication and upvote/downvote tracking. | `apps/api/src/modules/community/index.ts` | Verified (Upvote/Downvote validated) |
| **Telemetry Dashboard Stats** | `api:dashboard` | Computes live scan counts, verdict distributions, and average risk indices directly from MongoDB. | `apps/api/src/modules/dashboard/index.ts` | Verified (Live queries functional) |
| **Frontend Visualizer** | `web:app` | Cybersecurity SaaS UI with radial Risk Score Gauge, evidence inspector, and filterable tables. | `apps/web/src/app/` | Verified (9/9 routes compiled, HTTP 200) |

---

## 6. API and Database Changes

- **API Routes:**
  - `POST /api/v1/scans`: Initiates and executes threat analysis.
  - `GET /api/v1/scans`: Paginated scan history with domain regex filtering.
  - `GET /api/v1/scans/:id`: Individual scan state.
  - `GET /api/v1/reports/:id`: Full security report view with findings and TLS data.
  - `GET /api/v1/threats`: Global feed of suspicious and malicious domains.
  - `POST /api/v1/community/reports`: Community threat submission with SHA-256 deduplication.
  - `GET /api/v1/community/reports`: Community list with aggregated upvotes/downvotes.
  - `POST /api/v1/community/reports/:id/vote`: User voting on community reports.
  - `GET /api/v1/dashboard/stats`: Telemetry KPIs and recent scans.
- **Database Schema Constraints:**
  - `CertificateSchema`: Unique index on `scanId`.
  - `ThreatVoteSchema`: Unique compound index on `{ reportId: 1, userId: 1 }`.
  - `ThreatReportSchema`: Index on `urlHash` and `createdAt: -1`.
  - `ScanSchema`: Index on `{ normalizedDomain: 1, createdAt: -1 }` and `status: 1`.

---

## 7. Current Development Progress

- **Last Completed Task:** Established root-level `ARCHITECTURE.md` and `MEMORY.md`, enforced single root `.env` policy, reorganized `packages/shared/src/` into `types`, `contracts`, `utils`, and unified monorepo on `npm` workspaces.
- **Current Task:** Verification of documentation synchronization and codebase baseline.
- **Next Priority:** Implement asynchronous scan queue worker (e.g., BullMQ) for long-running deep scans and optional LLM forensic explanation connectors.
- **Pending Integration Work:** Optional external API keys for Google Safe Browsing and URLhaus automated webhook ingestion.
- **Known Bugs:** None currently identified.

---

## 8. Known Issues and Technical Debt

- **Synchronous Scan Execution:** Scans currently execute synchronously over internal HTTP. For deep scans involving multiple network hops, request latency can exceed 3 seconds. *Mitigation:* Interfaces in `@sentrix/shared` and Fastify are designed to transition to asynchronous polling/WebSockets without breaking frontend contracts.
- **Ephemeral Session Identifier:** Anonymous voting in community feeds uses browser localStorage session IDs (`sentrix_session_id`). *Mitigation:* Transition to signed JWT user authentication once auth module is implemented.

---

## 9. Important Engineering Rules

1. **Mandatory Documentation Update Protocol:**
   - Before every Git commit, inspect all modified and new files.
   - Update `MEMORY.md` with implementation status, features, and recent changes.
   - Update `ARCHITECTURE.md` if interfaces, system design, or data flow changes.
   - Include documentation updates in the same Git commit.
2. **Strict Single `.env` Rule:**
   - Exactly one `.env` file at the repository root. Never create service-level or example `.env` files.
3. **Database Isolation:**
   - Only `apps/api` communicates with MongoDB. The Python scanner remains completely stateless.
4. **Zero Fake Metrics:**
   - Dashboard telemetry must query genuine database records. Never populate production dashboards with fabricated mock metrics.
5. **Fail-Safe Security:**
   - Incomplete analyzer data must never produce a benign verdict. Always flag warnings and reduce confidence.

---

## 10. Chronological Change Log

| Date | Commit | Summary | Key Changes |
| :--- | :--- | :--- | :--- |
| **2026-11-07** | `60bfe51` | Platform Initialization | Complete modular cybersecurity platform initial commit with Next.js, Fastify, FastAPI, and MongoDB. |
| **2026-11-07** | `cc12d88` | Standardized on npm Workspaces | Migrated workspace configuration to standard `npm` workspaces, generated `package-lock.json`, updated Dockerfiles. |
| **2026-11-07** | `bd58628` | Architecture & Persistent Memory | Created root `ARCHITECTURE.md` and `MEMORY.md`, enforced single root `.env` loading across all services, organized `packages/shared` into `contracts`, `types`, and `utils`. |
