# SENTRIX Persistent Engineering Memory

This document serves as the persistent engineering memory for all developers, architects, and AI coding agents working on the SENTRIX platform.

---

## 1. Current Project State

- **Current Development Phase:** Phase 4 / Asynchronous Background Scanning Architecture Complete.
- **Implemented Modules:**
  - `apps/web`: Next.js 14 App Router UI (Landing, Scanner, Forensic Reports, Dashboard, Threat Intel, Community Feed, Scan History) updated with reactive polling in-flight state machine (`QUEUED` amber clock, `PROCESSING` cyan radar spinner), live security analyzer pipeline visualizer, automatic transition upon completion, and resilient error state for `FAILED` scans.
  - `apps/api`: Fastify 5 REST API gateway, Mongoose database models, rate-limiting, error handling, internal scanner client, input sanitization (`escapeRegex`, `sanitizePagination`), restricted `trustProxy`, sanitized 500 error handlers, server-derived voter identity (`sha256(voter:${request.ip})`), dedicated route-level rate limiting on voting, and **native MongoDB-backed asynchronous background scanning queue (`ScanWorkerService`)** with atomic job claiming (`findOneAndUpdate`), bounded concurrency (`MAX_CONCURRENT_JOBS = 3`), permanent SSRF error isolation, transient retry policy (`MAX_RETRIES = 3`), abandoned job recovery reaper, duplicate active scan detection, and status polling endpoint (`GET /api/v1/scans/:id/results`).
  - `services/scanner`: FastAPI threat engine with SSRF perimeter guard, socket-level connection-time IP pinning (`PinnedIPNetworkBackend`), controlled manual redirect validation, bounded 1 MB streaming responses, constant-time authentication (`secrets.compare_digest`), non-root container user (`appuser`), zero-trust `INCONCLUSIVE` risk scoring engine with strict success-based completeness (`v != "SUCCESS"`), and threat intelligence failure propagation (`ThreatProviderResult`).
  - `packages/shared`: Centralized TypeScript contracts, Zod schemas, domain types (`ScanStatusEnum.QUEUED`, `PROCESSING`, `COMPLETED`, `FAILED`, `VerdictEnum.INCONCLUSIVE`, `AnalysisStatusEnum`, `TIMEOUT` analyzer status), and URL utilities.
- **Partially Implemented Modules:**
  - External threat intelligence connectors: URLhaus integrated; Google Safe Browsing and LLM explanation connectors structured with graceful fallback when API keys are not supplied. Outages, timeouts, and 429/5xx status codes are strictly propagated as `FAILED`/`ERROR` rather than false clean matches.
- **Pending Modules:**
  - User authentication and role-based access control (RBAC) token issuance.
- **Known Blockers:**
  - None. All foundation services, local MongoDB models, health checks, 18 Fastify API integration tests, and 48 scanner pytest tests are operational and passing. Monorepo builds cleanly.

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
  - `CertificateSchema`: Compound unique sparse index on `{ scanId: 1, leaseToken: 1 }`, index on `scanId` and `fingerprint`.
  - `FindingSchema`: Compound index on `{ scanId: 1, leaseToken: 1 }`, `{ scanId: 1, severity: 1 }`, index on `category`.
  - `ThreatVoteSchema`: Unique compound index on `{ reportId: 1, userId: 1 }`.
  - `ThreatReportSchema`: Index on `urlHash` and `createdAt: -1`.
  - `ScanSchema`: Index on `{ normalizedDomain: 1, createdAt: -1 }`, `{ status: 1, createdAt: 1 }`, `{ status: 1, claimedAt: 1 }`, partial unique index on `{ urlHash: 1 }` (where `status IN ['QUEUED', 'PROCESSING']`), index on `publishedLeaseToken`.

---

## 7. Current Development Progress

- **Last Completed Task:** Asynchronous Background Scanning Reliability Remediation & Attempt-Scoped Result Persistence:
  - `SENTRIX-REL-01`: Cryptographically secure lease token (`leaseToken = crypto.randomUUID()`) and fenced state transitions (`{ _id, leaseToken, status: 'PROCESSING' }`) preventing zombie workers from corrupting active executions.
  - `SENTRIX-REL-02`: Conditional atomic abandoned-job reaper (`findOneAndUpdate` matching `status: 'PROCESSING'`, `leaseToken`, and `claimedAt`), eliminating race conditions where completed scans were reverted back to `QUEUED`.
  - `SENTRIX-REL-03`: Database-enforced duplicate submission prevention via partial unique index `{ urlHash: 1 }` on `status IN ['QUEUED', 'PROCESSING']` with MongoDB E11000 duplicate key handling.
  - `SENTRIX-REL-04`: Graceful shutdown signal handling (`SIGTERM` and `SIGINT`) in Fastify, ensuring container stops drain active worker jobs within a bounded 5s window before process exit.
  - `SENTRIX-REL-05`: Database outage resilience in `handleJobError` with `try/catch` wrapping, preventing unhandled promise rejections on database disconnection.
  - `SENTRIX-REL-06`: Dual-phase frontend polling: switched in-flight polling from heavy 3-collection report route to lightweight `GET /api/v1/scans/:id/results` with transient network failure tolerance (3 retries).
  - **Attempt-Scoped Result Persistence & Zombie Worker Safety:**
    - Eliminated critical cleanup race where stale workers previously deleted findings/certificates by `scanId` alone.
    - All persisted findings and certificates are tagged with `leaseToken: scan.leaseToken`.
    - Pre-write attempt cleanup and failure rollback are strictly scoped to `{ scanId: scan._id, leaseToken: scan.leaseToken }`.
    - Atomic result publication commits `publishedLeaseToken: scan.leaseToken` under `{ _id: scan._id, leaseToken: scan.leaseToken, status: 'PROCESSING' }`.
    - Reader endpoints (`/api/v1/scans/:id/results` and `/api/v1/reports/:id`) filter strictly by `leaseToken: scan.publishedLeaseToken` on attempt-scoped scans with a safe fallback to untagged records (`$exists: false`) for legacy pre-migration scans.
    - Post-publication superseded artifact pruning is insulated with `try/catch` so cleanup database errors never fail a completed scan or produce unhandled rejections.
  - **Phase 4.1 Operational Hardening (Orphan Cleanup & Controlled Index Migrations):**
    - **Reliable Orphan-Artifact Recovery (`OrphanCleanupService`):**
      - Bounded background sweep (every 5 minutes) evaluating attempt-scoped artifacts `(scanId, leaseToken)` older than `retentionMs` (default 10 minutes, exceeding 60s worker leases).
      - Strict preservation: published results (`scan.status === COMPLETED && scan.publishedLeaseToken === leaseToken`), active worker attempts (`scan.status === PROCESSING && scan.leaseToken === leaseToken`), and untagged legacy data (`leaseToken: null` or missing) are never deleted.
      - Purges abandoned attempts (`FAILED` or re-queued scans), superseded attempts (`COMPLETED` scans with older lease tokens), and dangling artifacts pointing to missing scans.
      - Execution concurrency guard (`isRunning`), bounded batching (`DEFAULT_CLEANUP_BATCH_SIZE = 50`), and database outage resilience.
      - Tested with 10 comprehensive integration scenarios in `apps/api/src/test/orphanCleanup.test.ts`.
    - **Controlled MongoDB Index Migrations (`IndexMigrationManager`):**
      - Removed startup `syncIndexes()` from `apps/api/src/plugins/db.ts` and explicitly set `autoIndex: false` in connection options to prevent production startup table locks.
      - Implemented explicit migration manager (`IndexMigrationManager` in `apps/api/src/migrations/indexMigration.ts`) with dry-run inspection mode (`npm run migrate:indexes:dry-run`) and apply execution (`npm run migrate:indexes`).
      - Distributed atomic lock management in `_schema_migrations` with 5-minute timeout window.
      - Pre-flight data deduplication for unique indexes (e.g. `urlHash_1_partial_active`).
      - Safe obsolete index pruning (e.g. dropping `certificates.scanId_1` unique) while strictly preserving immutable `_id_`.
      - Tested with 8 integration scenarios in `apps/api/src/test/indexMigration.test.ts`.
    - **Full Platform Verification:** 56 API tests passing across 5 suites (18 unit/reliability scenarios + 12 security tests + 8 real MongoDB concurrency tests + 10 orphan cleanup tests + 8 index migration tests), 48 scanner pytest tests passing (104 automated tests total), clean monorepo production build (`tsc` + Next.js), valid Docker Compose configuration.
- **Current Task:** Phase 4.1 Operational Hardening complete; awaiting user instructions.
- **Next Priority:** User authentication and role-based access control (RBAC) token issuance.
- **Pending Integration Work:** Optional external API keys for Google Safe Browsing and URLhaus automated webhook ingestion.
- **Known Bugs:** None currently identified.

---

## 8. Known Issues and Technical Debt

- **Anonymous Voting Identity:** Anonymous voting binds 1 vote per report per source IP address via salted SHA-256 hash. Clients behind large CGNAT or shared institutional networks share voting identity per report. *Mitigation:* Transition to signed JWT user authentication once auth module is implemented.
- **Horizontal Multi-Node Worker Scale:** The atomic MongoDB queue with cryptographic lease tokens (`crypto.randomUUID()`) safely coordinates multiple concurrent workers across independent nodes using atomic `findOneAndUpdate`. Under extreme enterprise throughput (>1,000 scans/sec), a dedicated external broker (e.g. RabbitMQ or Redis Streams) could be evaluated, but MongoDB 7.0 compound indexed queue easily handles standard platform load.

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
| **2026-11-07** | `ba0d7ef` | Security Hardening v1 | Implemented PinnedIPNetworkBackend, controlled manual redirects, 1MB streaming limits, strict TLS invariant, zero-trust INCONCLUSIVE verdicts, Fastify query/pagination sanitization, error redaction, 29 pytest tests, 4 API tests. |
| **2026-11-07** | `285bcd5` | Security Remediation v1.1 | Fixed SENTRIX-SEC-01 (Docker env isolation), SENTRIX-SEC-02 (threat feed failure propagation), SENTRIX-SEC-03 (analyzer completeness evaluation), and SENTRIX-SEC-04 (community voting abuse hardening with IP voter hash & route rate limit). 47 pytest tests, 7 API tests. |
| **2026-11-07** | `86ca62f` | Asynchronous Background Scanning Architecture | Implemented native MongoDB atomic background scan worker (`ScanWorkerService`), immediate QUEUED 201 response, duplicate active scan detection, retry & permanent error handling, abandoned job reaper, GET `/scans/:id/results` endpoint, and reactive frontend polling UI with live analyzer pipeline. 18 API tests, 48 scanner pytest tests. |
| **2026-11-07** | `Pending` | Operational Hardening & Controlled Migrations (Phase 4.1) | Implemented OrphanCleanupService, attempt-scoped artifact lifecycle recovery, IndexMigrationManager with distributed locking in _schema_migrations, dry-run CLI, removed startup syncIndexes, autoIndex: false, 56 API tests, 48 scanner pytest tests. |
