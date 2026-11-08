# SENTRIX Persistent Engineering Memory

This document serves as the persistent engineering memory for all developers, architects, and AI coding agents working on the SENTRIX platform.

---

## 1. Current Project State

- **Current Development Phase:** Phase 6.3 (Evidence-Based Detection Calibration) Complete in Working Tree.
- **Repository Branch:** `main` (Commit `1267507`, merging PR #1 / `origin/Sayandeep`).
- **Implemented Modules:**
  - `apps/web`: Next.js 14 App Router UI (Landing, Scanner, Forensic Reports, Dashboard, Threat Intel, Community Feed, Scan History) featuring reactive in-flight polling state machine, live security analyzer pipeline visualizer, automatic transition upon completion, typed API client (`apps/web/src/lib/api.ts` & `utils.ts`) with auth token management, resilient error state for `FAILED` scans, and dark cybersecurity styling.
  - `apps/api`: Fastify 5 REST API gateway, Mongoose database models, route-level rate-limiting, error handling, internal scanner client, input sanitization (`escapeRegex`, `sanitizePagination`), restricted `trustProxy`, sanitized 500 error handlers, **Hardened User Authentication & RBAC token issuance (`POST /register`, `POST /login`, `GET /me`, `PATCH /users/:id/role`, `authenticate`, `requireRole`) using versioned asynchronous `crypto.scrypt` password hashing with bounded concurrency (`ScryptConcurrencyLimiter`), timing-attack neutral login, JWT algorithm validation, roleVersion instantaneous token revocation, privilege-escalation-immune public registration (`role: 'user'`), operator admin CLI (`createAdmin.ts`) with interactive masked entry, and concurrency-safe distributed atomic lock for last-admin preservation**, authenticated community voting binding votes to verified user identities, native MongoDB-backed asynchronous background scanning queue (`ScanWorkerService`), attempt-scoped artifact persistence, orphan recovery service (`OrphanCleanupService`), controlled index migrations (`IndexMigrationManager` with `--dry-run` and distributed locking in `_schema_migrations`), and cross-platform test runner (`scripts/test.js`).
  - `services/scanner`: FastAPI threat engine with SSRF perimeter guard, socket-level connection-time IP pinning (`PinnedIPNetworkBackend`), controlled manual redirect validation, bounded 1 MB streaming responses, constant-time authentication (`secrets.compare_digest`), non-root container user (`appuser`), zero-trust `INCONCLUSIVE` risk scoring engine, **Deep Cryptographic X.509 Trust Engine (`cryptography.x509`) inspecting eMudhra/distrusted CAs, sub-2048 bit RSA keys, broken SHA-1/MD5 signature hashes, CA/Browser Forum Ballot SC-081v3 dynamic validity schedules (398d, 200d, 100d, 47d) scoped to public end-entity certificates, nuanced Certificate Transparency (CT) reporting, CA spoofing detection, and CA: TRUE leaf constraints**, enterprise banking & fintech brand impersonation detection (20+ global/national institutions), government service impersonation detection (`incometax`, `irs`, `passport`, `aadhaar`, `uidai`, `mygov`, `socialsecurity`), academic impersonation detection, deceptive recruitment scam detection, typosquatting & leetspeak homoglyph detection (`0->o`, `1->l`, `rn->m`, `vv->w`), payment/CVV harvester detection, third-party webhook exfiltration auditing (Telegram, Discord, Formspree), **Phase 6 Evaluation & Benchmarking Suite (offline test harness, 80-case dev dataset, 25-case val dataset, 3x3 multi-class confusion matrix, binary threat metrics, latency profiling), and Phase 6.3 Detection Calibration (15-pt posture ceiling, PSL-aware authentic domain context, token-based brand matching, multi-candidate leetspeak engine, financial credential escalation, and finding deduplication)**.
  - `packages/shared`: Centralized TypeScript contracts, Zod schemas, domain types (`IUser`, `UserRole`, `AuthResponse`, enriched `ICertificate` with cryptographic parameters, `UserRegisterSchema` with stripped roles, `UserRoleUpdateSchema`, `UserLoginSchema`), and URL utilities.
- **Partially Implemented Modules:**
  - External threat intelligence connectors: URLhaus integrated; Google Safe Browsing and LLM explanation connectors structured with graceful fallback when API keys are not supplied. Outages, timeouts, and 429/5xx status codes are strictly propagated as `FAILED`/`ERROR` rather than false clean matches.
- **Pending Modules:**
  - None. Core backend, user authentication, cryptographic trust engine, phishing & brand impersonation detection, background worker, orphan cleanup, controlled index migrations, and attempt-scoped persistence are operational.
- **Known Blockers:**
  - None. Monorepo builds cleanly (`build:shared`, `build:api`, Next.js 14 static generation). All test suites pass.

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
| **Database** | MongoDB | 7.0 | Document-oriented storage optimal for polymorphic security findings, atomic queues, and arbitrary forensic evidence trees. |
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
4. **Perimeter-First SSRF Defense & Socket IP Pinning:**
   - Pre-flight DNS resolution and IP address validation occurs before any network probe.
   - Loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets, and cloud instance metadata (`169.254.169.254`, `metadata.google.internal`) are blocked immediately.
   - Socket-level connection-time IP pinning (`PinnedIPNetworkBackend`) prevents Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
5. **Fail-Safe Zero-Trust Risk Scoring:**
   - Missing or unreachable analyzer results are never treated as evidence of safety.
   - Failed probes reduce confidence ratings and generate warning findings rather than lowering threat scores.
6. **Attempt-Scoped Result Persistence & Lease Fencing:**
   - Worker processes claim jobs atomically and receive a cryptographically secure `leaseToken`.
   - All findings and certificates are persisted tagged with `(scanId, leaseToken)`.
   - Pre-write cleanup, publication, and rollback are strictly attempt-scoped, guaranteeing stale workers can never delete or overwrite newer worker results.
7. **Controlled MongoDB Index Migrations:**
   - Startup index synchronization (`syncIndexes()` and `autoIndex`) is disabled (`autoIndex: false`) to eliminate production startup blocking table locks.
   - All 21 production indexes are managed explicitly via `IndexMigrationManager` with distributed locking in `_schema_migrations` and dry-run inspection mode (`npm run migrate:indexes:dry-run`).
8. **Production Authentication & Role-Based Access Control:**
   - Zero external auth provider dependency: uses Node.js standard `crypto.scrypt` with random 16-byte salt and constant-time comparison (`crypto.timingSafeEqual`).
   - HMAC-SHA256 signed JWT tokens with 7-day expiration.
   - Role enforcement (`user`, `analyst`, `admin`) via Fastify `requireRole` preHandler hooks.

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
│       ├── scripts/
│       │   └── test.js
│       └── src/
│           ├── config/
│           │   └── index.ts
│           ├── database/
│           │   └── index.ts
│           ├── migrations/
│           │   └── indexMigration.ts
│           ├── models/
│           │   ├── Certificate.ts
│           │   ├── Finding.ts
│           │   ├── index.ts
│           │   ├── Scan.ts
│           │   ├── ThreatReport.ts
│           │   ├── ThreatVote.ts
│           │   └── User.ts
│           ├── modules/
│           │   ├── auth/
│           │   │   ├── index.ts
│           │   │   └── middleware.ts
│           │   ├── community/
│           │   │   └── index.ts
│           │   ├── dashboard/
│           │   │   └── index.ts
│           │   ├── reports/
│           │   │   └── index.ts
│           │   ├── scans/
│           │   │   └── index.ts
│           │   └── threats/
│           │       └── index.ts
│           ├── plugins/
│           │   └── db.ts
│           ├── scripts/
│           │   └── migrateIndexes.ts
│           ├── services/
│           │   ├── orphanCleanup.ts
│           │   ├── scannerClient.ts
│           │   └── scanWorker.ts
│           ├── test/
│           │   ├── asyncScan.test.ts
│           │   ├── auth.test.ts
│           │   ├── indexMigration.test.ts
│           │   ├── orphanCleanup.test.ts
│           │   ├── realMongoConcurrency.test.ts
│           │   └── security.test.ts
│           ├── utils/
│           │   ├── auth.ts
│           │   └── config.ts
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
│       │   ├── test_http_response.py
│       │   ├── test_redirects.py
│       │   ├── test_reputation.py
│       │   ├── test_safety.py
│       │   ├── test_scoring.py
│       │   └── test_tls.py
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
│           ├── intelligence/
│           │   └── connectors.py
│           ├── safety/
│           │   └── ssrf_guard.py
│           ├── schemas/
│           │   ├── request.py
│           │   └── response.py
│           ├── scoring/
│           │   └── risk_engine.py
│           └── main.py
│
├── packages/
│   └── shared/
│       ├── package.json
│       ├── tsconfig.json
│       └── src/
│           ├── contracts/
│           │   └── index.ts
│           ├── types/
│           │   └── index.ts
│           ├── utils/
│           │   └── index.ts
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
| **SSRF Perimeter Defense & IP Pinning** | `scanner:safety` | Pre-flight DNS resolution, CIDR blocking (loopback, RFC 1918, cloud metadata), and socket-level IP pinning (`PinnedIPNetworkBackend`). | `services/scanner/app/safety/ssrf_guard.py` | Verified (Pytest unit + integration passing) |
| **Lexical URL Analysis** | `scanner:analyzers` | Flags raw IPs, embedded authority credentials, punycode/IDN, excessive subdomains, length, keywords. | `services/scanner/app/analyzers/url_analyzer.py` | Verified (Pytest + Live Scan) |
| **Brand & Sector Impersonation** | `scanner:analyzers` | Evaluates domain and subdomain tokens against banking/fintech, government, academic, and recruitment brand registries. | `services/scanner/app/analyzers/domain_analyzer.py` | Verified (Pytest passing on 20+ brand patterns) |
| **Deep Cryptographic X.509 Trust Engine** | `scanner:analyzers` | Cryptographic trust chain audit: eMudhra/distrusted CAs, sub-2048 bit RSA keys, broken SHA-1/MD5 hashes, CT SCTs, CA/B Forum 398d, and CA: TRUE leaf checks. | `services/scanner/app/analyzers/tls_analyzer.py` | Verified (Pytest passing with mock & real certs) |
| **Web Security & Credential Harvester Audit** | `scanner:analyzers` | Audits HSTS, CSP, X-Frame-Options, server header version disclosure, payment card/CVV form harvesting, and external webhook exfiltration. | `services/scanner/app/analyzers/web_security_analyzer.py` | Verified (Pytest passing) |
| **Explainable Zero-Trust Risk Scoring** | `scanner:scoring` | Computes 0–100 score, confidence, verdicts (`BENIGN`, `SUSPICIOUS`, `MALICIOUS`, `INCONCLUSIVE`), and MITRE ATT&CK tactics. | `services/scanner/app/scoring/risk_engine.py` | Verified (Pytest passing) |
| **Asynchronous Scan Worker & Fencing** | `api:services/scanWorker` | Native MongoDB atomic queue, cryptographic worker leases (`crypto.randomUUID()`), conditional atomic reaper, and graceful SIGTERM/SIGINT shutdown. | `apps/api/src/services/scanWorker.ts` | Verified (18 reliability & fencing tests passing) |
| **Attempt-Scoped Result Persistence** | `api:services/scanWorker` | Tags findings and certs with `(scanId, leaseToken)`, prevents stale worker race conditions, fenced atomic publication and rollback. | `apps/api/src/services/scanWorker.ts` | Verified (8 attempt-scoped regression tests passing) |
| **Orphan-Artifact Recovery & Cleanup** | `api:services/orphanCleanup` | Periodic background sweep (every 5 mins) purging abandoned/superseded attempt artifacts older than retention threshold while preserving active/published data. | `apps/api/src/services/orphanCleanup.ts` | Verified (10 orphan cleanup tests passing) |
| **Controlled MongoDB Index Migrations** | `api:migrations` | Explicit migration manager with distributed lock coordination in `_schema_migrations`, dry-run mode, pre-flight deduplication, and safe obsolete index pruning. | `apps/api/src/migrations/indexMigration.ts` | Verified (8 migration tests passing, CLI verified) |
| **User Authentication & RBAC** | `api:modules/auth` | Zero-dependency scrypt password hashing, signed HMAC-SHA256 JWTs, `authenticate` and `requireRole` guards, authenticated community voting. | `apps/api/src/modules/auth/` | Verified (Auth test suite passing) |
| **Forensic Report Retrieval** | `api:reports` | Returns aggregated scan, findings, certificate, and summary with attempt-scoped published lease token filtering. | `apps/api/src/modules/reports/index.ts` | Verified (HTTP 200 OK) |
| **Community Threat Feed & Voting** | `api:community` | Crowdsourced threat submission with SHA-256 hash deduplication, authenticated account voting, and fallback IP hash rate limiting. | `apps/api/src/modules/community/index.ts` | Verified (Upvote/Downvote validated) |
| **Telemetry Dashboard Stats** | `api:dashboard` | Computes live scan counts, verdict distributions, and average risk indices directly from MongoDB. | `apps/api/src/modules/dashboard/index.ts` | Verified (Live queries functional) |
| **Frontend Visualizer & Polling** | `web:app` | Cybersecurity SaaS UI with radial Risk Score Gauge, live analyzer pipeline visualizer, evidence inspector, and filterable tables. | `apps/web/src/app/` | Verified (9/9 routes compiled, Next.js static generation) |
| **Cross-Platform Test Runner** | `api:scripts` | Unified Node.js test execution script resolving cross-platform shell incompatibilities across Linux, macOS, and Windows. | `apps/api/scripts/test.js` | Verified (`npm test` passes cleanly) |

---

## 6. API and Database Changes

### API Routes

- **Authentication:**
  - `POST /api/v1/auth/register`: User registration with email, password, name, and optional role (`user` | `analyst`).
  - `POST /api/v1/auth/login`: User authentication returning signed JWT token and user profile.
  - `GET /api/v1/auth/me`: Authenticated user profile retrieval.
- **Scanning:**
  - `POST /api/v1/scans`: Enqueues URL, creates `QUEUED` scan record, triggers background worker, immediately returns HTTP 201 (or existing 200 on active duplicate).
  - `GET /api/v1/scans`: Paginated scan history with domain regex filtering.
  - `GET /api/v1/scans/:id`: Individual scan state.
  - `GET /api/v1/scans/:id/results`: Lightweight status polling endpoint returning in-flight progress or completed summary.
- **Reports:**
  - `GET /api/v1/reports/:id`: Full security report view with findings, TLS data, and forensic summary.
- **Threat Intelligence & Community:**
  - `GET /api/v1/threats`: Global feed of verified suspicious and malicious domains.
  - `POST /api/v1/community/reports`: Community threat submission with SHA-256 deduplication.
  - `GET /api/v1/community/reports`: Community list with aggregated upvotes/downvotes.
  - `POST /api/v1/community/reports/:id/vote`: Authenticated user voting (or rate-limited IP hash voting for guests).
- **Telemetry:**
  - `GET /api/v1/dashboard/stats`: Telemetry KPIs and recent scans computed directly from MongoDB.

### Database Collections & Production Indexes (Managed via `IndexMigrationManager`)

1. **`scans`**:
   - Fields: `submittedUrl`, `normalizedDomain`, `urlHash`, `status` (`QUEUED` | `PROCESSING` | `COMPLETED` | `FAILED`), `riskScore`, `verdict`, `confidence`, `analyzerStatuses`, `summary`, `retryCount`, `workerId`, `claimedAt`, `leaseToken`, `publishedLeaseToken`, `lastError`, `timeoutSeconds`, `errorMessage`, `completedAt`, timestamps.
   - Indexes:
     - `{ status: 1, createdAt: 1 }` (FIFO atomic queue claim index)
     - `{ status: 1, claimedAt: 1 }` (abandoned job recovery reaper index)
     - `{ urlHash: 1, status: 1 }` (duplicate active scan submission check index)
     - `{ urlHash: 1 }` (partial unique index where `status IN ['QUEUED', 'PROCESSING']`)
     - `{ publishedLeaseToken: 1 }` (published results lookup index)
     - `{ leaseToken: 1 }` (active worker lease lookup index)
     - `{ normalizedDomain: 1, createdAt: -1 }` (domain search index)
     - `{ createdAt: -1 }`, `{ verdict: 1 }`
2. **`findings`**:
   - Fields: `scanId`, `leaseToken`, `category`, `severity`, `title`, `description`, `evidence` (Mixed), `confidence`, timestamps.
   - Indexes: `{ scanId: 1, severity: 1 }`, `{ scanId: 1, leaseToken: 1 }`, `{ category: 1 }`, `{ leaseToken: 1 }`.
3. **`certificates`**:
   - Fields: `scanId`, `leaseToken`, `issuer`, `subject`, `validFrom`, `validUntil`, `fingerprint`, `hostnameMatched`, `rawDetails`, timestamps.
   - Indexes: `{ scanId: 1 }`, `{ scanId: 1, leaseToken: 1 }` (compound unique sparse index per worker attempt), `{ fingerprint: 1 }`, `{ leaseToken: 1 }`.
   - *Dropped obsolete constraint:* `certificates.scanId_1` unique dropped to support attempt-scoped result isolation.
4. **`threatreports`**:
   - Fields: `submittedUrl`, `normalizedDomain`, `urlHash` (SHA-256), `category`, `description`, `status`, `reportCount`, `submitterEmail`, timestamps.
   - Indexes: `{ urlHash: 1 }`, `{ status: 1 }`.
5. **`threatvotes`**:
   - Fields: `reportId`, `userId`, `vote` (`UPVOTE` | `DOWNVOTE`), timestamps.
   - Indexes: `{ reportId: 1, userId: 1 }` (unique compound index enforcing one vote per user/report).
6. **`users`**:
   - Fields: `email` (unique), `passwordHash`, `name`, `role` (`user` | `analyst` | `admin`), timestamps.
   - Indexes: `{ email: 1 }` (unique).
7. **`_schema_migrations`**:
   - Fields: `_id` (migration ID string), `status` (`IN_PROGRESS` | `COMPLETED` | `FAILED`), `lockedAt`, `lockHolder`, `appliedAt`, `details`, `lastError`, timestamps.

---

## 7. Current Development Progress

- **Completed Phases:**
  - **Phase 1-3:** Modular Core Platform, REST API, Threat Engine, Heuristic Scoring, Next.js UI, SSRF Perimeter Hardening.
  - **Phase 4:** Native MongoDB Asynchronous Scanning Queue, Worker Leasing & Fencing, Conditional Atomic Reaper, Attempt-Scoped Persistence & Rollback.
  - **Phase 4.1:** Operational Hardening: Bounded Orphan-Artifact Cleanup Service (`OrphanCleanupService`), Controlled MongoDB Index Migrations (`IndexMigrationManager`), Dry-Run Inspection CLI, `autoIndex: false` on startup.
  - **Phase 5:** Enterprise Threat Intelligence, Deep Cryptographic X.509 Trust Engine, Multi-Sector Phishing/Brand Impersonation Detection, Production User Authentication & RBAC, Cross-Platform Test Runner.
  - **Phase 6.1:** Benchmark Infrastructure & Baseline Evaluation: Reproducible offline test harness, 80-case development dataset (`dataset_dev.json`), 25-case independent validation dataset (`dataset_val.json`), 3x3 confusion matrix, binary threat metrics, and latency measurement without network egress.
  - **Phase 6.3:** Evidence-Based Detection Calibration: Implemented CAL-01 through CAL-06, lifting development accuracy from 78.75% to 87.50%, eliminating all false alarms on benign targets (FPR 0.0%), and achieving 100% binary threat detection (FNR 0.0%).
- **Completed Improvements:**
  - `SENTRIX-AUTH-01`: Production-grade User Authentication & Role-Based Access Control (RBAC) token issuance in `apps/api` (`POST /api/v1/auth/register`, `POST /api/v1/auth/login`, `GET /api/v1/auth/me`) using zero-dependency Node `crypto.scrypt` password hashing with random 16-byte salt, constant-time comparison, and signed HMAC-SHA256 JWTs.
  - `SENTRIX-AUTH-02`: Implemented `authenticate` and `requireRole(['admin', 'analyst'])` preHandler guards in Fastify, and integrated authenticated voter identity into community threat reporting and voting, resolving `SENTRIX-SEC-04` by tying votes directly to verified accounts while gracefully supporting anonymous IP hash voting.
  - `SENTRIX-TLS-01`: Implemented deep cryptographic X.509 inspection using Python `cryptography.x509` in `tls_analyzer.py`, detecting:
    - Flawed CA key generation and untrust incidents (specifically detecting **eMudhra** flawed sub-CAs, WoSign, StartCom, Camerfirma, DigiNotar, and DarkMatter/TrustCor).
    - Sub-2048 bit RSA keys (<2048 flagged CRITICAL) and legacy/weak algorithms.
    - Broken signature hash algorithms (SHA-1/MD5 collision risks flagged CRITICAL).
    - Missing Certificate Transparency (CT) Signed Certificate Timestamps (SCTs) on public certificates (flagged MEDIUM).
    - CA/Browser Forum Baseline Requirements validity violations (>398 days for post-Sept 2020 certs).
    - Rogue end-entity leaf certificates claiming CA privileges (`CA: TRUE` flagged CRITICAL).
  - `SENTRIX-PHISH-01`: Expanded targeted brand and sector impersonation detection in `domain_analyzer.py`:
    - Major global and national banking & fintech brands (SBI, HDFC, ICICI, Wells Fargo, Chase, Citi, Barclays, HSBC, Santander, Stripe, Razorpay, Revolut, Venmo, CashApp, Binance, Coinbase).
    - Government & public authority impersonation detection (flagging keywords like `incometax`, `irs`, `passport`, `aadhaar`, `uidai`, `mygov`, `socialsecurity` hosted on non-governmental TLDs).
    - Higher education & academic impersonation detection (flagging university/student-aid terms on non-accredited TLDs).
    - Deceptive recruitment scam detection (flagging employment terms under high-abuse TLDs).
    - Typosquatting and leetspeak homoglyph detection (`0->o`, `1->l`, `rn->m`, `vv->w`).
  - `SENTRIX-APPSEC-01`: Enhanced application security and credential harvesting defenses in `web_security_analyzer.py`:
    - Server header version leakage detection and `X-Powered-By` framework disclosure.
    - Payment card and financial credential harvester detection (`cvv`, `cardnumber`, `bankaccount`).
    - Third-party webhook exfiltration auditing (forms submitting to Telegram bot APIs, Discord webhooks, or Formspree).
    - Client-side `<meta http-equiv="refresh">` external redirect detection.
  - `SENTRIX-OPS-01`: Cross-platform test execution runner (`apps/api/scripts/test.js`) and root `npm test` script resolving cross-platform shell environment incompatibilities.
  - `SENTRIX-WEB-01`: Added typed API client (`apps/web/src/lib/api.ts` and `apps/web/src/lib/utils.ts`) with auth token management, passing 100% Next.js TypeScript typechecks (`tsc --noEmit`).
  - `SENTRIX-SEC-05`: Fixed Registration Privilege Escalation: Public registration payload strictly accepts email and password (`UserRegisterSchema`), stripping any supplied `role` or extraneous parameters. Document creation strictly assigns `role: 'user'`. Built dedicated operator CLI bootstrap script (`createAdmin.ts`) with password complexity checks and idempotency, and authorized role management endpoint (`PATCH /api/v1/auth/users/:id/role`) with last-admin demotion prevention.
  - `SENTRIX-SEC-06`: Authentication Hardening & Instant Role Revocation: Implemented non-blocking versioned `crypto.scrypt` key derivation (`scrypt$v=1$n=16384,r=8,p=1$<saltHex>$<derivedKeyHex>`), max password length 128-char limit, timing-attack neutral login (`dummyVerifyPassword`), generic error responses, 10 req/min rate limiting, explicit JWT algorithm (`HS256`) and expiration enforcement, and `roleVersion` fencing to instantaneously invalidate active tokens on role changes.
  - `SENTRIX-SEC-07`: Concurrency-Safe Last Administrator Invariant: Implemented distributed atomic locking (`executeWithAdminRoleLock` on `_auth_locks.admin_role_mutation`) and conditional updates preventing write-skew under simultaneous administrator demotions. Tested and verified in real MongoDB 7.0 that concurrent demotions leave exactly one administrator and failed demotions preserve `roleVersion`.
  - `SENTRIX-SEC-08`: Password Hashing Concurrency Limiting & Bound Enforcement: Implemented `ScryptConcurrencyLimiter` bounding parallel scrypt operations to 10 with queued handling, enforced strict 128-char bounds across registration and login, and implemented safe parameter validation (rejecting malformed parameters and unsupported versions) preventing CPU/memory exhaustion attacks.
  - `SENTRIX-SEC-09`: Enhanced Administrator Provisioning: Interactive hidden password prompt in `createAdmin.ts` for terminal operators, memory-purging of `ADMIN_PASSWORD`, and duplicate key race handling.
  - `SENTRIX-TLS-02`: CA/Browser Forum Ballot SC-081v3 Dynamic Validity Schedule: Implemented dynamic lifetime limits (398d before March 2026, 200d from March 2026, 100d from March 2027, 47d from March 2029) scoped strictly to public end-entity subscriber certificates (`issuer != subject and not is_ca`). Distinguished policy violations from expired certificates with full forensic evidence.
  - `SENTRIX-TLS-03`: Nuanced Certificate Transparency & CA Trust Reporting: Qualified reporting on missing embedded SCTs (acknowledging TLS handshake/OCSP delivery channels) and distinguished CA subject spoofing on self-signed certs from unverified and verified certificate chains.
  - `SENTRIX-TLS-04`: Comprehensive SC-081v3 Deterministic Boundary Testing: Added exact UTC boundary tests for 2026 (200d), 2027 (100d), and 2029 (47d) transitions, and verified CA/self-signed validity exemptions.
  - `SENTRIX-CAL-01`: Contextual Security Posture Scoring: Implemented 15-point ceiling on defense-in-depth posture findings (missing HSTS, CSP, XFO, XCTO, Referrer-Policy, server banner disclosure, missing leaf SCTs) in `risk_engine.py`, preventing benign sites from crossing the SUSPICIOUS threshold (>= 26).
  - `SENTRIX-CAL-02`: PSL-Aware Authentic Domain Context: Integrated `tldextract` to identify authentic registrable domains from `RECOGNIZED_AUTHENTIC_DOMAINS` in `url_analyzer.py`, suppressing naive credential keyword penalties on standard authentication paths (`/login`, `/signin`, `/account`) for recognized domains free of homoglyphs and userinfo.
  - `SENTRIX-CAL-03`: Token-Based Domain Segmentation: Domain segmentation into hyphen- and dot-delimited tokens in `domain_analyzer.py`. Short brands (<= 4 chars) require exact token equality (resolving false positives like `isbilling.com` and `simplicity.org`), and multi-token brands are matched across hyphens.
  - `SENTRIX-CAL-04`: Multi-Candidate Leetspeak Impersonation Engine: Generated multi-candidate character substitutions (`1` -> `l`, `i`, `t`; `0` -> `o`) in `domain_analyzer.py`, detecting obfuscated impersonations like `wha1sapp`, `spot1fy`, and `b0fa`.
  - `SENTRIX-CAL-05`: Credential Harvesting & Evasion Severity Calibration: Escalated national ID and financial credential collection to CRITICAL (40 points) in `web_security_analyzer.py`. Calibrated client-side meta-refresh redirects to require corroborating indicators before escalating to CRITICAL. Hardened TLS analyzer against `AttributeError` on `verify_message`.
  - `SENTRIX-CAL-06`: Finding Deduplication & Risk Factor Aggregation: Deduplicated threat findings by `dedup_key` (e.g. `HOST_RAW_IP`) in `risk_engine.py`, selecting the highest-severity observation per group to prevent double-counting in score and risk factors.
- **Benchmark Metrics Comparison:**
  - **Development Dataset (80 cases, `dataset_dev.json`):**
    - Overall 3-Class Accuracy: **78.75% -> 87.50%** (+8.75%)
    - Macro-Averaged F1: **67.12% -> 79.95%** (+12.83%)
    - Weighted-Averaged F1: **78.43% -> 87.88%** (+9.45%)
    - Binary Threat F1 (Threat = SUSPICIOUS | MALICIOUS): **95.65% -> 100.00%**
    - False Positive Rate (FPR): **8.57% -> 0.00%** (0 false alarms out of 35 benign cases)
    - False Negative Rate (FNR): **2.22% -> 0.00%** (0 missed threats out of 45 threat cases)
    - BENIGN Class F1: **94.12% -> 100.00%** (Precision: 100.0%, Recall: 100.0%)
  - **Independent Validation Dataset (25 cases, `dataset_val.json`):**
    - Overall 3-Class Accuracy: **80.00% -> 88.00%** (+8.00%)
    - Macro-Averaged F1: **73.18% -> 78.70%** (+5.52%)
    - Weighted-Averaged F1: **80.00% -> 88.66%** (+8.66%)
    - Binary Threat F1: **92.86% -> 100.00%** (FPR: 10.0% -> 0.0%, FNR: 0.0% -> 0.0%)
- **Test Metrics & Platform Verification:**
  - **API Test Suite:** 69 tests across 7 test suites (`security.test.ts`, `auth.test.ts`, `authIntegration.test.ts`, `asyncScan.test.ts`, `realMongoConcurrency.test.ts`, `orphanCleanup.test.ts`, `indexMigration.test.ts`) passing with 100% success rate against live MongoDB 7.0 (69 passed, 0 failed, 0 skipped).
  - **Scanner Pytest Suite:** 67 tests passing (including 6 new calibration regression tests in `test_calibration_regression.py`) with zero failures.
  - **Monorepo Build:** `@sentrix/shared` (tsc) + `@sentrix/api` (tsc) + `@sentrix/web` (Next.js 14 static generation) building 9/9 routes cleanly.
  - **Docker Compose:** `docker compose config --quiet` validating cleanly.
- **Current Task:** Phase 6.3 Evidence-Based Detection Calibration completed; calibration benchmark reports generated (`calibrated_dev_report.json`, `calibrated_val_report.json`).
- **Next Priorities:**
  - Expand benchmark test suites with real-world threat feeds and broader multi-sector targets.
  - Complete optional external threat feeds (Google Safe Browsing v4 API key setup).
  - Add user profile and API key generation for enterprise automated scan submissions.

---

## 8. Known Issues and Technical Debt

- **Anonymous Voting Identity:** Solved by Phase 5 authentication module; authenticated users vote with cryptographically verified account IDs while anonymous users safely fallback to salted IP hashes with route rate limits (20 votes/min).
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
| **2026-11-07** | `f30d2be` | Operational Hardening & Controlled Migrations (Phase 4.1) | Implemented OrphanCleanupService, attempt-scoped artifact lifecycle recovery, IndexMigrationManager with distributed locking in _schema_migrations, dry-run CLI, removed startup syncIndexes, autoIndex: false, 56 API tests, 48 scanner pytest tests. |
| **2026-11-07** | `3f93302` | Enterprise Threat Intelligence, Deep Cryptographic Trust Engine & Production Auth (Phase 5) | Built User Authentication & RBAC (`/api/v1/auth`), deep X.509 cryptographic validation in `tls_analyzer.py` (eMudhra incident & weak CA checks, sub-2048 bit RSA keys, broken SHA-1 signatures, CT SCTs, CA: TRUE leaf checks), enterprise banking, government, academic and recruitment impersonation engines in `domain_analyzer.py`, cross-platform test runner (`scripts/test.js`), and typed web API client. |
| **2026-11-08** | `1267507` | Merge PR #1: Enterprise Threat Intelligence & Production Auth | Merged branch `Sayandeep` into `main`, unifying Phase 4.1 operational hardening, index migrations, orphan artifact cleanup, and Phase 5 enterprise auth and cryptographic trust engines. |
| **2026-11-08** | `Working Tree` | Phase 5.2 Final Security Verification & Production Readiness Audit | Implemented distributed atomic locking for last-admin demotion invariant, bounded scrypt concurrency limiter (10 parallel max), safe hash parameter parsing, interactive masked password CLI in createAdmin.ts, exact UTC SC-081v3 boundary tests (2026, 2027, 2029) + CA exemptions, 7 real MongoDB 7.0 auth integration tests (69 total API tests + 61 pytest tests, 100% passing). |
| **2026-11-08** | `Working Tree` | Phase 6.1 Benchmark Infrastructure & Baseline Evaluation | Built reproducible benchmark test harness, 80-case development dataset (`dataset_dev.json`), 25-case independent validation dataset (`dataset_val.json`), baseline reports (`baseline_dev_report.json`, `baseline_val_report.json`), 3x3 confusion matrix and binary metrics. |
| **2026-11-08** | `Working Tree` | Phase 6.3 Evidence-Based Detection Calibration | Implemented CAL-01 through CAL-06 (15-pt posture ceiling, PSL authentic domain context, short-brand token boundaries, multi-candidate leetspeak matching, financial credential escalation, finding deduplication). Improved dev accuracy to 87.50% (+8.75%), eliminated false alarms (FPR 0.0%), achieved 100% binary threat detection. Added 6 calibration regression tests (67 passed in pytest). |
