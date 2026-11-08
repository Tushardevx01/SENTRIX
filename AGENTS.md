# AGENTS.md

SENTRIX: website threat detection platform. npm-workspaces monorepo (TypeScript) plus one Python service.

Deeper context lives in `MEMORY.md` (engineering memory, current phase, conventions) and `ARCHITECTURE.md` (design). Read `MEMORY.md` §9 before committing — it mandates updating `MEMORY.md`/`ARCHITECTURE.md` in the same commit as code changes.

## Layout & boundaries

- `apps/web` — Next.js 14 (App Router, port 3000). Talks only to the API via `NEXT_PUBLIC_API_URL`.
- `apps/api` — Fastify 5 gateway (port 8000). **Sole owner of MongoDB access.** Entry: `src/server.ts` (auto-starts unless `NODE_ENV=test`).
- `services/scanner` — Python FastAPI threat engine (port 8001). Stateless, no DB credentials; authenticated by `X-Scanner-Secret`. **Not an npm workspace** — run it with Python directly.
- `packages/shared` — `@sentrix/shared` TS contracts/types/utils, consumed from its **built `dist/`** (`main: ./dist/index.js`; `dist/` is gitignored).
- Ports: web 3000, api 8000, scanner 8001, mongo 27017. In Docker Compose the scanner port is intentionally not published.

## Commands

```bash
npm install                     # root; installs all workspaces
npm run build:shared            # REQUIRED first: api/web import @sentrix/shared from dist/
npm run build                   # shared -> api -> web (order matters; use this, not per-package builds)

npm run dev:web                 # :3000
npm run dev:api                 # :8000 (tsx watch)
npm run dev:scanner             # :8001 — uses services/scanner/.venv
docker compose up --build       # full stack
```

Tests:

```bash
# API (root script = api workspace only)
npm test
# Single API test file — NODE_ENV=test is mandatory, otherwise importing server.ts boots the server:
cd apps/api && NODE_ENV=test npx tsx --test src/test/auth.test.ts

# Scanner (offline, mocked sockets/HTTP)
cd services/scanner && .venv/bin/pytest
cd services/scanner && .venv/bin/pytest tests/test_tls.py::test_name   # single test

# Offline benchmark harness (no network egress; uses production analyzers + risk engine)
cd services/scanner && .venv/bin/python benchmarks/evaluate.py --dataset dataset_dev.json --output report.json
```

There is **no lint/format toolchain** — do not invent one. Verification = `npm run build` (tsc/`next build` typecheck) + both test suites.

## Gotchas (things you would otherwise get wrong)

- **`@sentrix/shared` must be built before anything else.** After `npm install`, after editing `packages/shared/src`, or on a fresh clone, run `npm run build:shared` or api/web builds and dev servers fail to resolve the package. `npm run build` handles the order.
- **`apps/api/scripts/test.js` hardcodes the list of 7 test files.** A new `src/test/*.test.ts` file will NOT run until you add it there. Root `npm test` runs only API tests — scanner tests are a separate command.
- **API tests need a root `.env` and live MongoDB.** Config validation (`src/config/index.ts`) fails at import without `MONGODB_URI` and `SCANNER_API_SECRET` (≥16 chars). Integration suites connect to `mongodb://127.0.0.1:27017/...` (override with `TEST_MONGODB_URI`). Start Mongo first: `docker run -d --name sentrix-mongo -p 27017:27017 mongo:7.0`.
- **Single root `.env` policy — never create per-service `.env` files.** All three services resolve the repo-root `.env` themselves (paths are cwd-independent). Keys are documented in `README.md`; required: `MONGODB_URI`, `SCANNER_API_SECRET`, `SCANNER_INTERNAL_URL`, `NEXT_PUBLIC_API_URL`. Production additionally requires a non-default `JWT_SECRET` (≥32 chars).
- **Index changes are not applied automatically** — Mongoose runs with `autoIndex: false`. After adding/changing indexes, run `npm run migrate:indexes` (inspect with `npm run migrate:indexes:dry-run`).
- `npm run dev:scanner` uses `services/scanner/.venv/bin/python`; install scanner dependencies from `services/scanner/requirements.txt` into that environment if it is missing or incomplete.
- Admin accounts are provisioned via `npm run create:admin` (interactive, masked password), not by inserting users directly.

## Invariants (do not break)

- Only `apps/api` talks to MongoDB; the scanner must stay DB-free and stateless.
- Failed/unreachable analyzers must never yield a benign verdict — degrade confidence, flag warnings (`MEMORY.md` §9 "Fail-Safe Security").
- Dashboard telemetry must query real data; never inject mock metrics.
- Scanner↔API auth is the shared `SCANNER_API_SECRET` header; keep it out of logs and error responses.
