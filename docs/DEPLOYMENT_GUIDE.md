# SENTRIX | Production & Local Deployment Guide

**Target Audience:** DevOps Engineers, System Administrators, Security Engineers, Hackathon Evaluators.  
**Platform Architecture:** Fastify 5 API Gateway, Next.js 14 App Router UI, FastAPI Threat Engine, MongoDB 7.0, Solidity 0.8.20 EVM Smart Contract.

---

## 1. System Requirements

- **Operating System:** Linux (Ubuntu 22.04/24.04, Debian 12), macOS, or WSL2.
- **Node.js:** v20.x LTS or v22.x LTS with `npm` 10+.
- **Python:** Python 3.11, 3.12, 3.13, 3.14, or 3.15.
- **Container Engine:** Docker Engine 24+ & Docker Compose v2, or Podman 4+.
- **Database:** MongoDB Community or Enterprise 7.0+ (or MongoDB Atlas).
- **RAM / CPU:** Minimum 4 GB RAM, 2 CPU cores (8 GB RAM recommended for full stack with Next.js build).

---

## 2. Environment Configuration (Single Root `.env` Policy)

SENTRIX enforces a **strict single root `.env` policy**. All three services (`web`, `api`, `scanner`) resolve the same configuration from the repository root. Never create nested or per-directory `.env` files.

### Configuration Template (`/.env`)

```bash
# General Environment
NODE_ENV=production
PORT=8000
API_PORT=8000
SCANNER_PORT=8001
CORS_ORIGIN=http://localhost:3000

# Web Client URL
NEXT_PUBLIC_API_URL=http://localhost:8000

# Persistence & Gateway Security
MONGODB_URI=mongodb://localhost:27017/sentrix
JWT_SECRET=production_super_secret_jwt_key_at_least_32_characters_long
SCANNER_INTERNAL_URL=http://localhost:8001
SCANNER_API_SECRET=64_character_hex_shared_secret_between_api_and_scanner

# Web3 Blockchain Configuration (Optional EVM Testnet / Hardhat)
BLOCKCHAIN_ENABLED=true
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
THREAT_REGISTRY_CONTRACT_ADDRESS=0x5FbDB2315678afecb367f032d93F642f64180aa3
# NOTE: 0xac09... is permitted ONLY on local Hardhat RPC (127.0.0.1 / localhost);
# For public networks (e.g. Ethereum Sepolia), supply your funded wallet private key:
BLOCKCHAIN_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

# External Intelligence Feeds (Optional)
URLHAUS_ENABLED=true
GOOGLE_SAFE_BROWSING_API_KEY=
LLM_API_KEY=
```

---

## 3. Fast Deployment with Docker Compose (Recommended)

Docker Compose starts all 3 core services and MongoDB in an isolated network:

```bash
# 1. Clone repository
git clone https://github.com/Tushardevx01/SENTRIX.git
cd SENTRIX

# 2. Build and launch services in background
docker compose up -d --build

# 3. Apply MongoDB indexes
docker compose exec api npm run migrate:indexes

# 4. Verify running containers
docker compose ps
```

- **Next.js Web UI:** `http://localhost:3000`
- **Fastify API Gateway:** `http://localhost:8000`
- **MongoDB:** `localhost:27017`
- **Scanner Engine:** Port `8001` is strictly internal to the container network and not exposed to the host.

---

## 4. Bare-Metal / Local Development Deployment

### Step 1: Start MongoDB
```bash
docker run -d --name sentrix-mongo -p 27017:27017 mongo:7.0
```

### Step 2: Install Node Dependencies & Build Shared Contract Package
```bash
npm install
npm run build:shared
```

### Step 3: Set Up Python Scanner Virtual Environment
```bash
cd services/scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ../..
```

### Step 4: Compile Smart Contracts
```bash
node contracts/compile.js
```

### Step 5: Migrate Database Indexes
```bash
npm run migrate:indexes:dry-run
npm run migrate:indexes
```

### Step 6: Create Admin Operator Account (Optional)
```bash
npm run create:admin
```

### Step 7: Launch Services in Separate Terminals
```bash
# Terminal 1: Python Threat Engine
npm run dev:scanner

# Terminal 2: Fastify REST API
npm run dev:api

# Terminal 3: Next.js Frontend
npm run dev:web
```

---

## 5. Web3 Smart Contract Deployment (Local or Testnet)

SENTRIX operates seamlessly with:
1. **Live EVM Node / Hardhat / Sepolia Testnet:** Automatically broadcasts signed transactions and commits SHA-256 hashes to the smart contract ledger.
2. **Offline Fallback / Simulated Ledger:** In the event of RPC unavailability, generates identical cryptographic commitments and maintains persistent ledger state in MongoDB with byte-for-byte SHA-256 verification.

### Launching Local Hardhat EVM Node & Deploying Contract
```bash
# Start local node
npx hardhat node

# Compile contract
node contracts/compile.js

# The contract ThreatRegistry.sol is now available for deployment via ethers.js or hardhat-deploy
```

---

## 6. Production Security Hardening Checklist

- [x] **Perimeter SSRF Defense:** Python scanner executes pre-flight DNS lookups and socket-level IP pinning (`PinnedIPNetworkBackend`) to reject private subnets, cloud metadata (`169.254.169.254`), and anti-TOCTOU rebinding.
- [x] **Database Isolation:** Fastify is the sole owner of MongoDB credentials; Python scanner has zero database connectivity.
- [x] **Inter-Service Security:** API↔Scanner communication authenticated via `X-Scanner-Secret` header using constant-time comparison (`secrets.compare_digest`).
- [x] **Bounded Streaming:** HTTP responses are capped at 1 MB to prevent decompression bombs and memory exhaustion.
- [x] **Zero PII On-Chain:** The Web3 registry stores only SHA-256 hash commitments and severity scores, preserving user privacy.
- [x] **Non-Root Execution:** Scanner and web containers run under unprivileged service users (`appuser`).
- [x] **Atomic Queue & Orphan Recovery:** ScanWorker uses atomic `findOneAndUpdate` with unique lease tokens and automatic 60s reaper recovery.
