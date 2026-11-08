# SENTRIX REST API Specification

This document outlines the API contracts, request payloads, response structures, and error codes for SENTRIX services.

Base URL: `http://localhost:8000/api/v1`

---

## 1. System Endpoints

### 1.1 Fastify API Health Check
- **Method:** `GET`
- **Paths:** `/health` and `/api/v1/health`
- **Authentication:** None
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "sentrix-api",
  "version": "1.0.0",
  "database": "connected",
  "timestamp": "2026-11-08T16:04:36.165Z"
}
```

### 1.2 Python Threat Scanner Health Check (Internal)
- **Method:** `GET`
- **Path:** `http://localhost:8001/health`
- **Authentication:** None
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "sentrix-scanner",
  "version": "1.0.0",
  "uptimeSeconds": 4310.45,
  "analyzers": [
    "UrlAnalyzer",
    "DomainAnalyzer",
    "TlsAnalyzer",
    "WebSecurityAnalyzer",
    "ReputationAnalyzer"
  ]
}
```

---

## 2. Threat Scans API

### 2.1 Submit & Enqueue Threat Scan
- **Method:** `POST`
- **Path:** `/api/v1/scans`
- **Rate Limit:** 120 req / minute
- **Request Body:**
```json
{
  "url": "https://example.com/login",
  "deepScan": false
}
```
- **Response (201 Created — Immediate Enqueue):**
```json
{
  "scanId": "6aeeb30f7d820d3c9abefb2f",
  "status": "QUEUED",
  "submittedUrl": "https://example.com/login",
  "normalizedDomain": "example.com",
  "message": "Scan queued for asynchronous processing"
}
```
- **Duplicate Active Scan Response (200 OK):**
```json
{
  "scanId": "6aeeb30f7d820d3c9abefb2f",
  "status": "PROCESSING",
  "submittedUrl": "https://example.com/login",
  "isDuplicate": true,
  "message": "Scan already active"
}
```
- **Error Responses:**
  - `400 Bad Request` (Validation error or SSRF restriction):
    ```json
    {
      "error": "SCAN_FAILED",
      "message": "Target destination violated perimeter safety policies.",
      "statusCode": 400
    }
    ```

### 2.2 Poll Scan Status & Results
- **Method:** `GET`
- **Path:** `/api/v1/scans/:id/results`
- **Response while In-Flight (200 OK):**
```json
{
  "scanId": "6aeeb30f7d820d3c9abefb2f",
  "status": "PROCESSING",
  "submittedUrl": "https://example.com/login",
  "retryCount": 0,
  "message": "Analysis in progress"
}
```
- **Response upon Completion (200 OK):**
```json
{
  "scanId": "6aeeb30f7d820d3c9abefb2f",
  "status": "COMPLETED",
  "submittedUrl": "https://example.com/login",
  "normalizedDomain": "example.com",
  "riskScore": 15,
  "verdict": "BENIGN",
  "confidence": 92,
  "completedAt": "2026-11-08T16:05:00.000Z",
  "findings": [...],
  "certificate": {...},
  "summary": {
    "threatTypes": [],
    "riskFactors": [],
    "mitreTactics": [],
    "redirectChain": ["https://example.com/login"],
    "responseTimeMs": 145.2
  }
}
```

### 2.3 List Recent Scans
- **Method:** `GET`
- **Path:** `/api/v1/scans?limit=20&skip=0&domain=paypal`
- **Response (200 OK):**
```json
{
  "total": 42,
  "scans": [
    {
      "_id": "6aeeb30f7d820d3c9abefb2f",
      "submittedUrl": "https://example.com/",
      "normalizedDomain": "example.com",
      "status": "COMPLETED",
      "riskScore": 15,
      "verdict": "BENIGN",
      "confidence": 92,
      "createdAt": "2026-11-08T16:04:45.000Z"
    }
  ]
}
```

---

## 3. Security Reports API

### 3.1 Get Comprehensive Security Report
- **Method:** `GET`
- **Path:** `/api/v1/reports/:id`
- **Response (200 OK):**
```json
{
  "scan": {
    "_id": "6aeeb30f7d820d3c9abefb2f",
    "submittedUrl": "https://example.com/",
    "normalizedDomain": "example.com",
    "status": "COMPLETED",
    "riskScore": 15,
    "verdict": "BENIGN",
    "confidence": 92,
    "analyzerStatuses": {
      "urlAnalyzer": "SUCCESS",
      "domainAnalyzer": "SUCCESS",
      "tlsAnalyzer": "SUCCESS",
      "webSecurityAnalyzer": "SUCCESS",
      "reputationAnalyzer": "SUCCESS"
    },
    "completedAt": "2026-11-08T16:05:00.000Z"
  },
  "findings": [
    {
      "_id": "6aeeb3147d820d3c9abefb31",
      "scanId": "6aeeb30f7d820d3c9abefb2f",
      "category": "DOMAIN_REPUTATION",
      "severity": "INFO",
      "title": "Domain Taxonomy Verified",
      "description": "Extracted domain: example, suffix: com, subdomains: none.",
      "evidence": {
        "subdomain": "",
        "domain": "example",
        "suffix": "com",
        "registeredDomain": "example.com"
      },
      "confidence": 100
    }
  ],
  "certificate": {
    "_id": "6aeeb314ae6c8624764ef492",
    "scanId": "6aeeb30f7d820d3c9abefb2f",
    "issuer": "CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1",
    "subject": "CN=example.com",
    "validFrom": "2026-01-01T00:00:00.000Z",
    "validUntil": "2026-12-31T23:59:59.000Z",
    "fingerprint": "85ca6ab068e9bcce88b6c4aa3c47f7d17228134a457f870d3800e6223a0df07a",
    "hostnameMatched": true
  },
  "summary": {
    "threatTypes": [],
    "riskFactors": [],
    "mitreTactics": [],
    "redirectChain": ["https://example.com/"],
    "responseTimeMs": 145.2
  }
}
```

---

## 4. AI-Powered Scam & Message Analysis API (Module A)

### 4.1 Analyze Suspicious Message Text
- **Method:** `POST`
- **Path:** `/api/v1/messages/analyze`
- **Request Body:**
```json
{
  "messageText": "URGENT: Your Chase checking account is suspended. Reply with your 6-digit OTP code to +1-800-555-0199 or verify at http://chase-security-auth.net/verify immediately.",
  "channel": "SMS",
  "senderInfo": "+1-800-555-0199"
}
```
- **Allowed `channel` Values:** `SMS`, `WHATSAPP`, `EMAIL`, `TELEGRAM`, `SOCIAL_MEDIA`, `OTHER`
- **Response (201 Created):**
```json
{
  "_id": "6af09dc6ac9bfb4b4d7b1113",
  "messageHash": "f9c1686302b670fb5a4499a62620dde735243b25249101bc93a3d35185a2cd11",
  "channel": "SMS",
  "preview": "URGENT: Your Chase checking account is suspended. Reply with your 6-digit OTP code to +1-800-555-0199...",
  "classification": "MALICIOUS",
  "riskScore": 77,
  "confidence": 90,
  "detectedPatterns": [
    {
      "tactic": "CREDENTIAL_OTP_HARVESTING",
      "severity": "CRITICAL",
      "title": "Credential or OTP Authentication Harvesting",
      "description": "Message directly requests authentication credentials, one-time passwords (OTP), recovery seed phrases, or urgent KYC verification.",
      "matchedPatterns": ["OTP"]
    },
    {
      "tactic": "URGENCY_FEAR",
      "severity": "MEDIUM",
      "title": "Psychological Urgency & Fear-Inducing Language",
      "description": "Message employs strict deadlines, threats of account suspension, or legal repercussions.",
      "matchedPatterns": ["immediately", "suspended"]
    },
    {
      "tactic": "AUTHORITY_IMPERSONATION",
      "severity": "HIGH",
      "title": "Institutional or Brand Impersonation",
      "description": "Message claims representation from reputable institutions (Chase Banking & Payments).",
      "matchedPatterns": ["Chase Banking & Payments"]
    }
  ],
  "extractedIndicators": {
    "urls": ["http://chase-security-auth.net/verify"],
    "domains": ["chase-security-auth.net"],
    "emails": [],
    "phones": ["+1-800-555-0199"],
    "wallets": [],
    "paymentRefs": [],
    "entities": ["Chase Banking & Payments"]
  },
  "threatIntelMatches": [],
  "aiExplanation": {
    "summary": "High-risk social engineering attack detected (Risk Score: 77/100).",
    "reasoning": [
      "Psychological Urgency & Fear-Inducing Language detected.",
      "Credential or OTP Authentication Harvesting detected.",
      "Institutional or Brand Impersonation detected."
    ],
    "precautions": [
      "DO NOT click any links, open attachments, or reply to the sender.",
      "Never disclose one-time passcodes (OTP), account passwords, or seed phrases.",
      "Block the sender address/phone number."
    ],
    "limitations": [
      "Analysis evaluated content lexically and cryptographically; confirm communication independently through official bank numbers."
    ]
  },
  "createdAt": "2026-11-08T16:05:26.538Z"
}
```

### 4.2 Get Message Report by ID
- **Method:** `GET`
- **Path:** `/api/v1/messages/:id`
- **Response (200 OK):** Returns single `IMessageAnalysis` object.

### 4.3 List Historical Message Analyses
- **Method:** `GET`
- **Path:** `/api/v1/messages?limit=20&skip=0`
- **Response (200 OK):**
```json
{
  "total": 15,
  "messages": [...]
}
```

---

## 5. Threat Correlation & Campaign Graph API (Module B)

### 5.1 Query Related Threat Incidents by Indicator
- **Method:** `GET`
- **Path:** `/api/v1/correlations/related/:target`
- **Example:** `/api/v1/correlations/related/chase-security-auth.net`
- **Response (200 OK):**
```json
{
  "target": "chase-security-auth.net",
  "indicatorMatches": [
    {
      "_id": "6af09dc6696e69d3786e3685",
      "type": "DOMAIN",
      "value": "chase-security-auth.net",
      "normalizedValue": "chase-security-auth.net",
      "occurrences": 1,
      "severity": "CRITICAL",
      "tags": ["MALICIOUS"],
      "relatedScanIds": [],
      "relatedMessageIds": ["6af09dc6ac9bfb4b4d7b1113"],
      "firstSeen": "2026-11-08T16:05:26.694Z",
      "lastSeen": "2026-11-08T16:05:26.694Z"
    }
  ],
  "campaigns": [],
  "relatedScans": [],
  "relatedMessages": [
    {
      "_id": "6af09dc6ac9bfb4b4d7b1113",
      "preview": "URGENT: Your Chase checking account is suspended...",
      "classification": "MALICIOUS",
      "riskScore": 77,
      "createdAt": "2026-11-08T16:05:26.538Z"
    }
  ]
}
```

### 5.2 List Active Threat Campaigns
- **Method:** `GET`
- **Path:** `/api/v1/correlations/campaigns?limit=20`
- **Response (200 OK):**
```json
{
  "campaigns": [
    {
      "campaignId": "camp-chase-phishing-2026",
      "name": "Chase Banking Credential Harvesting Campaign",
      "threatType": "PHISHING",
      "confidence": 92,
      "indicators": ["chase-security-auth.net", "+1-800-555-0199"],
      "relatedIncidents": 4,
      "summary": "Coordinated SMS smishing and fake authentication forms."
    }
  ]
}
```

### 5.3 List Top Recurring Threat Indicators
- **Method:** `GET`
- **Path:** `/api/v1/correlations/indicators?limit=30`
- **Response (200 OK):** Returns array of tracked indicators sorted by occurrence count (`occurrences: -1`).

---

## 6. Web3 Threat Registry & Blockchain API (Module C)

### 6.1 Register Threat Report on Blockchain
- **Method:** `POST`
- **Path:** `/api/v1/blockchain/register`
- **Request Body:**
```json
{
  "reportId": "6af09dc6ac9bfb4b4d7b1113",
  "reportType": "MESSAGE"
}
```
- **Allowed `reportType` Values:** `SCAN`, `MESSAGE`, `THREAT_REPORT`
- **Response (201 Created — On-Chain Mode):**
```json
{
  "message": "Threat report commitment registered on blockchain",
  "record": {
    "reportId": "6af09dc6ac9bfb4b4d7b1113",
    "reportType": "MESSAGE",
    "target": "URGENT: Your Chase checking account is suspended...",
    "reportHash": "0x97c00380538fe28e36a7d7f46cb41e0423fd50181d9a83a1b9709a827ee91a5f",
    "txHash": "0xf4e3ba8fe580b6f24953d899c62e9a2349a952c57c6cc4e200b919be6eefc3ad",
    "blockNumber": 25,
    "blockTimestamp": 1794153960,
    "contractAddress": "0x322813fd9a801c5507c9de605d63cea4f2ce6c44",
    "chainId": 31337,
    "networkName": "Hardhat Local",
    "reporterAddress": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
    "status": "CONFIRMED",
    "isSimulated": false
  }
}
```
- **Response (201 Created — Offline Simulated Mode):**
```json
{
  "message": "Threat report commitment registered on blockchain",
  "record": {
    "reportId": "6af09dc6ac9bfb4b4d7b1113",
    "reportType": "MESSAGE",
    "reportHash": "0x97c00380538fe28e36a7d7f46cb41e0423fd50181d9a83a1b9709a827ee91a5f",
    "txHash": "simulated-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "blockNumber": 0,
    "status": "SIMULATED",
    "isSimulated": true,
    "networkName": "Simulated Cryptographic Ledger (Offline / Non-EVM)"
  }
}
```

### 6.2 Independently Verify Report on Blockchain
- **Method:** `GET`
- **Path:** `/api/v1/blockchain/verify/:id`
- **Response (200 OK — On-Chain Verified):**
```json
{
  "verified": true,
  "reportId": "6af09dc6ac9bfb4b4d7b1113",
  "calculatedHash": "0x97c00380538fe28e36a7d7f46cb41e0423fd50181d9a83a1b9709a827ee91a5f",
  "onChainHash": "0x97c00380538fe28e36a7d7f46cb41e0423fd50181d9a83a1b9709a827ee91a5f",
  "hashesMatch": true,
  "isSimulated": false,
  "mode": "ON_CHAIN",
  "blockNumber": 25,
  "blockTimestamp": 1794153960,
  "timestampDate": "2026-11-08T16:06:00.000Z",
  "txHash": "0xf4e3ba8fe580b6f24953d899c62e9a2349a952c57c6cc4e200b919be6eefc3ad",
  "contractAddress": "0x322813fd9a801c5507c9de605d63cea4f2ce6c44",
  "networkName": "Hardhat Local",
  "reporterAddress": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
}
```

### 6.3 Get Blockchain & Network Configuration
- **Method:** `GET`
- **Path:** `/api/v1/blockchain/config`
- **Response (200 OK):**
```json
{
  "networkName": "Hardhat Local",
  "chainId": 31337,
  "contractAddress": "0x322813fd9a801c5507c9de605d63cea4f2ce6c44",
  "isConnected": true,
  "isSimulated": false
}
```

---

## 7. Evidence-Grounded AI Explanation API (Module D)

### 7.1 Generate Grounded Threat Explanation
- **Method:** `POST`
- **Path:** `/api/v1/ai/explain`
- **Request Body:**
```json
{
  "contextType": "SCAN",
  "contextId": "6aeeb30f7d820d3c9abefb2f",
  "target": "https://example.com/login",
  "verdict": "BENIGN",
  "riskScore": 15,
  "findings": [
    {
      "title": "Domain Taxonomy Verified",
      "category": "DOMAIN_REPUTATION",
      "severity": "INFO"
    }
  ]
}
```
- **Response (200 OK):**
```json
{
  "summary": "Verified benign profile for https://example.com/login (Risk Score: 15/100). Standard security baseline confirmed.",
  "reasoning": [
    "Inspection confirmed authentic domain identity and valid cryptographic TLS certificate."
  ],
  "precautions": [
    "No immediate defensive action required; destination conforms to enterprise standards."
  ],
  "limitations": [
    "Automated passive security inspection evaluates observable parameters without testing invasive exploit payloads."
  ]
}
```

---

## 8. Threat Intelligence API

### 8.1 Global Threat Feed
- **Method:** `GET`
- **Path:** `/api/v1/threats?query=paypal`
- **Response (200 OK):**
```json
{
  "threats": [
    {
      "_id": "6aeeb3207d820d3c9abefb3e",
      "submittedUrl": "http://paypal-security-center.account-verify.xyz/login",
      "normalizedDomain": "paypal-security-center.account-verify.xyz",
      "riskScore": 100,
      "verdict": "MALICIOUS",
      "createdAt": "2026-11-08T12:00:00.000Z"
    }
  ],
  "communityThreats": []
}
```

---

## 9. Community Reporting & Consensus API

### 9.1 Submit Community Threat Report
- **Method:** `POST`
- **Path:** `/api/v1/community/reports`
- **Request Body:**
```json
{
  "url": "https://secure-chase-update-account.top/login",
  "category": "PHISHING",
  "description": "Impersonates Chase bank login portal to harvest credentials.",
  "submitterEmail": "analyst@sentrix.local"
}
```
- **Response (201 Created):**
```json
{
  "report": {
    "_id": "6aeeb33b7d820d3c9abefb58",
    "submittedUrl": "https://secure-chase-update-account.top/login",
    "normalizedDomain": "secure-chase-update-account.top",
    "urlHash": "a6bed3594b8597e9e8940eed14c3c677d6c3acbadbb8e5f722bed7cf810deacb",
    "category": "PHISHING",
    "description": "Impersonates Chase bank login portal to harvest credentials.",
    "status": "SUBMITTED",
    "reportCount": 1,
    "createdAt": "2026-11-08T12:05:00.000Z"
  },
  "message": "Threat report submitted successfully for community verification."
}
```

### 9.2 List Community Reports with Vote Tallies
- **Method:** `GET`
- **Path:** `/api/v1/community/reports`
- **Response (200 OK):**
```json
{
  "reports": [
    {
      "_id": "6aeeb33b7d820d3c9abefb58",
      "submittedUrl": "https://secure-chase-update-account.top/login",
      "normalizedDomain": "secure-chase-update-account.top",
      "category": "PHISHING",
      "description": "Impersonates Chase bank login portal to harvest credentials.",
      "status": "SUBMITTED",
      "reportCount": 1,
      "upvotes": 5,
      "downvotes": 0,
      "userVote": "UPVOTE",
      "createdAt": "2026-11-08T12:05:00.000Z"
    }
  ]
}
```

### 9.3 Cast Vote on Community Report
- **Method:** `POST`
- **Path:** `/api/v1/community/reports/:id/vote`
- **Rate Limit:** 20 votes / minute per IP
- **Request Body:**
```json
{
  "vote": "UPVOTE"
}
```
- **Response (200 OK):**
```json
{
  "message": "Vote recorded",
  "vote": "UPVOTE"
}
```

---

## 10. Dashboard Telemetry API

### 10.1 Real-Time Telemetry Statistics
- **Method:** `GET`
- **Path:** `/api/v1/dashboard/stats`
- **Response (200 OK):**
```json
{
  "totalScans": 128,
  "maliciousCount": 34,
  "suspiciousCount": 18,
  "benignCount": 76,
  "averageRiskScore": 38,
  "threatsReported": 12,
  "recentScans": [...]
}
```

---

## 11. Authentication & RBAC API

### 11.1 Register User Account
- **Method:** `POST`
- **Path:** `/api/v1/auth/register`
- **Rate Limit:** 10 req / minute per IP
- **Security:** Public registration is strictly restricted to `role: 'user'`.
- **Request Body:**
```json
{
  "email": "analyst@sentrix.io",
  "password": "SecurePassword123!"
}
```
- **Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "_id": "6aef0e8840d8291a1005a711",
    "email": "analyst@sentrix.io",
    "role": "user",
    "createdAt": "2026-11-08T10:15:30.000Z"
  }
}
```

### 11.2 Authenticate / Login User
- **Method:** `POST`
- **Path:** `/api/v1/auth/login`
- **Rate Limit:** 10 req / minute per IP
- **Security:** Constant-time dummy password hashing on unknown emails prevents enumeration.
- **Request Body:**
```json
{
  "email": "analyst@sentrix.io",
  "password": "SecurePassword123!"
}
```
- **Response (200 OK):** Returns JWT token and user record.

### 11.3 Get Current Authenticated Profile
- **Method:** `GET`
- **Path:** `/api/v1/auth/me`
- **Headers:** `Authorization: Bearer <token>`
- **Response (200 OK):** Returns current user record.

### 11.4 Update User Role (Admin Only)
- **Method:** `PATCH`
- **Path:** `/api/v1/auth/users/:id/role`
- **Headers:** `Authorization: Bearer <admin-token>`
- **Security Invariant:** Demoting the sole remaining administrator account is prevented under an atomic distributed MongoDB lock (`_auth_locks`). Increments `roleVersion` to invalidate existing tokens.
- **Request Body:**
```json
{
  "role": "analyst"
}
```
- **Response (200 OK):** Returns updated user record with incremented `roleVersion`.

### 11.5 Operator Administrator Provisioning CLI
```bash
# Interactive masked password prompt
npm run create:admin -- --email admin@sentrix.io

# Automated non-interactive execution
ADMIN_EMAIL=admin@sentrix.io ADMIN_PASSWORD=<SecurePassword123!> npm run create:admin
```
