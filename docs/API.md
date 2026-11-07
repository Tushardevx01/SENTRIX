# SENTRIX REST API Specification

This document outlines the API contracts, request payloads, response structures, and error codes for SENTRIX services.

Base URL: `http://localhost:8000/api/v1`

---

## 1. System Endpoints

### 1.1 Fastify API Health Check
- **Method:** `GET`
- **Path:** `/health`
- **Authentication:** None
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "sentrix-api",
  "version": "1.0.0",
  "database": "connected",
  "timestamp": "2026-11-07T05:11:39.702Z"
}
```

### 1.2 Python Scanner Health Check (Internal)
- **Method:** `GET`
- **Path:** `http://localhost:8001/health`
- **Authentication:** None
- **Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "sentrix-scanner",
  "version": "1.0.0",
  "uptimeSeconds": 124.5,
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

### 2.1 Submit & Execute Threat Scan
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
- **Response (201 Created):**
```json
{
  "scanId": "6aeeb30f7d820d3c9abefb2f",
  "status": "COMPLETED",
  "riskScore": 20,
  "verdict": "BENIGN",
  "confidence": 91,
  "submittedUrl": "https://example.com/login",
  "normalizedDomain": "example.com",
  "completedAt": "2026-11-07T05:11:48.871Z",
  "summary": {
    "threatTypes": [],
    "riskFactors": [],
    "mitreTactics": [],
    "redirectChain": ["https://example.com/login"],
    "responseTimeMs": 145.2
  }
}
```
- **Error Responses:**
  - `400 Bad Request` (Validation error or SSRF restriction):
    ```json
    {
      "error": "SCAN_FAILED",
      "message": "Resolved IP 127.0.0.1 belongs to a restricted/private network.",
      "details": {
        "error": "SSRF_VIOLATION",
        "detail": "Target destination violated perimeter safety policies or targeted internal networks."
      },
      "scanId": "6aeeb3287d820d3c9abefb4a"
    }
    ```

### 2.2 List Recent Scans
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
      "riskScore": 20,
      "verdict": "BENIGN",
      "confidence": 91,
      "createdAt": "2026-11-07T05:11:43.759Z"
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
    "riskScore": 20,
    "verdict": "BENIGN",
    "confidence": 91,
    "analyzerStatuses": {
      "urlAnalyzer": "SUCCESS",
      "domainAnalyzer": "SUCCESS",
      "tlsAnalyzer": "SUCCESS",
      "webSecurityAnalyzer": "SUCCESS",
      "reputationAnalyzer": "SUCCESS"
    },
    "completedAt": "2026-11-07T05:11:48.871Z"
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
    "issuer": "countryName=US, organizationName=SSL Corporation, commonName=Cloudflare TLS Issuing ECC CA 3",
    "subject": "commonName=example.com",
    "validFrom": "2026-09-26T22:49:11+00:00",
    "validUntil": "2026-12-25T22:56:35+00:00",
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

## 4. Threat Intelligence API

### 4.1 Global Threat Feed
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
      "createdAt": "2026-11-07T05:12:00.917Z"
    }
  ],
  "communityThreats": []
}
```

---

## 5. Community Reporting & Consensus API

### 5.1 Submit Community Threat Report
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
    "createdAt": "2026-11-07T05:12:27.249Z"
  },
  "message": "Threat report submitted successfully for community verification."
}
```

### 5.2 List Community Reports with Vote Tallies
- **Method:** `GET`
- **Path:** `/api/v1/community/reports`
- **Headers:** `X-Session-ID: <anonymous_session_identifier>` (optional)
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
      "createdAt": "2026-11-07T05:12:27.249Z"
    }
  ]
}
```

### 5.3 Cast Vote on Community Report
- **Method:** `POST`
- **Path:** `/api/v1/community/reports/:id/vote`
- **Request Body:**
```json
{
  "vote": "UPVOTE",
  "sessionIdentifier": "session_user_abc123"
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

## 7. Authentication & RBAC API

### 7.1 Register User Account
- **Method:** `POST`
- **Path:** `/api/v1/auth/register`
- **Request Body:**
```json
{
  "email": "analyst@sentrix.io",
  "password": "SecurePassword123!",
  "role": "analyst"
}
```
- **Response (201 Created):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "_id": "6aef0e8840d8291a1005a711",
    "email": "analyst@sentrix.io",
    "role": "analyst",
    "createdAt": "2026-11-08T10:15:30.000Z"
  }
}
```

### 7.2 Authenticate / Login User
- **Method:** `POST`
- **Path:** `/api/v1/auth/login`
- **Request Body:**
```json
{
  "email": "analyst@sentrix.io",
  "password": "SecurePassword123!"
}
```
- **Response (200 OK):**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "_id": "6aef0e8840d8291a1005a711",
    "email": "analyst@sentrix.io",
    "role": "analyst",
    "createdAt": "2026-11-08T10:15:30.000Z"
  }
}
```

### 7.3 Get Current Authenticated Profile
- **Method:** `GET`
- **Path:** `/api/v1/auth/me`
- **Headers:** `Authorization: Bearer <token>`
- **Response (200 OK):**
```json
{
  "user": {
    "_id": "6aef0e8840d8291a1005a711",
    "email": "analyst@sentrix.io",
    "role": "analyst",
    "createdAt": "2026-11-08T10:15:30.000Z"
  }
}
```


### 6.1 Telemetry Metrics
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
