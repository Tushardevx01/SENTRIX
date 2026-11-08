# SENTRIX — Live Hackathon Demonstration Guide

> **"Don't trust the link. Verify the threat."**

This guide provides a structured, fail-safe script for demonstrating the **SENTRIX Website Threat Intelligence & Malicious URL Detection Platform** to hackathon judges, evaluators, and security teams.

---

## 1. Executive Summary for Judges (30-Second Elevator Pitch)

Most URL scanners rely either on **slow external blacklists** (which miss zero-day phishing campaigns) or **black-box machine learning** (which hallucinate false positives on legitimate SaaS authentication portals).

**SENTRIX solves this with an explainable, multi-vector zero-trust threat engine:**
- **Zero-Trust Analysis Invariant:** A URL is never assumed safe simply because blacklists have not yet indexed it. Failing or unreachable analyzers degrade confidence and yield `INCONCLUSIVE`, never a false benign.
- **Multi-Vector Inspection:** Analyzes URLs across 5 parallel vectors in sub-second time:
  1. Lexical & Punycode Homoglyph Analysis
  2. Domain Impersonation & TLD Risk Profiling
  3. Cryptographic TLS/SSL Certificate Verification
  4. Web Security, DOM Inspection & BIP-39 Seed-Phrase Harvesting Detection
  5. Tranco Top-10K Domain Intelligence & Global Reputation Feeds
- **Explainable Verdicts:** Generates transparent risk scores (0–100) mapped to MITRE ATT&CK tactics, actionable findings, and defense-in-depth posture observations.

---

## 2. Quick Demo Setup & Health Check

Ensure all three platform services are active before presenting:

```bash
# 1. Verify Mongo, Scanner, and Web Gateway Health
curl -s http://localhost:8001/health | jq .status
# Expected: "healthy"

curl -s http://localhost:8000/api/v1/health | jq .status
# Expected: "healthy"
```

Open the web interface in your browser:
**URL:** [http://localhost:3000](http://localhost:3000)

---

## 3. The 5 Live Demonstration Scenarios

SENTRIX supports five distinct verdict states. Follow these steps during the live demo:

### Scenario 1: BENIGN — Legitimate High-Reputation Platform

* **Objective:** Demonstrate that SENTRIX correctly recognizes legitimate portals without false positives, leveraging Tranco Top-10K domain intelligence and TLS auditing.
* **Target URL:** `https://python.org` (or `https://github.com/login`)
* **How to Run in Web UI:**
  1. Navigate to `/scanner` (or use the hero input on the home page).
  2. Enter `https://python.org` and click **Analyze Threat**.
  3. Watch the scan transition from `QUEUED` &rarr; `PROCESSING` &rarr; `COMPLETED` in real time.
* **CLI cURL Alternative:**
  ```bash
  curl -s -X POST http://localhost:8000/api/v1/scans \
    -H "Content-Type: application/json" \
    -d '{"url": "https://python.org"}' | jq .
  ```
* **Expected Outcome:**
  * **Verdict:** `BENIGN` (Green Badge)
  * **Risk Score:** ~15/100 (bounded defense-in-depth posture findings only)
  * **Confidence:** &ge; 90%
  * **Analysis Status:** `COMPLETE` (All 5 analyzers report `SUCCESS`)
  * **Key Findings:** Authentic domain verification, valid Let's Encrypt / DigiCert certificate, zero active malicious indicators.

---

### Scenario 2: SUSPICIOUS — Ambiguous Affiliate & Heuristic Anomaly

* **Objective:** Show how SENTRIX detects risky heuristic patterns (suspicious query parameters, high-risk TLDs, redirect evasion) before a full weaponized payload is confirmed.
* **Target URL:** `https://smart-shopper-coupon-finder.xyz/bounce?coupon=99`
* **Expected Outcome:**
  * **Verdict:** `SUSPICIOUS` (Amber Badge)
  * **Risk Score:** 45–60/100
  * **Analysis Status:** `COMPLETE`
  * **Key Findings:** High-risk TLD (`.xyz`), deceptive tracking/redirect query parameters, lack of established brand identity.
  * **Analyst Advisory:** Prompts elevated attention and sandboxed review before navigating.

---

### Scenario 3: MALICIOUS — Credential Harvesting & Brand Impersonation

* **Objective:** Demonstrate detection of an active credential harvesting campaign targeting enterprise single sign-on (SSO).
* **Target URL:** `http://microsoft-online-recovery.net/office365/login.htm`
* **Expected Outcome:**
  * **Verdict:** `MALICIOUS` (Red Badge)
  * **Risk Score:** 85–100/100
  * **Confidence:** 95%+
  * **MITRE ATT&CK Tactics:** `Reconnaissance`, `Initial Access`, `Credential Access`
  * **Key Findings:**
    * **Brand Impersonation:** Detected unauthorized use of `Microsoft / Office365` trademark in an unverified domain.
    * **Insecure Form Submission:** Login form submitting credentials over cleartext HTTP.
    * **Suspicious Path Structure:** Phishing path imitating corporate password recovery.

---

### Scenario 4: UNVERIFIED_INFRASTRUCTURE — Parked / Cold Hosting

* **Objective:** Demonstrate Phase 7.3's defensive classification. Parked domains and low-reputation staging sites that lack malicious payloads are NOT marked benign, nor are they falsely flagged as active threats.
* **Target URL:** `http://fast-content-delivery-cdn-test.club`
* **Expected Outcome:**
  * **Verdict:** `UNVERIFIED_INFRASTRUCTURE` (Cyan/Indigo Informational Badge)
  * **Risk Score:** 15–25/100
  * **Analysis Status:** `COMPLETE`
  * **Key Findings:** Parked or placeholder domain page indicators, absence of production TLS certificate, non-authoritative hosting.
  * **Value Proposition:** Prevents analysts from treating unverified throwaway infrastructure as trusted corporate assets.

---

### Scenario 5: INCONCLUSIVE — Zero-Trust Fail-Safe Under Network Anomaly

* **Objective:** Prove the core zero-trust security invariant: **Incomplete or unreachable analysis NEVER defaults to clean.**
* **Target URL:** `http://192.0.2.1/test` (or internal loopback `http://127.0.0.1:8000/api`)
* **Expected Outcome:**
  * **For loopback/private IPs:** Immediate HTTP 400 rejection via `SSRFGuard` with message `Target destination violated perimeter safety policies`.
  * **For unreachable hosts:** The scan completes with `verdict: "INCONCLUSIVE"` and `analysisStatus: "PARTIAL"`, warning the user that safety could not be verified due to unreachable analyzers.

---

## 4. Touring Platform Features

After demonstrating URL scanning, walk judges through the rest of the application:

1. **Investigation Report View (`/reports/:id`):**
   * **Categorized Findings Breakdown:** Filter by Critical, High, Medium, Low, and Info.
   * **Cryptographic TLS Audit:** View leaf certificate subject, issuer, serial, SANs, and validity period.
   * **Raw Evidence Payloads:** Expand each finding to inspect raw HTTP headers, DOM fixtures, and token matches.
2. **Global Threat Dashboard (`/dashboard`):**
   * Real telemetry aggregated directly from MongoDB.
   * Total Scans Conducted, Threat Detection Rate, Average Risk Score.
   * Breakdown of threats by category (Impersonation, Phishing, TLS Weaknesses).
3. **Community Threat Hub (`/community`):**
   * Crowdsourced URL threat submissions.
   * Real-time community upvoting with IP-based rate limiting (20 votes/min).
   * Search and filter by domain or status.

---

## 5. Offline Fallback Procedure (If Conference Internet Drops)

If network connectivity fails during presentation, SENTRIX includes an offline benchmark evaluation harness that tests against deterministic, curated datasets without requiring internet egress:

```bash
# Run the 80-case development benchmark harness:
cd services/scanner
.venv/bin/python benchmarks/evaluate.py --dataset dataset_dev.json --output demo_report.json

# View high-level metrics summary:
# 100% Threat Detection Binary F1 (TP=45, FN=0)
# 0.00% False Positive Rate on Legitimate Sites
# P50 Latency: < 100 ms
```

Pre-scanned historical cases remain accessible locally in the web dashboard at `http://localhost:3000/history`.

---

## 6. Judge FAQ & Talking Points

* **Q: How does SENTRIX differ from VirusTotal or Google Safe Browsing?**  
  * *A:* VirusTotal and GSB are primarily reactive blacklists. When a phisher registers a new domain and sends lures, it can take 12–48 hours for blacklists to flag it. SENTRIX inspects lexical structure, DOM form actions, TLS certificates, and cryptographic entropy on the wire, catching zero-day phishing attacks on their first encounter.
* **Q: How do you prevent false positives on corporate login pages?**  
  * *A:* Through Tranco Top-10K domain intelligence and contextual risk weighting (CAL-01 & CAL-02). Legitimate SaaS authentication portals (Google, Atlassian, Docker) are validated as authentic brand owners, preventing legitimate credential forms from being misclassified as phishing.
* **Q: Is the scanner safe to run against weaponized sites?**  
  * *A:* Yes. SENTRIX features strict SSRF protection (blocking RFC 1918, link-local, loopback, and cloud metadata addresses), connection-time IP pinning to defeat DNS rebinding, streaming body limits (2 MB maximum), and inert parsing via BeautifulSoup without executing client-side scripts.
