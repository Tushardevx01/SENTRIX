# SENTRIX Scanner Benchmark & Evaluation Suite

This directory contains the reproducible benchmark datasets, offline test harness, metric computation engine, and evaluation runner for the SENTRIX URL threat detection engine.

## Invariant Safety Rules

- **Zero Network Egress to Malicious Infrastructure**: Benchmarks execute 100% offline using deterministic mock contexts (recorded TLS certificates, HTTP response headers, and DOM trees).
- **Unmodified Production Scanner Pipeline**: The evaluation harness invokes the real production analyzers (`UrlAnalyzer`, `DomainAnalyzer`, `TlsAnalyzer`, `WebSecurityAnalyzer`, `ReputationAnalyzer`) and the real `RiskAggregationEngine.evaluate()`. No approximation or duplicate scoring logic is used.
- **Strict Separation of Train / Dev / Validation Corpora**: The 80-case development dataset (`dataset_dev.json`) is kept isolated from the 25-case independent validation corpus (`dataset_val.json`).

---

## Datasets

### 1. Development Dataset (`dataset_dev.json`) - 80 Cases
Structured across 8 security categories:
1. `BENIGN_LEGITIMATE` (15 cases): Top-tier global websites (Tranco top 1k) with complete defense-in-depth headers and valid certificates.
2. `BENIGN_LEGACY_HEADERS` (10 cases): Harmless public websites (libraries, local businesses, community organizations) with older web server configurations lacking modern headers.
3. `BENIGN_AUTH_PORTALS` (10 cases): Legitimate sign-in, login, and single sign-on endpoints on recognized platforms.
4. `CONFIRMED_PHISHING_CREDENTIAL_HARVESTING` (12 cases): Active phishing kits, credential harvesting forms posting to external hosts, webhook exfiltration (Discord, Telegram), and financial harvesting.
5. `TYPOSQUATTING_HOMOGLYPHS` (10 cases): Punycode IDN homoglyphs and leetspeak substitutions targeting recognized brands.
6. `BRAND_IMPERSONATION_SUBDOMAIN_STACKING` (10 cases): Fake subdomain hierarchies and brand keyword stuffing across untrusted or high-risk TLDs.
7. `MALICIOUS_REDIRECTS_EVASIONS` (8 cases): Userinfo `@` authority masking, meta refresh redirects to external destinations, raw numeric IP hosts, and hidden iframe drops.
8. `CERTIFICATE_TLS_ANOMALIES` (5 cases): Expired certificates, self-signed certificates, revoked/distrusted CAs (WoSign, DigiNotar), CA:TRUE in subscriber leaf, and SC-081v3 validity duration violations.

### 2. Validation Dataset (`dataset_val.json`) - 25 Cases
An independent, non-overlapping verification corpus covering all 8 security categories with distinct domain names and URLs.

---

## Running the Evaluation

To evaluate against the development dataset:
```bash
# Baseline evaluation
python benchmarks/evaluate.py --dataset dataset_dev.json --output baseline_dev_report.json

# Calibrated evaluation (Phase 6.3)
python benchmarks/evaluate.py --dataset dataset_dev.json --output calibrated_dev_report.json
```

To evaluate against the independent validation dataset:
```bash
# Baseline evaluation
python benchmarks/evaluate.py --dataset dataset_val.json --output baseline_val_report.json

# Calibrated evaluation (Phase 6.3)
python benchmarks/evaluate.py --dataset dataset_val.json --output calibrated_val_report.json
```

---

## Metrics Computed

- **3x3 Multi-Class Confusion Matrix**: Ground truth vs predicted verdicts across `BENIGN`, `SUSPICIOUS`, `MALICIOUS`.
- **Per-Class Metrics**: True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN), Precision, Recall, F1-Score, and Support.
- **Aggregate Metrics**: Overall Accuracy, Macro-Averaged F1, Weighted-Averaged F1.
- **Binary Threat Metrics**:
  - Positive Class: `SUSPICIOUS` or `MALICIOUS` (Threat detected)
  - Negative Class: `BENIGN` (Safe)
  - Reports Precision, Recall (Sensitivity), Specificity, F1, False Positive Rate (FPR), False Negative Rate (FNR).
- **Latency Distribution**: Mean, Minimum, Maximum, P50, P90, P99 execution time per scan case.
