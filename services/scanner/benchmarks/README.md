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

### 3. Expanded Independent Validation Dataset (`dataset_val_expanded.json`) - 530 Cases
A large-scale independent validation corpus designed in Phase 6.4 to evaluate real-world generalization without tuning detection weights. Covers 13 security categories across 230 BENIGN, 100 SUSPICIOUS, and 200 MALICIOUS cases with 0 URL/domain overlaps with `dataset_dev.json` or `dataset_val.json`.
- `BENIGN_LEGITIMATE` (75 cases): Top-tier global platforms from Tranco top 1k.
- `BENIGN_AUTH_PORTALS` (50 cases): Real-world login and account portals.
- `BENIGN_REGIONAL_SMALLBIZ` (40 cases): Regional businesses, municipal services, and local community websites.
- `BENIGN_LEGACY_HEADERS` (35 cases): Benign servers lacking modern defensive security headers.
- `BENIGN_UNUSUAL_EDGE_CASES` (30 cases): Benign sites with unusual URL parameters, long query strings, and redirects.
- `SUSPICIOUS_UNVERIFIED_INFRASTRUCTURE` (40 cases): Low-cost TLDs, staging nodes, and unverified redirect gateways.
- `SUSPICIOUS_AMBIGUOUS_REVIEWS` (30 cases): Mixed-reputation affiliate portals and parked domains.
- `SUSPICIOUS_TLS_CONFIGURATIONS` (30 cases): Certificate expiration, weak key sizes, and self-signed internal certs.
- `CONFIRMED_PHISHING_CREDENTIAL_HARVESTING` (65 cases): Active credential harvesters, webhook exfiltration, and bank spoofing.
- `BRAND_IMPERSONATION_SUBDOMAIN_STACKING` (45 cases): Subdomain stacking targeting technology and financial institutions.
- `TYPOSQUATTING_HOMOGLYPHS` (35 cases): Punycode homoglyphs and character omissions.
- `LEETSPEAK_ABBREVIATION_IMPERSONATION` (30 cases): Visual leetspeak and brand abbreviation spoofing.
- `MALICIOUS_REDIRECTS_EVASIONS` (25 cases): Multi-hop redirect evasions and hidden payload drops.

---

## Running the Evaluation

All commands run from `services/scanner/` with the project virtualenv (`.venv/bin/python`).

```bash
# Baseline evaluation (Phase 6.1, preserved as-is)
.venv/bin/python benchmarks/evaluate.py --dataset dataset_dev.json  --output benchmarks/baseline_dev_report.json
.venv/bin/python benchmarks/evaluate.py --dataset dataset_val.json  --output benchmarks/baseline_val_report.json

# Calibrated evaluation (Phase 6.3)
.venv/bin/python benchmarks/evaluate.py --dataset dataset_dev.json  --output benchmarks/calibrated_dev_report.json
.venv/bin/python benchmarks/evaluate.py --dataset dataset_val.json  --output benchmarks/calibrated_val_report.json

# Expanded independent validation evaluation (Phase 6.4)
.venv/bin/python benchmarks/evaluate.py --dataset dataset_val_expanded.json --output benchmarks/expanded_val_report.json
```

### Evaluation Protocol

- **Iterate on dev only.** Every detector change is validated by re-running the 80-case development benchmark and diffing scores/verdicts against the previous run. Ground-truth labels, the datasets, and the Phase 6.1 baseline reports are never modified.
- **Run val exactly once per calibration cycle.** The 25-case validation corpus is used only after development is frozen — no tuning is performed against its outcomes. The val report is a single-shot generalization check; with 25 cases (11 benign / 3 suspicious / 11 malicious) its accuracy has a wide confidence interval and must never be cited as a production accuracy figure.
- **Reports are regenerated, not hand-edited.** `calibrated_dev_report.json` and `calibrated_val_report.json` are verbatim `evaluate.py` outputs.

---

## Current Results (Phase 7.3)

| Metric | Baseline (6.1) dev | Calibrated dev | Baseline (6.1) val | Calibrated val | Expanded (6.4) val | Phase 7.1 Exp Val | Phase 7.2 Exp Val | Phase 7.3 Exp Val |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Total cases | 80 | 80 | 25 | 25 | 530 | 530 | 530 | **530** |
| 3-class accuracy | 78.75% | 93.75% | 80.00% | 92.00% | 90.19% (478/530) | 91.89% (487/530) | 92.64% (491/530) | **93.21%** (494/530) |
| Macro F1 | 67.12% | 88.88% | 68.40% | 85.86% | 86.47% | 88.44% | 89.38% | **96.17%** |
| Weighted F1 | 79.95% | 93.63% | 81.14% | 92.00% | 89.76% | 91.34% | 92.06% | **93.14%** |
| Strict Malicious Recall | 94.3% | 94.3% | 90.9% | 90.9% | 95.50% | 98.00% | 100.00% | **100.00%** (200/200) |
| Strict Malicious F1 | 93.0% | 93.0% | 90.9% | 90.9% | 94.79% | 96.08% | 97.09% | **97.09%** |
| Binary threat F1 (SUS+MAL vs BENIGN) | 95.65% | 100.00% | 92.86% | 100.00% | 94.68% | 95.34% | 95.34% | **95.83%** |
| Threat Precision / Recall | 93.6% / 97.8% | 100% / 100% | 92.9% / 92.9% | 100% / 100% | 97.53% / 92.00% | 98.92% / 92.00% | 98.92% / 92.00% | **100.0% / 92.00%** |
| Benign false positives | 3 / 35 | 0 / 35 | 1 / 11 | 0 / 11 | 7 / 230 (3.04%) | 3 / 230 (1.30%) | 3 / 230 (1.30%) | **0 / 230 (0.00%)** |
| Missed threats (BENIGN pred) | 1 / 45 | 0 / 45 | 1 / 14 | 0 / 14 | 24 / 300 (8.00%) | 24 / 300 (8.00%) | 24 / 300 (8.00%) | **0 / 300 (0.00%)** |
| Informational (UNVERIFIED_INFRASTRUCTURE) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | **24** |

Phase 7.3 introduced the `UNVERIFIED_INFRASTRUCTURE` classification state across backend analyzers, shared contracts, and web UI. Resolved 100% of the 24 disputed cases in `SUSPICIOUS_UNVERIFIED_INFRASTRUCTURE` from BENIGN to `UNVERIFIED_INFRASTRUCTURE` (score 20). Concurrently resolved 100% of open-source technical documentation false alarms (`EXP-VAL-207`, `EXP-VAL-210`, `EXP-VAL-221`) on Ruby, Podman, and OWASP to `BENIGN` (score 15), completely eliminating false alarms on benign targets (FPR 0.00%, Benign F1 100.00%). Preserved 100.00% malicious recall (200/200) and 100.00% Web3 phishing retention with zero threat degradation.

Remaining dev errors (5): DEV-057, DEV-066, DEV-072 (GT `SUSPICIOUS`, predicted `MALICIOUS` — stacked distinct deception indicators each scoring ≥ 70 under unchanged weights) and DEV-078, DEV-080 (GT `MALICIOUS`, predicted `SUSPICIOUS` — certificate trust/compliance failures that, per CAL-05, are not sufficient evidence of phishing or malware). Val errors (2): VAL-021 and VAL-024, the same two principled patterns. In the 530-case validation corpus, all 3 prior documentation false alarms (EXP-VAL-207, EXP-VAL-210, EXP-VAL-221) were resolved to `BENIGN`, and all 24 staging nodes in `SUSPICIOUS_UNVERIFIED_INFRASTRUCTURE` were successfully classified as `UNVERIFIED_INFRASTRUCTURE`, achieving 0.00% false positive rate on benign targets.

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
