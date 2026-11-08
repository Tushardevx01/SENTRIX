# SENTRIX Detection Scoring & Calibration

This document describes how the SENTRIX scanner turns analyzer findings into a
risk score and verdict, how Phase 6.3 evidence-based calibration shaped that
pipeline, and what the measured benchmark results — and their limits — are.

Companion documents: `ARCHITECTURE.md` §9 (scoring architecture),
`services/scanner/benchmarks/README.md` (benchmark methodology).

---

## 1. Scoring Model

Severity weights (unchanged since Phase 3; **never modified during calibration**):

| Severity | Weight |
| :--- | :---: |
| `CRITICAL` | +40 |
| `HIGH` | +25 |
| `MEDIUM` | +12 |
| `LOW` | +5 |
| `INFO` | +0 |

Posture findings (missing defense-in-depth headers, server banner disclosure,
missing embedded leaf SCTs) are summed separately and **capped at 15 points**
(CAL-01). Threat findings are deduplicated per stable key (CAL-06) before
summing. The total is clamped to `[0, 100]`.

Verdict thresholds (unchanged):

| Range | Verdict |
| :--- | :--- |
| `0 – 25` | `BENIGN` (only when analysis is `COMPLETE`) |
| `26 – 69` | `SUSPICIOUS` |
| `70 – 100` | `MALICIOUS` |
| any score, analysis `PARTIAL`/`FAILED` | `INCONCLUSIVE` (zero-trust: missing analyzers are never proof of safety) |

## 2. Calibration Rules (CAL-01 … CAL-06)

- **CAL-01 — Posture ceiling.** Missing HSTS/CSP/XFO/XCTO/Referrer-Policy,
  server banner leaks, and missing embedded SCTs can contribute at most 15
  points in aggregate; posture alone can never reach `SUSPICIOUS` (≥ 26).
- **CAL-02 — Authentic-domain context.** PSL-aware (`tldextract`) registered
  domains are checked against a recognized authentic registry; ordinary
  auth-path keyword penalties are suppressed only on authentic domains that
  are free of punycode, userinfo masking, and subdomain stacking.
  Subdomain-stacked attacker domains (`paypal.com.attacker.example`) are never
  trusted.
- **CAL-03 — Evidence-based hostname matching.** No substring trust decisions:
  token/compound matching, IDNA decoding, Unicode confusable skeletons,
  hyphen-window joins (`wells-fargo-alert` → `wellsfargo`), financial
  abbreviations (`b0fa` → BofA), and corroboration-gated bounded token edit
  distance (≤4 chars exact; 5–8 → distance 1; ≥9 → distance 2; plural guard;
  requires high-risk TLD / punycode / leet digits / auth-context corroboration).
  Token-only keywords (`phish`) match complete tokens only. Brand domains are
  never blanket-trusted; `isbilling.com` ≠ SBI, `simplicity.org` ≠ Citi,
  `revolute.com`/`stripes.com`/`chases.com` are clean.
- **CAL-04 — Controlled normalization.** Ambiguous leet substitutions
  (`1` → `l/i/t`, `0` → `o`, `5` → `s`) are generated per token with a
  16-candidate cap — never a global substitution map — so ordinary English is
  unaffected. Every finding preserves the original domain in evidence alongside
  normalized forms (`idnaDecodedDomain`, `confusableSkeleton`, `matchMethod`).
- **CAL-05 — Corroborated severity.** `<meta http-equiv="refresh">` is `CRITICAL`
  only with corroborating indicators (high-risk TLD or credential/exfil-style
  path); an unknown destination alone is never malicious. Hostile redirect
  targets and hidden-iframe sources additionally emit a `HIGH` destination
  finding; concealed iframes loading hostile payloads escalate to `CRITICAL`.
  Distrusted-CA verdicts require chain evidence — issuer-string spoofing on a
  self-signed certificate is not a genuine distrusted issuer, and certificate
  trust/compliance failures alone never yield `MALICIOUS`.
- **CAL-06 — Stable deduplication with provenance.** Findings carry stable
  dedup keys; the risk engine keeps the highest-severity finding per key so
  overlapping observations are counted once, while the report retains every raw
  finding. Each finding's `evidence["analyzer"]` is stamped at collection time.

### Dedup key registry

| Key | Findings it unifies |
| :--- | :--- |
| `HOST_RAW_IP` | Raw-IP host warnings (url analyzer's direct-IP finding; a shared identity any other analyzer's IP-host warning joins) |
| `DECEPTIVE_HOSTNAME:<host>` | Hostname-only keyword findings + gov/academic/recruitment/brand hostname findings for the same host |
| `HOSTILE_DESTINATION:<host>` | Hostile-destination findings from meta-refresh, hidden-iframe, and other redirect mechanisms for the same destination |
| `HIDDEN_IFRAME` | Hidden-iframe concealment observation + hostile-payload escalation |
| `POSTURE_*` | Per-header posture observations (also capped at 15 in aggregate) |
| `CATEGORY:title` (fallback) | Same-title findings within one category |

## 3. Measured Results

All numbers are verbatim outputs of `benchmarks/evaluate.py` against the
preserved Phase 6.1 baseline reports; datasets and ground-truth labels were
never modified.

### Development set (80 cases — iterate-only corpus)

| Metric | Baseline 6.1 | Phase 6.3 final |
| :--- | :---: | :---: |
| 3-class accuracy | 78.75% | **93.75%** |
| Macro F1 | 67.12% | **88.88%** |
| Weighted F1 | 79.95% | **93.63%** |
| Binary threat F1 | 95.65% | **100.00%** |
| Benign FP | 3 / 35 | **0 / 35** |
| Threats missed as BENIGN | 1 / 45 | **0 / 45** |
| Latency (mean / p50 / p99) | 137.3 / 108.2 / 392.7 ms | 136.8 / 114.0 / 233.0 ms |

Per-class (final): BENIGN P/R/F1 = 100/100/100 (support 35); SUSPICIOUS =
77.8/70.0/73.7 (support 10); MALICIOUS = 91.7/94.3/93.0 (support 35).
Confusion: 35/35 benign correct, 7/10 suspicious correct (3 → MAL), 33/35
malicious correct (2 → SUS).

### Validation set (25 cases — single run after dev freeze)

| Metric | Baseline 6.1 | Phase 6.3 final |
| :--- | :---: | :---: |
| 3-class accuracy | 80.00% | **92.00%** |
| Macro F1 | 68.40% | **85.86%** |
| Weighted F1 | 81.14% | **92.00%** |
| Binary threat F1 | 92.86% | **100.00%** |
| Benign FP | 1 / 11 | **0 / 11** |
| Threats missed as BENIGN | 1 / 14 | **0 / 14** |

### Errors fixed by this iteration (dev)

| Case | Was | Now | Fix |
| :--- | :--- | :--- | :--- |
| DEV-067 | 80 → MAL (FP) | 55 → SUS | `DECEPTIVE_HOSTNAME` dedup of hostname keyword vs gov impersonation |
| DEV-070 | 55 → SUS (FN) | 80 → MAL | hostile-destination HIGH for meta-refresh target |
| DEV-071 | 55 → SUS (FN) | 92 → MAL | destination HIGH + token-only `phish` keyword |
| DEV-074 | 27 → SUS (FN) | 80 → MAL | concealed-iframe hostile payload CRITICAL + destination HIGH |
| DEV-076 | 67 → SUS (FN) | 80 → MAL | token-only `phish` keyword raises keyword finding to HIGH |

### Remaining principled errors (not fixed by design)

- **Over-classification (GT `SUSPICIOUS`):** DEV-057 (80), DEV-066 (80),
  DEV-072 (77), VAL-021 (80) — each stacks multiple *distinct* deception
  indicators (e.g. brand typosquat + high-risk TLD + keyword stuffing) whose
  individual weights legitimately sum to ≥ 70. Collapsing them further would
  conflate distinct characteristics.
- **Under-classification (GT `MALICIOUS`):** DEV-078 (55), DEV-080 (27),
  VAL-024 (55) — certificate trust/compliance failures (distrusted CA,
  excessive validity). Per CAL-05 these are `SUSPICIOUS`-class evidence;
  promoting them to `MALICIOUS` on issuer/validity strings alone would violate
  the chain-evidence rule.

## 4. Regression Coverage

`services/scanner/tests/test_calibration_regression.py` (19 tests) pins every
calibration rule with positive and negative cases: posture ceiling, authentic
login suppression vs untrusted-domain penalties, short-brand boundaries
(`isbilling.com`, `simplicity.org` negatives; `sbi-card-verification.net`,
`wells-fargo-alert.info`, `b0fa-secure-portal.com` positives), substring-FP
removal (`revolute.com`, `stripes.com`, `chases.com`), leetspeak multi-candidate
positives, confusable-skeleton homographs, token-only `phish`, hostname dedup
key equality and engine collapse, hostile/unknown meta-refresh destinations,
hidden-iframe escalation vs benign embeds, `evaluate_hostile_destination`
corroboration, referrer-policy posture classification, and analyzer provenance
stamping.

Full verification for the phase: scanner pytest **81 passed**, API `npm test`
**69 passed**, `npm run build` clean, `docker compose config` clean.

## 5. Limitations & Guardrails

- **No threshold gaming.** Classification thresholds (26/70) and severity
  weights (40/25/12/5/0) were not altered to improve accuracy; all gains come
  from evidence quality, matching precision, and deduplication.
- **Small corpora.** 80 dev / 25 cases. The 25-case validation run has wide
  confidence intervals — its 92% must **never** be quoted as production
  accuracy.
- **Offline-by-construction benchmark.** Results rely on recorded TLS/HTTP/DOM
  mock contexts; real-world header diversity, CDN behavior, and novel attacker
  infrastructure are not represented.
- **Calibration iterated on dev only.** The validation corpus was evaluated
  once after the dev freeze; no tuning was performed against its outcomes.
- **Known residual risk.** Stacked-indicator benign-looking malicious sites and
  certificate-only malicious sites sit near the SUS/MAL boundary; future work
  should improve *corroboration evidence* (not weights) for those classes.
