# SENTRIX Threat Model & Security Considerations

This document details the defensive boundaries, adversary models, and mitigations implemented within SENTRIX to defend against common scanner exploitation techniques.

---

## 1. Adversary Model

Because SENTRIX accepts arbitrary, untrusted URLs from external users and initiates network probes to inspect them, the scanner is a prime target for adversarial manipulation:
1. **SSRF Exploitation:** Attackers attempting to use the scanner as an intranet proxy or proxy into cloud metadata endpoints (e.g., AWS EC2 metadata `169.254.169.254`, Google Cloud metadata `metadata.google.internal`, or private subnets).
2. **DNS Rebinding (TOCTOU):** Domains configured with microsecond TTLs that resolve to a public IP during pre-flight checks, but swap to a loopback or intranet IP (`127.0.0.1`, `10.0.0.1`) during actual HTTP socket connection.
3. **Redirect Pivoting:** Public initial URL redirecting (via 301/302) to restricted internal resources or cloud metadata.
4. **Denial of Service (DoS):** Slowloris-style hanging connections, infinite redirect loops, or memory exhaustion via streaming infinite payloads / decompression bombs.
5. **False Negative Manipulation:** Intentionally failing network probes or TLS handshakes to trick naive security systems into declaring uninspected targets "clean" or `BENIGN`.
6. **Data Leakage / Internal Infrastructure Enumeration:** Extracting database credentials, internal service endpoints, or stack traces through verbose error responses.

---

## 2. Threat Matrix & Mitigations (Security Hardening v1)

| Threat Vector | Severity | Vulnerability Description | SENTRIX Mitigation |
| :--- | :--- | :--- | :--- |
| **SSRF (Loopback & Intranet)** | **CRITICAL** | Target URL resolves to `127.0.0.1`, `localhost`, RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), or link-local IPv6. | `validate_url_safety()` in `ssrf_guard.py` resolves domain via `socket.getaddrinfo`, inspects all returned A and AAAA records, and raises `SSRFSecurityException` if any address belongs to reserved, private, or multicast ranges. Embedded credentials (`user:pass@`) and non-standard schemes/ports are strictly rejected. |
| **Cloud Metadata Exfiltration** | **CRITICAL** | Target URL attempts to query `169.254.169.254` or `metadata.google.internal` to extract IAM instance credentials or tokens. | Explicit CIDR filtering on link-local `169.254.0.0/16` and keyword blacklisting on metadata hostnames before any socket connection. |
| **DNS Rebinding (TOCTOU)** | **CRITICAL** | Attacker domain passes pre-flight DNS check with a benign public IP, then returns `127.0.0.1` upon subsequent HTTP connect. | **Connection-Time IP Pinning (`PinnedIPNetworkBackend`):** Overrides `httpcore.AnyIOBackend.connect_tcp` to connect directly to the pre-validated IP while passing `server_hostname` to TLS `start_tls`. This binds the physical connection to the verified IP while preserving full SNI and certificate validation. |
| **Redirect SSRF Bypass & Loops** | **HIGH** | URL redirects to private networks or loops indefinitely (`A -> B -> A`). | **Controlled Manual Redirects:** Automatic client redirects disabled (`follow_redirects=False`). Redirect loop explicitly bounds hops to 5, detects loops via `seen_urls`, and executes full SSRF pre-flight validation on every redirect hop before following. |
| **Response Memory Exhaustion (OOM)** | **HIGH** | Massive responses or infinite streams designed to exhaust scanner memory. | **Bounded Streaming Read:** Reads response body using `stream_resp.aiter_bytes(chunk_size=16384)` with a hard 1 MB (1,048,576 byte) ceiling. Stream stops immediately once reached, sets `isTruncated = True`, and logs a forensic security finding. |
| **Insecure TLS Fallback** | **HIGH** | Disabling certificate validation (`verify=False`) to permit scans of broken HTTPS targets, exposing the scanner to MITM attacks. | **Strict TLS Invariant:** `verify=True` strictly enforced on all HTTP clients. Hostname verification and trusted CA requirements are mandatory (`CERT_REQUIRED`). Broken certs are forensically inspected and flagged with CRITICAL/HIGH findings without downgrading security. |
| **False-Negative "Benign" Verdicts** | **HIGH** | Incomplete analyses (e.g. host unreachable, TLS handshake failure, probe timeout) defaulting to a `BENIGN` score due to absence of findings. | **Zero-Trust Inconclusive Classification:** Incomplete or failed scans with risk score < 26 are assigned `INCONCLUSIVE` (never `BENIGN`). Confidence is penalised, explicit `inconclusiveReasons` are persisted, and the UI displays a warning banner. |
| **ReDoS & Query Injection** | **MEDIUM** | Malicious regex patterns in domain search or threat feed query parameters causing denial of service or unexpected match behavior in MongoDB. | **Input Sanitization:** Fastify routes escape all user regex queries via `escapeRegex()` and clamp pagination parameters via `sanitizePagination()` (`skip >= 0`, `limit <= 100`). |
| **Information Leakage via Errors** | **MEDIUM** | Unhandled 500 errors or internal scanner connection exceptions leaking database URIs, connection strings, or internal infrastructure details. | **Sanitized Central Error Handler:** Fastify error handler redacts all 500 error messages to generic text, suppresses internal details, and logs full diagnostics internally with correlation IDs. |
| **Timing Attacks on API Secret** | **LOW** | Remote attacker inferring scanner API secret bytes via response latency differences. | **Constant-Time Secret Comparison:** Scanner authenticates `X-Scanner-Secret` using `secrets.compare_digest`. |
| **Rate Limit Flooding** | **MEDIUM** | Automated script spamming scans to overwhelm backend resources. | Fastify rate limiter (`@fastify/rate-limit`) limits client IPs to 120 requests per minute. Restricted `trustProxy` CIDRs prevent header spoofing. |
| **Internal Scanner Compromise** | **HIGH** | Attacker compromises Python scanner sandbox via web vulnerability or parsing exploit. | **Privilege Isolation:** Scanner has zero database access, possesses no Mongo credentials, runs as unprivileged user (`appuser`), and lives in an isolated container network. |

---

## 3. Secret Management Guidelines

- **Zero Secrets in Source Control:** `.gitignore` excludes all `.env` files.
- **Strict Prohibition of Example Files:** No `.env.example`, `.env.sample`, or nested `.env` files exist in the repository to eliminate accidental secret leaking. Exactly one root `/.env` manages the entire deployment.
- **Internal Pre-Shared Key Isolation:** Fastify communicates with Python using a high-entropy 256-bit hexadecimal secret transmitted in the `X-Scanner-Secret` header, verified via `secrets.compare_digest`.
- **Public Frontend Isolation:** Next.js client bundles only expose variables prefixed with `NEXT_PUBLIC_` (`NEXT_PUBLIC_API_URL`). All sensitive keys (`MONGODB_URI`, `SCANNER_API_SECRET`) remain purely server-side.
