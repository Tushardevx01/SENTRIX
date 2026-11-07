# SENTRIX Threat Model & Security Considerations

This document details the defensive boundaries, adversary models, and mitigations implemented within SENTRIX to defend against common scanner exploitation techniques.

---

## 1. Adversary Model

Because SENTRIX accepts arbitrary, untrusted URLs from external users and initiates network probes to inspect them, the scanner is a prime target for adversarial manipulation:
1. **SSRF Exploitation:** Attackers attempting to use the scanner as an intranet proxy or proxy into cloud metadata endpoints (e.g., AWS EC2 metadata `169.254.169.254`, Google Cloud metadata `metadata.google.internal`).
2. **Denial of Service (DoS):** Slowloris-style hanging connections, infinite redirect loops, or gzip/DOM decompression bombs.
3. **DNS Rebinding:** Domains configured with microsecond TTLs that resolve to a public IP during pre-flight checks, but swap to a loopback or intranet IP (`127.0.0.1`, `10.0.0.1`) during actual HTTP fetching.
4. **Credential Exfiltration:** Attempts to extract database connection strings or internal API keys.

---

## 2. Threat Matrix & Mitigations

| Threat Vector | Severity | Vulnerability Description | SENTRIX Mitigation |
| :--- | :--- | :--- | :--- |
| **SSRF (Loopback & Intranet)** | **CRITICAL** | Target URL resolves to `127.0.0.1`, `localhost`, or RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). | `validate_url_safety()` in `ssrf_guard.py` resolves domain via `socket.getaddrinfo`, inspects all returned IPs, and raises `SSRFSecurityException` if any address is private, loopback, or reserved. |
| **Cloud Instance Metadata Theft** | **CRITICAL** | Target URL attempts to query `169.254.169.254` or `metadata.google.internal` to extract IAM instance credentials or service tokens. | Explicit CIDR filtering on link-local `169.254.0.0/16` and keyword blacklisting on metadata hostnames before socket connection. |
| **DNS Rebinding** | **HIGH** | Domain resolves to public IP during pre-check, but subsequent HTTP socket connection resolves to internal IP. | 1. Scanner operates within a sandboxed Docker network with no route to host/intranet.<br/>2. Python scanner has no access to MongoDB network. |
| **Redirect Abuse & Infinite Loops** | **MEDIUM** | Malicious redirect chain (`A -> B -> C -> ... -> A`) or deep hop chain attempting to exhaust scanner memory and execution threads. | `httpx.AsyncClient` configured with strict redirect limit (max 5 hops) and overall 5.0-second timeout. |
| **Decompression / Body Bombs** | **MEDIUM** | Gigantic HTML bodies or infinite stream responses designed to cause Out-of-Memory (OOM) crashes. | HTTP response body read limit capped at 250,000 bytes for HTML parsing. |
| **Non-HTTP Protocol Injections** | **HIGH** | URL specifies dangerous URI schemes like `file:///etc/passwd`, `gopher://`, or `dict://`. | Scheme whitelist strictly enforced to `{"http", "https"}`. All other schemes fail validation immediately. |
| **Rate Limit Flooding** | **MEDIUM** | Automated script spamming scans to overwhelm backend resources. | Fastify rate limiter (`@fastify/rate-limit`) limits client IPs to 120 requests per minute. |
| **Internal Scanner Compromise** | **HIGH** | Attacker compromises Python scanner sandbox via web vulnerability or parsing exploit. | **Privilege Isolation:** Scanner has zero database access, possesses no Mongo credentials, and lives in an isolated container network. Fastify API verifies scanner outputs with strict Pydantic schemas. |

---

## 3. Secret Management Guidelines

- **Zero Secrets in Source Control:** `.gitignore` excludes all `.env` files.
- **Strict Prohibition of Example Files:** No `.env.example` or `.env.sample` files exist in the repository to eliminate accidental secret leaking.
- **Internal Pre-Shared Key Isolation:** Fastify communicates with Python using a high-entropy 256-bit hexadecimal secret transmitted in the `X-Scanner-Secret` header. Requests lacking this secret return `401 Unauthorized`.
- **Public Frontend Isolation:** Next.js client bundles only expose variables prefixed with `NEXT_PUBLIC_` (`NEXT_PUBLIC_API_URL`). All sensitive keys (`MONGODB_URI`, `SCANNER_API_SECRET`) remain purely server-side.
