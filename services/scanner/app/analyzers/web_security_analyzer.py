import time
import ssl
import socket
from urllib.parse import urlsplit, urljoin, urlparse
from typing import List, Dict, Any, Tuple, Optional, Set
import httpx
from bs4 import BeautifulSoup

from app.schemas.response import RawFinding
from app.safety.ssrf_guard import (
    validate_url_syntax_and_authority,
    resolve_and_validate_hostname,
    PinnedIPNetworkBackend,
    SSRFSecurityException,
)

MAX_RESPONSE_BYTES = 1024 * 1024  # 1 MB strictly bounded
MAX_REDIRECTS = 5
SAFE_CONTENT_TYPES = ("text/html", "application/xhtml+xml", "text/plain")


class WebSecurityAnalyzer:
    """
    Evaluates HTTP response headers, enforces SSRF-safe controlled redirects,
    performs connection-time IP pinning, validates TLS certificates,
    and applies bounded streaming DOM inspection.
    """

    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SENTRIX-ThreatScanner/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate",
        }

    async def analyze(
        self,
        target_url: str,
        normalized_domain: str,
        pinned_ip: Optional[str] = None
    ) -> Tuple[List[RawFinding], Dict[str, Any]]:
        findings: List[RawFinding] = []
        metadata: Dict[str, Any] = {
            "redirectChain": [target_url],
            "responseTimeMs": 0.0,
            "statusCode": 0,
            "finalUrl": target_url,
            "contentType": "",
            "isTruncated": False,
            "tlsVerified": True,
        }

        # Initialize connection-time IP pinning backend
        pinned_backend = PinnedIPNetworkBackend()
        start_time = time.time()

        # Step 1: Pre-flight validation of initial URL
        try:
            scheme, host, port = validate_url_syntax_and_authority(target_url)
            resolved_ip = pinned_ip
            if not resolved_ip:
                resolved_ips = resolve_and_validate_hostname(host, port)
                resolved_ip = resolved_ips[0]
            pinned_backend.pin_host(host, resolved_ip)
        except SSRFSecurityException as e:
            findings.append(RawFinding(
                category="WEB_SECURITY",
                severity="CRITICAL",
                title="Target URL Blocked by SSRF Perimeter Policy",
                description=str(e),
                evidence={"url": target_url},
                confidence=100.0,
            ))
            return findings, metadata

        # Step 2: Controlled Redirect Loop with Connection-Time Enforcement
        current_url = target_url
        seen_urls: Set[str] = {target_url}
        redirect_hops = 0
        final_response_text = ""

        transport = httpx.AsyncHTTPTransport(
            verify=True,  # STRICT TLS VERIFICATION: Never verify=False
            retries=0,
        )
        transport._pool._network_backend = pinned_backend

        timeout_config = httpx.Timeout(connect=5.0, read=5.0, write=5.0, pool=5.0)

        async with httpx.AsyncClient(
            headers=self.headers,
            transport=transport,
            timeout=timeout_config,
            follow_redirects=False,  # CONTROLLED MANUAL REDIRECTS
        ) as client:

            while True:
                response = None
                try:
                    # Stream response to enforce max body size without memory exhaustion
                    async with client.stream("GET", current_url) as stream_resp:
                        metadata["statusCode"] = stream_resp.status_code
                        resp_headers = {k.lower(): v for k, v in stream_resp.headers.items()}
                        content_type = resp_headers.get("content-type", "").lower()
                        metadata["contentType"] = content_type

                        # Handle HTTP 3xx Redirects manually
                        if stream_resp.status_code in (301, 302, 303, 307, 308):
                            location = stream_resp.headers.get("location")
                            if not location:
                                break  # 3xx without location header

                            redirect_hops += 1
                            if redirect_hops > MAX_REDIRECTS:
                                findings.append(RawFinding(
                                    category="URL_ANOMALY",
                                    severity="HIGH",
                                    title="Excessive Redirection Chain Exceeded Limit",
                                    description=f"Destination exceeded maximum permitted redirect hops ({MAX_REDIRECTS}).",
                                    evidence={"chain": metadata["redirectChain"]},
                                    confidence=90.0,
                                ))
                                break

                            next_url = urljoin(current_url, location)

                            # Check for redirect loop
                            if next_url in seen_urls:
                                findings.append(RawFinding(
                                    category="URL_ANOMALY",
                                    severity="HIGH",
                                    title="Redirect Loop Detected",
                                    description="Target destination redirected back to an already visited URL in the chain.",
                                    evidence={"loopUrl": next_url, "chain": metadata["redirectChain"]},
                                    confidence=95.0,
                                ))
                                break

                            # Validate redirect target with SSRF Guard
                            try:
                                next_scheme, next_host, next_port = validate_url_syntax_and_authority(next_url)
                                next_ips = resolve_and_validate_hostname(next_host, next_port)
                                pinned_backend.pin_host(next_host, next_ips[0])
                            except SSRFSecurityException as ssrf_err:
                                findings.append(RawFinding(
                                    category="WEB_SECURITY",
                                    severity="CRITICAL",
                                    title="Redirect to Restricted Network Blocked (SSRF)",
                                    description=f"Redirect destination '{next_url}' was blocked: {str(ssrf_err)}",
                                    evidence={"target": next_url, "chain": metadata["redirectChain"]},
                                    confidence=100.0,
                                ))
                                break

                            # Record hop and advance
                            seen_urls.add(next_url)
                            metadata["redirectChain"].append(next_url)
                            current_url = next_url
                            continue

                        # Terminal non-redirect response reached
                        metadata["finalUrl"] = current_url
                        metadata["responseTimeMs"] = round((time.time() - start_time) * 1000, 2)

                        # Header Security Analysis
                        if "strict-transport-security" not in resp_headers:
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="LOW",
                                title="Missing Strict-Transport-Security (HSTS)",
                                description="The HTTP response lacks an HSTS header, leaving users vulnerable to SSL-stripping man-in-the-middle attacks.",
                                evidence={"header": "Strict-Transport-Security"},
                                confidence=90.0,
                            ))

                        if "content-security-policy" not in resp_headers:
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="LOW",
                                title="Missing Content-Security-Policy (CSP)",
                                description="No Content-Security-Policy header was detected, increasing vulnerability to Cross-Site Scripting (XSS) and data injection.",
                                evidence={"header": "Content-Security-Policy"},
                                confidence=85.0,
                            ))

                        if "x-frame-options" not in resp_headers and "content-security-policy" not in resp_headers:
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="LOW",
                                title="Missing Clickjacking Defenses",
                                description="Neither X-Frame-Options nor CSP frame-ancestors is present to protect the site from UI redress/clickjacking.",
                                evidence={"header": "X-Frame-Options"},
                                confidence=85.0,
                            ))

                        if "x-content-type-options" not in resp_headers:
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="LOW",
                                title="Missing X-Content-Type-Options Header",
                                description="Lacks 'nosniff' directive, allowing browsers to MIME-sniff responses away from the declared content-type.",
                                evidence={"header": "X-Content-Type-Options"},
                                confidence=90.0,
                            ))

                        # Server & Technology Information Disclosure
                        server_header = resp_headers.get("server")
                        if server_header:
                            # Flag if server header leaks exact version numbers (e.g. Apache/2.4.41, nginx/1.18.0)
                            has_version = any(char.isdigit() for char in server_header) and ("/" in server_header or " " in server_header)
                            if has_version:
                                findings.append(RawFinding(
                                    category="WEB_SECURITY",
                                    severity="LOW",
                                    title="Server Header Leaks Exact Software Version",
                                    description=f"The 'Server' response header discloses precise version information ('{server_header}'), assisting attacker exploit enumeration.",
                                    evidence={"server": server_header},
                                    confidence=95.0,
                                ))

                        powered_by = resp_headers.get("x-powered-by")
                        if powered_by:
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="LOW",
                                title="X-Powered-By Header Reveals Application Framework",
                                description=f"The 'X-Powered-By' header discloses the backend execution environment ('{powered_by}').",
                                evidence={"xPoweredBy": powered_by},
                                confidence=95.0,
                            ))

                        # Bounded Streaming Body Read
                        is_html = any(safe_type in content_type for safe_type in SAFE_CONTENT_TYPES)
                        if is_html:
                            body_chunks = []
                            total_bytes = 0
                            async for chunk in stream_resp.aiter_bytes(chunk_size=16384):
                                if total_bytes + len(chunk) > MAX_RESPONSE_BYTES:
                                    allowed = MAX_RESPONSE_BYTES - total_bytes
                                    if allowed > 0:
                                        body_chunks.append(chunk[:allowed])
                                    total_bytes += allowed
                                    metadata["isTruncated"] = True
                                    findings.append(RawFinding(
                                        category="WEB_SECURITY",
                                        severity="LOW",
                                        title="HTTP Response Body Exceeded Safe Limit (1MB Truncated)",
                                        description="The target HTTP response exceeded the 1 MB security inspection ceiling and was safely truncated.",
                                        evidence={"bytesRead": total_bytes, "limit": MAX_RESPONSE_BYTES},
                                        confidence=80.0,
                                    ))
                                    break
                                body_chunks.append(chunk)
                                total_bytes += len(chunk)

                            raw_bytes = b"".join(body_chunks)
                            final_response_text = raw_bytes.decode("utf-8", errors="replace")
                        else:
                            # Non-HTML content type (e.g. binary/octet-stream, zip, image)
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="INFO",
                                title="Non-HTML Payload Detected",
                                description=f"Target returned content-type '{content_type}'; DOM parsing skipped to prevent arbitrary binary execution.",
                                evidence={"contentType": content_type},
                                confidence=95.0,
                            ))
                        break

                except httpx.ConnectError as conn_err:
                    err_str = str(conn_err)
                    if "SSLCertVerificationError" in err_str or "certificate verify failed" in err_str.lower():
                        metadata["tlsVerified"] = False
                        findings.append(RawFinding(
                            category="TLS_SECURITY",
                            severity="HIGH",
                            title="HTTPS Certificate Verification Failed",
                            description="The target HTTPS connection failed strict TLS certificate validation. Traffic cannot be verified as secure.",
                            evidence={"error": err_str, "url": current_url},
                            confidence=95.0,
                        ))
                    else:
                        findings.append(RawFinding(
                            category="WEB_SECURITY",
                            severity="INFO",
                            title="Web Endpoint Connection Failed",
                            description=f"HTTP connection to destination failed ({type(conn_err).__name__}).",
                            evidence={"error": err_str, "url": current_url},
                            confidence=75.0,
                        ))
                    break

                except (httpx.TimeoutException, socket.timeout, TimeoutError) as timeout_err:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="INFO",
                        title="HTTP Request Timed Out",
                        description=f"HTTP probe to destination timed out ({type(timeout_err).__name__}).",
                        evidence={"url": current_url},
                        confidence=70.0,
                    ))
                    break

                except httpx.RequestError as req_err:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="INFO",
                        title="HTTP Inspection Request Error",
                        description=f"Encountered network error during request: {str(req_err)}",
                        evidence={"error": str(req_err)},
                        confidence=60.0,
                    ))
                    break

        # Step 3: Parse DOM Phishing Indicators on Safe HTML Text
        if final_response_text:
            soup = BeautifulSoup(final_response_text, "html.parser")
            final_host = urlparse(metadata["finalUrl"]).hostname or normalized_domain

            # 1. Password input form analysis
            password_inputs = soup.find_all("input", attrs={"type": "password"})
            if password_inputs:
                for form in soup.find_all("form"):
                    if form.find("input", attrs={"type": "password"}):
                        action = form.get("action", "")
                        action_url = urljoin(metadata["finalUrl"], action)
                        action_parsed = urlsplit(action_url)

                        if action_parsed.hostname and action_parsed.hostname != final_host:
                            findings.append(RawFinding(
                                category="PHISHING_INDICATOR",
                                severity="CRITICAL",
                                title="Credential Form Submits to External Host",
                                description=f"A password input form targets external host '{action_parsed.hostname}' instead of destination '{final_host}'.",
                                evidence={"pageHost": final_host, "formAction": action_url},
                                confidence=95.0,
                            ))

                        if action_parsed.scheme == "http":
                            findings.append(RawFinding(
                                category="WEB_SECURITY",
                                severity="HIGH",
                                title="Insecure Form Submission (HTTP)",
                                description="A password input form submits sensitive credentials over unencrypted plain HTTP.",
                                evidence={"formAction": action_url},
                                confidence=95.0,
                            ))

            # 2. Financial & Payment Data Harvesting Form Analysis
            PAYMENT_FIELD_KEYWORDS = {"cvv", "cvc", "cardnumber", "cc-number", "card-number", "creditcard", "bankaccount", "accountnumber", "routingnumber", "ssn", "aadhaar", "pan-number"}
            EXFILTRATION_PATTERNS = ["discord.com/api/webhooks", "api.telegram.org", "formspree.io", "webhook.site", "pipedream.net"]

            for form in soup.find_all("form"):
                action = form.get("action", "")
                action_url = urljoin(metadata["finalUrl"], action).lower()
                action_parsed = urlsplit(action_url)

                # Check for third-party webhook exfiltration
                for exfil in EXFILTRATION_PATTERNS:
                    if exfil in action_url:
                        findings.append(RawFinding(
                            category="PHISHING_INDICATOR",
                            severity="CRITICAL",
                            title="Form Exfiltrates Data to Third-Party Webhook / Messaging API",
                            description=f"Form action '{action_url}' directs submitted form data to third-party relay service '{exfil}'. Commonly used by phishing kits to harvest credentials.",
                            evidence={"formAction": action_url, "exfiltrationTarget": exfil},
                            confidence=99.0,
                        ))

                # Check for sensitive payment / personal identity inputs
                inputs = form.find_all(["input", "select"])
                harvested_fields = []
                for inp in inputs:
                    name_attr = (inp.get("name") or "").lower()
                    id_attr = (inp.get("id") or "").lower()
                    auto_attr = (inp.get("autocomplete") or "").lower()
                    placeholder_attr = (inp.get("placeholder") or "").lower()
                    combined_attrs = f"{name_attr} {id_attr} {auto_attr} {placeholder_attr}"

                    for kw in PAYMENT_FIELD_KEYWORDS:
                        if kw in combined_attrs:
                            harvested_fields.append(kw)

                if harvested_fields:
                    findings.append(RawFinding(
                        category="PHISHING_INDICATOR",
                        severity="CRITICAL" if ("cvv" in harvested_fields or "cardnumber" in harvested_fields) else "HIGH",
                        title="Payment / Financial Credential Harvesting Form Detected",
                        description=f"Detected form collecting payment or sensitive identity markers ({', '.join(set(harvested_fields))}).",
                        evidence={"detectedFields": list(set(harvested_fields)), "formAction": action_url},
                        confidence=94.0,
                    ))

            # 3. Client-Side Meta Refresh Redirect Detection
            meta_refresh = soup.find("meta", attrs={"http-equiv": lambda v: v and v.lower() == "refresh"})
            if meta_refresh and meta_refresh.get("content"):
                content_val = meta_refresh.get("content", "")
                # Pattern: "0;url=http://..."
                if "url=" in content_val.lower():
                    refresh_target = content_val.lower().split("url=")[-1].strip("'\" ")
                    refresh_url = urljoin(metadata["finalUrl"], refresh_target)
                    refresh_parsed = urlsplit(refresh_url)
                    if refresh_parsed.hostname and refresh_parsed.hostname != final_host:
                        findings.append(RawFinding(
                            category="URL_ANOMALY",
                            severity="HIGH",
                            title="Client-Side Meta Refresh Redirect to External Host",
                            description=f"Page executes an automatic client-side redirect via <meta http-equiv='refresh'> to external host '{refresh_parsed.hostname}'.",
                            evidence={"refreshTarget": refresh_url, "pageHost": final_host},
                            confidence=92.0,
                        ))

            # 4. Hidden IFrame detection
            hidden_iframes = soup.find_all(
                "iframe",
                style=lambda val: val and ("display:none" in val.replace(" ", "") or "visibility:hidden" in val.replace(" ", ""))
            )
            if hidden_iframes:
                findings.append(RawFinding(
                    category="WEB_SECURITY",
                    severity="MEDIUM",
                    title="Hidden IFrame Detected",
                    description="Page contains concealed iframe elements often used for silent exploit delivery or tracking.",
                    evidence={"hiddenIframeCount": len(hidden_iframes)},
                    confidence=75.0,
                ))

        return findings, metadata
