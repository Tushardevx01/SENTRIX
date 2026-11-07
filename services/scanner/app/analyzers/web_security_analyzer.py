import time
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Any, Tuple
import httpx
from bs4 import BeautifulSoup
from app.schemas.response import RawFinding


class WebSecurityAnalyzer:
    """Evaluates HTTP response headers, redirect behaviors, and DOM phishing artifacts."""

    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SENTRIX-ThreatScanner/1.0"
        }

    async def analyze(self, target_url: str, normalized_domain: str) -> Tuple[List[RawFinding], Dict[str, Any]]:
        findings: List[RawFinding] = []
        metadata: Dict[str, Any] = {
            "redirectChain": [],
            "responseTimeMs": 0.0,
            "statusCode": 0
        }

        start_time = time.time()
        try:
            async with httpx.AsyncClient(headers=self.headers, verify=False, timeout=5.0) as client:
                response = await client.get(target_url, follow_redirects=True)
                metadata["responseTimeMs"] = round((time.time() - start_time) * 1000, 2)
                metadata["statusCode"] = response.status_code
                metadata["redirectChain"] = [str(r.url) for r in response.history] + [str(response.url)]

                # 1. Inspect HTTP Security Headers
                resp_headers = {k.lower(): v for k, v in response.headers.items()}

                if "strict-transport-security" not in resp_headers:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="LOW",
                        title="Missing Strict-Transport-Security (HSTS)",
                        description="The HTTP response lacks an HSTS header, leaving users vulnerable to SSL-stripping man-in-the-middle attacks.",
                        evidence={"header": "Strict-Transport-Security"},
                        confidence=90.0
                    ))

                if "content-security-policy" not in resp_headers:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="LOW",
                        title="Missing Content-Security-Policy (CSP)",
                        description="No Content-Security-Policy header was detected, increasing vulnerability to Cross-Site Scripting (XSS) and data injection.",
                        evidence={"header": "Content-Security-Policy"},
                        confidence=85.0
                    ))

                if "x-frame-options" not in resp_headers and "content-security-policy" not in resp_headers:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="LOW",
                        title="Missing Clickjacking Defenses",
                        description="Neither X-Frame-Options nor CSP frame-ancestors is present to protect the site from UI redress/clickjacking.",
                        evidence={"header": "X-Frame-Options"},
                        confidence=85.0
                    ))

                if "x-content-type-options" not in resp_headers:
                    findings.append(RawFinding(
                        category="WEB_SECURITY",
                        severity="LOW",
                        title="Missing X-Content-Type-Options Header",
                        description="Lacks 'nosniff' directive, allowing browsers to MIME-sniff responses away from the declared content-type.",
                        evidence={"header": "X-Content-Type-Options"},
                        confidence=90.0
                    ))

                # 2. Redirect Analysis
                if len(response.history) > 3:
                    findings.append(RawFinding(
                        category="URL_ANOMALY",
                        severity="MEDIUM",
                        title="Multiple Redirection Hops",
                        description=f"Detected {len(response.history)} intermediate redirect hops before reaching final destination, characteristic of redirection cloaking.",
                        evidence={"hops": metadata["redirectChain"]},
                        confidence=80.0
                    ))

                # Check cross-domain redirect
                initial_host = urlparse(target_url).hostname
                final_host = urlparse(str(response.url)).hostname
                if initial_host and final_host and initial_host != final_host:
                    findings.append(RawFinding(
                        category="URL_ANOMALY",
                        severity="MEDIUM",
                        title="Cross-Domain Redirect Observed",
                        description=f"Destination redirects from '{initial_host}' to external host '{final_host}'.",
                        evidence={"initialHost": initial_host, "finalHost": final_host},
                        confidence=75.0
                    ))

                # 3. DOM & Form Security Analysis
                content_type = resp_headers.get("content-type", "")
                if "text/html" in content_type:
                    soup = BeautifulSoup(response.text[:250000], "html.parser")

                    # Check for password inputs
                    password_inputs = soup.find_all("input", attrs={"type": "password"})
                    if password_inputs:
                        for form in soup.find_all("form"):
                            if form.find("input", attrs={"type": "password"}):
                                action = form.get("action", "")
                                action_url = urljoin(str(response.url), action)
                                action_parsed = urlparse(action_url)

                                # Form posts to external host
                                if action_parsed.hostname and action_parsed.hostname != final_host:
                                    findings.append(RawFinding(
                                        category="PHISHING_INDICATOR",
                                        severity="CRITICAL",
                                        title="Credential Form Submits to External Host",
                                        description="A password input form action posts credentials to a completely different domain than the page host.",
                                        evidence={"pageHost": final_host, "formAction": action_url},
                                        confidence=95.0
                                    ))

                                # Form posts over unencrypted HTTP
                                if action_parsed.scheme == "http":
                                    findings.append(RawFinding(
                                        category="WEB_SECURITY",
                                        severity="HIGH",
                                        title="Insecure Form Submission (HTTP)",
                                        description="A password form posts credentials over unencrypted plain HTTP transport.",
                                        evidence={"formAction": action_url},
                                        confidence=95.0
                                    ))

                    # Check for hidden IFrames
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
                            confidence=75.0
                        ))

        except httpx.RequestError as e:
            findings.append(RawFinding(
                category="WEB_SECURITY",
                severity="INFO",
                title="Web Endpoint Unreachable During Inspection",
                description=f"HTTP probe could not connect to destination ({type(e).__name__}).",
                evidence={"error": str(e)},
                confidence=60.0
            ))

        return findings, metadata
