import re
import ipaddress
from urllib.parse import urlparse, unquote
from typing import List
from app.schemas.response import RawFinding

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "paypal", "appleid",
    "wallet", "billing", "recover", "passcode", "credential", "webscr",
    "payment", "invoice", "refund", "kyc", "aadhaar", "debit", "creditcard",
    "cvv", "otp", "claim", "airdrop", "lottery", "recruitment", "salary"
}


class UrlAnalyzer:
    """Analyzes URL structure, lexical patterns, and obfuscation heuristics."""

    def analyze(self, target_url: str, normalized_domain: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(target_url)
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()
        hostname = (parsed.hostname or normalized_domain).lower()

        # 1. Check if hostname is raw IP address
        try:
            ipaddress.ip_address(hostname)
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="HIGH",
                title="Direct IP Address in URL",
                description="The target URL utilizes an explicit IP address rather than a registered domain name, a common phishing tactic to evade domain reputation filters.",
                evidence={"hostname": hostname},
                confidence=95.0
            ))
        except ValueError:
            pass

        # 2. Punycode / Internationalized Domain Name (Homograph Risk)
        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="MEDIUM",
                title="Punycode / Homograph Domain Detected",
                description="The domain uses Punycode encoding (xn--), which can be exploited in IDN homograph attacks to impersonate legitimate brand domains.",
                evidence={"hostname": hostname},
                confidence=85.0
            ))

        # 3. Embedded userinfo in URL (e.g. http://google.com@phishing.com)
        if parsed.username or parsed.password or "@" in parsed.netloc:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="CRITICAL",
                title="Embedded User Credentials / Authority Masking",
                description="The URL contains an '@' character in the authority component, deliberately disguising the destination host.",
                evidence={"netloc": parsed.netloc},
                confidence=95.0
            ))

        # 4. Excessive URL length
        if len(target_url) > 150:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="MEDIUM",
                title="Excessive URL Length",
                description="The URL exceeds 150 characters, often indicating parameter padding or token masking used in evasion techniques.",
                evidence={"length": len(target_url)},
                confidence=70.0
            ))
        elif len(target_url) > 90:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="LOW",
                title="Elevated URL Length",
                description="URL length is longer than 90 characters.",
                evidence={"length": len(target_url)},
                confidence=60.0
            ))

        # 5. Suspicious keywords in subdomains or path
        matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_lower or kw in query_lower or kw in hostname]
        if matched_keywords:
            severity = "HIGH" if len(matched_keywords) >= 2 else "MEDIUM"
            findings.append(RawFinding(
                category="PHISHING_INDICATOR",
                severity=severity,
                title="Sensitive Authentication Keywords in URL",
                description=f"Detected high-risk deceptive terms ({', '.join(matched_keywords)}) in the URL path, parameters, or domain.",
                evidence={"keywords": matched_keywords, "url": target_url},
                confidence=80.0
            ))

        # 6. Excessive subdomain depth
        subdomains = hostname.split(".")
        if len(subdomains) > 4:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="MEDIUM",
                title="Excessive Subdomain Stacking",
                description="The host has more than 3 subdomain levels, often used to simulate trustworthy host hierarchies (e.g., login.microsoft.com.attacker.com).",
                evidence={"subdomainCount": len(subdomains), "hostname": hostname},
                confidence=75.0
            ))

        # 7. Suspicious hyphen usage in hostname
        if hostname.count("-") >= 3:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="LOW",
                title="Repeated Hyphenation in Hostname",
                description="The hostname contains multiple hyphens, frequently observed in deceptive typosquatting domains.",
                evidence={"hyphenCount": hostname.count("-"), "hostname": hostname},
                confidence=65.0
            ))

        return findings
