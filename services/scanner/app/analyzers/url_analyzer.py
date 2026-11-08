import re
import ipaddress
import tldextract
from urllib.parse import urlparse, unquote
from typing import List, Set, Dict, Any, Optional
from app.schemas.response import RawFinding
from app.intelligence.tranco_provider import get_tranco_provider, TrancoIntelligenceProvider

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "secure", "security",
    "account", "update", "banking", "authenticate", "paypal", "appleid",
    "wallet", "billing", "recover", "passcode", "credential", "webscr",
    "payment", "invoice", "refund", "kyc", "aadhaar", "debit", "creditcard",
    "cvv", "otp", "claim", "airdrop", "lottery", "recruitment", "salary",
    "phish",
}

# CAL-03: substring matching is unsafe for some terms ("phish" would also be
# checked against ordinary words), so these keywords only count when they form
# a complete alphanumeric token of the hostname / path / query.
TOKEN_ONLY_KEYWORDS: Set[str] = {"phish"}

# CAL-06: a keyword finding that originates solely from the hostname describes
# the same deceptive-hostname characteristic as the domain analyzer's
# impersonation findings for that host, so both share one stable dedup key
# (the higher-severity finding is retained; report evidence is never dropped).
HOSTNAME_IMPERSONATION_DEDUP_PREFIX = "DECEPTIVE_HOSTNAME:"


def _token_match(keyword: str, text: str, tokens: Set[str]) -> bool:
    if keyword in TOKEN_ONLY_KEYWORDS:
        return keyword in tokens
    return keyword in text


def _split_tokens(text: str) -> Set[str]:
    return {tok for tok in re.split(r"[^a-z0-9]+", text.lower()) if tok}

ORDINARY_AUTH_TERMS: Set[str] = {
    "login", "signin", "account", "portal", "verify", "update",
    "auth", "security", "authenticate", "secure", "verification"
}

RECOGNIZED_AUTHENTIC_DOMAINS: Set[str] = {
    # Major tech & identity providers
    "google.com", "github.com", "amazon.com", "paypal.com", "apple.com",
    "microsoft.com", "live.com", "office.com", "azure.com", "docker.com",
    "atlassian.com", "gitlab.com", "steampowered.com", "netflix.com",
    "facebook.com", "meta.com", "instagram.com", "whatsapp.com",
    "box.com", "openai.com", "cloudflare.com", "bitbucket.org",
    "wikipedia.org", "python.org", "mozilla.org", "stackoverflow.com",
    "nytimes.com", "mit.edu", "bbc.co.uk", "apache.org", "kernel.org",
    "debian.org", "w3.org", "archive.org", "redhat.com", "rust-lang.org",
    "cam.ac.uk", "nih.gov",

    # Financial institutions
    "chase.com", "bankofamerica.com", "bofa.com", "wellsfargo.com",
    "citi.com", "citibank.com", "barclays.co.uk", "barclays.com",
    "hsbc.com", "hsbc.co.uk", "santander.com", "santanderbank.com",
    "sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "hdfcbank.com",
    "icicibank.com", "stripe.com", "razorpay.com", "revolut.com",
    "venmo.com", "cash.app", "binance.com", "coinbase.com",
    "metamask.io", "trezor.io", "ledger.com", "exodus.com",
    "phantom.app", "trustwallet.com", "uniswap.org", "pancakeswap.finance",
    "spotify.com", "adobe.com", "dhl.com", "dropbox.com", "ebay.com",
    "linkedin.com", "indeed.com", "workday.com", "glassdoor.com",
}


class UrlAnalyzer:
    """Analyzes URL structure, lexical patterns, and obfuscation heuristics."""

    def __init__(self, tranco_provider: Optional[TrancoIntelligenceProvider] = None):
        self.extract = tldextract.TLDExtract(cache_dir=None)
        self.tranco_provider = tranco_provider or get_tranco_provider()

    def analyze(self, target_url: str, normalized_domain: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        parsed = urlparse(target_url)
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()
        hostname = (parsed.hostname or normalized_domain).lower()

        # Public Suffix List-aware domain extraction
        ext = self.extract(hostname)
        domain = ext.domain.lower() if ext.domain else ""
        suffix = ext.suffix.lower() if ext.suffix else ""
        registered_domain = f"{domain}.{suffix}" if domain and suffix else hostname

        # Operational coverage notice if Tranco intelligence is operating in degraded fallback
        tranco_meta = self.tranco_provider.get_metadata()
        if tranco_meta.get("status") in ("DEGRADED_FALLBACK", "DEGRADED_CORRUPT"):
            findings.append(RawFinding(
                category="DOMAIN_REPUTATION",
                severity="INFO",
                title="Domain Intelligence Operating in Degraded Mode",
                description="Tranco popular domain database is operating in degraded fallback mode. Static authentic registries remain active.",
                evidence={"status": tranco_meta.get("status"), "warning": tranco_meta.get("warning") or tranco_meta.get("error")},
                confidence=50.0,
            ))

        # 1. Check if hostname is raw IP address
        try:
            ipaddress.ip_address(hostname)
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="HIGH",
                title="Direct IP Address in URL",
                description="The target URL utilizes an explicit IP address rather than a registered domain name, a common phishing tactic to evade domain reputation filters.",
                evidence={"hostname": hostname, "dedupKey": "HOST_RAW_IP"},
                confidence=95.0
            ))
        except ValueError:
            pass

        # 2. Punycode / Internationalized Domain Name (Homograph Risk)
        is_punycode = hostname.startswith("xn--") or ".xn--" in hostname
        if is_punycode:
            findings.append(RawFinding(
                category="URL_ANOMALY",
                severity="MEDIUM",
                title="Punycode / Homograph Domain Detected",
                description="The domain uses Punycode encoding (xn--), which can be exploited in IDN homograph attacks to impersonate legitimate brand domains.",
                evidence={"hostname": hostname},
                confidence=85.0
            ))

        # 3. Embedded userinfo in URL (e.g. http://google.com@phishing.com)
        has_userinfo = bool(parsed.username or parsed.password or "@" in parsed.netloc)
        if has_userinfo:
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

        # 5. Context-Aware Authentication and Phishing Keyword Analysis (CAL-02 & Phase 7.1)
        # Check if destination resides on an authentic recognized platform or Tranco popular domain without deceptive evasions
        is_tranco_popular = self.tranco_provider.is_popular_domain(registered_domain)
        is_authentic_recognized_domain = (
            (registered_domain in RECOGNIZED_AUTHENTIC_DOMAINS or is_tranco_popular)
            and not is_punycode
            and not has_userinfo
        )

        # Token sets for exact-token keyword matching (CAL-03)
        hostname_tokens = _split_tokens(hostname)
        path_tokens = _split_tokens(path_lower)
        query_tokens = _split_tokens(query_lower)

        matched_keywords: List[str] = []
        matched_in_path_or_query: Set[str] = set()
        for kw in SUSPICIOUS_KEYWORDS:
            in_host = _token_match(kw, hostname, hostname_tokens)
            in_pathq = _token_match(kw, path_lower, path_tokens) or _token_match(
                kw, query_lower, query_tokens
            )
            if in_host or in_pathq:
                matched_keywords.append(kw)
                if in_pathq:
                    matched_in_path_or_query.add(kw)

        if is_authentic_recognized_domain:
            # On authentic domains, suppress penalties for ordinary authentication endpoints (/login, /signin)
            # and ignore the brand's own registered domain name (e.g. "paypal" in paypal.com)
            filtered_keywords = [
                kw for kw in matched_keywords
                if kw not in ORDINARY_AUTH_TERMS and kw != domain
            ]
        else:
            filtered_keywords = matched_keywords

        if filtered_keywords:
            severity = "HIGH" if len(filtered_keywords) >= 2 else "MEDIUM"
            evidence: Dict[str, Any] = {"keywords": filtered_keywords, "url": target_url}
            # Hostname-only keyword findings deduplicate against domain-analyzer
            # impersonation findings for the same host (one deceptive hostname).
            if all(kw not in matched_in_path_or_query for kw in filtered_keywords):
                evidence["hostname"] = hostname
                evidence["dedupKey"] = f"{HOSTNAME_IMPERSONATION_DEDUP_PREFIX}{hostname.lower()}"
            findings.append(RawFinding(
                category="PHISHING_INDICATOR",
                severity=severity,
                title="Sensitive Authentication Keywords in URL",
                description=f"Detected high-risk deceptive terms ({', '.join(filtered_keywords)}) in the URL path, parameters, or domain.",
                evidence=evidence,
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
