import tldextract
from typing import List
from app.schemas.response import RawFinding

HIGH_RISK_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "fit", "surf",
    "icu", "work", "cam", "xyz", "rest", "bar", "live", "space"
}

TARGETED_BRANDS = [
    ("paypal", ["paypal.com"]),
    ("microsoft", ["microsoft.com", "live.com", "office.com"]),
    ("google", ["google.com", "accounts.google.com"]),
    ("apple", ["apple.com", "icloud.com"]),
    ("amazon", ["amazon.com", "aws.amazon.com"]),
    ("netflix", ["netflix.com"]),
    ("chase", ["chase.com"]),
    ("bankofamerica", ["bankofamerica.com"]),
    ("wellsfargo", ["wellsfargo.com"]),
    ("facebook", ["facebook.com", "fb.com"]),
    ("instagram", ["instagram.com"]),
    ("binance", ["binance.com"]),
    ("coinbase", ["coinbase.com"]),
]


class DomainAnalyzer:
    """Analyzes domain taxonomy, TLD risk profiles, and brand impersonation patterns."""

    def __init__(self):
        self.extract = tldextract.TLDExtract(cache_dir=None)

    def analyze(self, normalized_domain: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        ext = self.extract(normalized_domain)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if domain and suffix else normalized_domain

        # 1. High-Risk / Abused TLD Detection
        if suffix in HIGH_RISK_TLDS:
            findings.append(RawFinding(
                category="DOMAIN_REPUTATION",
                severity="HIGH",
                title="High-Risk Top-Level Domain (TLD)",
                description=f"The domain uses .{suffix}, a TLD statistically correlated with high abuse and malicious activity.",
                evidence={"tld": suffix, "registeredDomain": registered_domain},
                confidence=85.0
            ))

        # 2. Brand Impersonation / Typosquatting Heuristics
        for brand, legitimate_domains in TARGETED_BRANDS:
            # If the brand name appears in subdomain or domain name
            if brand in domain or brand in subdomain:
                # Check if it's NOT an authentic domain
                is_legit = any(registered_domain == legit or registered_domain.endswith("." + legit) for legit in legitimate_domains)
                if not is_legit:
                    findings.append(RawFinding(
                        category="PHISHING_INDICATOR",
                        severity="CRITICAL",
                        title=f"Brand Impersonation Detected: {brand.capitalize()}",
                        description=f"The domain contains the brand term '{brand}', but is not affiliated with official domain(s) ({', '.join(legitimate_domains)}). High likelihood of credential harvesting.",
                        evidence={
                            "targetedBrand": brand,
                            "domain": domain,
                            "subdomain": subdomain,
                            "registeredDomain": registered_domain
                        },
                        confidence=92.0
                    ))

        # 3. Informational domain registration finding
        findings.append(RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Domain Taxonomy Verified",
            description=f"Extracted domain: {domain}, suffix: {suffix}, subdomains: {subdomain or 'none'}.",
            evidence={"subdomain": subdomain, "domain": domain, "suffix": suffix, "registeredDomain": registered_domain},
            confidence=100.0
        ))

        return findings
