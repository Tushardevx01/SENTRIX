import re
import tldextract
from typing import List, Tuple, Set
from app.schemas.response import RawFinding

HIGH_RISK_TLDS: Set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "buzz", "fit", "surf",
    "icu", "work", "cam", "xyz", "rest", "bar", "live", "space",
    "click", "link", "online", "site", "vip", "monster", "cfd"
}

LEGITIMATE_GOV_SUFFIXES: Set[str] = {
    "gov", "gov.in", "gov.uk", "gov.au", "gov.ca", "mil", "nic.in",
    "gov.br", "gov.za", "gc.ca", "fed.us", "state.us"
}

GOVERNMENT_KEYWORDS: Set[str] = {
    "incometax", "irs", "passport", "aadhaar", "uidai", "mygov",
    "socialsecurity", "usps", "fedex", "dhl", "dmv", "customs",
    "treasury", "nationalportal"
}

LEGITIMATE_EDU_SUFFIXES: Set[str] = {
    "edu", "ac.uk", "edu.in", "edu.au", "edu.cn", "edu.sg", "ac.in"
}

ACADEMIC_KEYWORDS: Set[str] = {
    "harvard", "stanford", "oxford", "cambridge", "studentaid",
    "finaid", "scholarship-portal", "university-admissions"
}

RECRUITMENT_KEYWORDS: Set[str] = {
    "careers-portal", "job-portal", "recruitment-portal",
    "hiring-interview", "offer-letter", "workday-jobs"
}

TARGETED_BRANDS: List[Tuple[str, List[str]]] = [
    # Global Tech & Authentication
    ("paypal", ["paypal.com"]),
    ("microsoft", ["microsoft.com", "live.com", "office.com", "azure.com"]),
    ("google", ["google.com", "accounts.google.com"]),
    ("apple", ["apple.com", "icloud.com"]),
    ("amazon", ["amazon.com", "aws.amazon.com"]),
    ("netflix", ["netflix.com"]),
    ("facebook", ["facebook.com", "fb.com", "meta.com"]),
    ("instagram", ["instagram.com"]),
    ("whatsapp", ["whatsapp.com"]),
    ("spotify", ["spotify.com"]),
    ("adobe", ["adobe.com"]),
    ("dropbox", ["dropbox.com"]),
    ("box", ["box.com"]),
    ("openai", ["openai.com", "chatgpt.com"]),
    ("ebay", ["ebay.com"]),
    ("docker", ["docker.com"]),
    ("atlassian", ["atlassian.com"]),
    ("gitlab", ["gitlab.com"]),
    ("steampowered", ["steampowered.com", "steamcommunity.com"]),

    # Banking & Financial Services
    ("chase", ["chase.com"]),
    ("bankofamerica", ["bankofamerica.com", "bofa.com"]),
    ("bofa", ["bankofamerica.com", "bofa.com"]),
    ("wellsfargo", ["wellsfargo.com"]),
    ("citibank", ["citi.com", "citibank.com"]),
    ("citi", ["citi.com", "citibank.com"]),
    ("barclays", ["barclays.co.uk", "barclays.com"]),
    ("hsbc", ["hsbc.com", "hsbc.co.uk"]),
    ("santander", ["santander.com", "santanderbank.com"]),
    ("sbi", ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"]),
    ("hdfc", ["hdfcbank.com", "hdfc.com"]),
    ("icici", ["icicibank.com"]),

    # Fintech, Payments & Crypto
    ("stripe", ["stripe.com"]),
    ("razorpay", ["razorpay.com"]),
    ("revolut", ["revolut.com"]),
    ("venmo", ["venmo.com"]),
    ("cashapp", ["cash.app"]),
    ("binance", ["binance.com"]),
    ("coinbase", ["coinbase.com"]),
    ("metamask", ["metamask.io"]),

    # Recruitment & Career Portals
    ("linkedin", ["linkedin.com"]),
    ("indeed", ["indeed.com"]),
    ("naukri", ["naukri.com"]),
    ("workday", ["workday.com", "myworkdayjobs.com"]),
    ("glassdoor", ["glassdoor.com"]),
]


def generate_normalization_candidates(text: str) -> List[str]:
    """
    Generates controlled visual similarity and leetspeak substitution candidates.
    Supports ambiguous substitutions (e.g. 1 -> l/i/t, 0 -> o, rn -> m).
    """
    base = text.lower().replace("rn", "m").replace("vv", "w")
    base = (
        base.replace("0", "o")
        .replace("3", "e")
        .replace("4", "a")
        .replace("5", "s")
        .replace("8", "b")
        .replace("@", "a")
        .replace("$", "s")
    )
    candidates = {
        base.replace("1", "l"),
        base.replace("1", "i"),
        base.replace("1", "t"),
        base,
    }
    return list(candidates)


class DomainAnalyzer:
    """Analyzes domain taxonomy, TLD risk profiles, brand impersonation, government/banking spoofing, and recruitment scams."""

    def __init__(self):
        self.extract = tldextract.TLDExtract(cache_dir=None)

    def analyze(self, normalized_domain: str) -> List[RawFinding]:
        findings: List[RawFinding] = []
        ext = self.extract(normalized_domain)
        subdomain = ext.subdomain.lower()
        domain = ext.domain.lower()
        suffix = ext.suffix.lower()
        registered_domain = f"{domain}.{suffix}" if domain and suffix else normalized_domain

        # Token-based domain segmentation
        d_tokens = set(domain.split("-"))
        sub_tokens = {
            tok
            for part in subdomain.split(".")
            for tok in part.split("-")
            if tok
        }
        all_tokens = d_tokens | sub_tokens
        dehyphen_domain = domain.replace("-", "")

        # 1. High-Risk / Abused TLD Detection
        if suffix in HIGH_RISK_TLDS:
            findings.append(RawFinding(
                category="DOMAIN_REPUTATION",
                severity="HIGH",
                title="High-Risk Top-Level Domain (TLD)",
                description=f"The domain uses .{suffix}, a TLD statistically correlated with high abuse, phishing campaigns, and malware delivery.",
                evidence={"tld": suffix, "registeredDomain": registered_domain},
                confidence=85.0
            ))

        # 2. Government & Public Authority Impersonation Audit (Token-Aware CAL-03)
        is_legit_gov = any(suffix == s or suffix.endswith("." + s) for s in LEGITIMATE_GOV_SUFFIXES)
        if not is_legit_gov:
            matched_gov_keywords = []
            for kw in GOVERNMENT_KEYWORDS:
                if len(kw) <= 4:
                    # Short keywords require token-level match to avoid false positives (e.g. "irs" in "first-aid")
                    if kw in all_tokens or dehyphen_domain == kw:
                        matched_gov_keywords.append(kw)
                else:
                    if kw in all_tokens or kw in domain or kw in subdomain or dehyphen_domain == kw:
                        matched_gov_keywords.append(kw)

            # Check for standalone "gov" in subdomain (e.g. login.gov.attacker.com)
            if "gov" in sub_tokens or "gov" in subdomain.split("."):
                matched_gov_keywords.append("gov")

            if matched_gov_keywords:
                findings.append(RawFinding(
                    category="PHISHING_INDICATOR",
                    severity="CRITICAL",
                    title="Government / Public Authority Impersonation Detected",
                    description=(
                        f"The domain incorporates sensitive government service keyword(s) ({', '.join(set(matched_gov_keywords))}), "
                        f"but is hosted on non-governmental TLD '.{suffix}'. High risk of fraudulent tax, citizen identity, or benefits harvesting."
                    ),
                    evidence={
                        "matchedKeywords": list(set(matched_gov_keywords)),
                        "domain": domain,
                        "subdomain": subdomain,
                        "suffix": suffix,
                        "registeredDomain": registered_domain
                    },
                    confidence=95.0
                ))

        # 3. Academic & Higher Education Impersonation Audit (Token-Aware CAL-03)
        is_legit_edu = any(suffix == s or suffix.endswith("." + s) for s in LEGITIMATE_EDU_SUFFIXES)
        if not is_legit_edu:
            matched_academic = []
            for kw in ACADEMIC_KEYWORDS:
                if kw in all_tokens or kw in domain or kw in subdomain or dehyphen_domain == kw:
                    matched_academic.append(kw)

            if "edu" in sub_tokens or "edu" in subdomain.split("."):
                matched_academic.append("edu")

            if matched_academic:
                findings.append(RawFinding(
                    category="PHISHING_INDICATOR",
                    severity="HIGH",
                    title="Academic / Higher Education Impersonation Detected",
                    description=(
                        f"The domain references educational institutions or student aid services ({', '.join(set(matched_academic))}), "
                        f"but does not reside on an accredited educational domain (.edu / .ac). Risk of fake admissions, student loan scams, or credential theft."
                    ),
                    evidence={
                        "matchedKeywords": list(set(matched_academic)),
                        "registeredDomain": registered_domain
                    },
                    confidence=90.0
                ))

        # 4. Deceptive Recruitment & Job Portal Audit
        matched_recruitment = [
            kw for kw in RECRUITMENT_KEYWORDS
            if kw in all_tokens or kw in domain or kw in subdomain
        ]
        if matched_recruitment and suffix in HIGH_RISK_TLDS:
            findings.append(RawFinding(
                category="PHISHING_INDICATOR",
                severity="HIGH",
                title="Deceptive Recruitment / Job Portal Detected",
                description=(
                    f"The domain uses employment keywords ({', '.join(matched_recruitment)}) under high-abuse TLD '.{suffix}'. "
                    "Fake recruitment portals routinely solicit identity documents, banking credentials, or advance fees."
                ),
                evidence={
                    "matchedKeywords": matched_recruitment,
                    "tld": suffix,
                    "registeredDomain": registered_domain
                },
                confidence=88.0
            ))

        # 5. Token-Based & Leetspeak Brand Impersonation / Typosquatting (CAL-03 & CAL-04)
        cand_domains = generate_normalization_candidates(domain)
        cand_subdomains = generate_normalization_candidates(subdomain)

        for brand, legitimate_domains in TARGETED_BRANDS:
            is_legit = any(
                registered_domain == legit or registered_domain.endswith("." + legit)
                for legit in legitimate_domains
            )
            if is_legit:
                continue

            is_short = len(brand) <= 4

            # 5a. Canonical match check
            if is_short:
                has_canonical = (brand in all_tokens) or (dehyphen_domain == brand)
            else:
                has_canonical = (
                    (brand in all_tokens)
                    or (brand in dehyphen_domain)
                    or (brand in domain)
                    or (brand in subdomain)
                )

            # 5b. Typo / visual similarity match check across candidates
            has_typosquat = False
            if not has_canonical:
                for c_dom in cand_domains:
                    c_tokens = set(c_dom.split("-"))
                    c_dehyphen = c_dom.replace("-", "")
                    if is_short:
                        if (brand in c_tokens) or (c_dehyphen == brand):
                            has_typosquat = True
                            break
                    else:
                        if (brand in c_tokens) or (brand in c_dehyphen) or (brand in c_dom):
                            has_typosquat = True
                            break

                if not has_typosquat:
                    for c_sub in cand_subdomains:
                        c_sub_tokens = {tok for part in c_sub.split(".") for tok in part.split("-") if tok}
                        if (brand in c_sub_tokens) or (brand in c_sub):
                            has_typosquat = True
                            break

            if has_canonical or has_typosquat:
                is_typo_case = has_typosquat and not has_canonical
                title = (
                    f"Typosquatting / Leetspeak Impersonation: {brand.capitalize()}"
                    if is_typo_case
                    else f"Brand Impersonation Detected: {brand.capitalize()}"
                )
                description = (
                    f"The domain mimics '{brand}' through character substitutions (e.g. {domain}), "
                    f"targeting users of official domains ({', '.join(legitimate_domains)})."
                    if is_typo_case
                    else f"The domain contains the brand term '{brand}', but is not affiliated with official domain(s) ({', '.join(legitimate_domains)}). High likelihood of credential harvesting."
                )

                findings.append(RawFinding(
                    category="PHISHING_INDICATOR",
                    severity="CRITICAL",
                    title=title,
                    description=description,
                    evidence={
                        "targetedBrand": brand,
                        "domain": domain,
                        "subdomain": subdomain,
                        "registeredDomain": registered_domain,
                        "isTyposquat": is_typo_case
                    },
                    confidence=94.0 if is_typo_case else 92.0
                ))

        # 6. Informational domain taxonomy finding
        findings.append(RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Domain Taxonomy Verified",
            description=f"Extracted domain: {domain}, suffix: {suffix}, subdomains: {subdomain or 'none'}.",
            evidence={"subdomain": subdomain, "domain": domain, "suffix": suffix, "registeredDomain": registered_domain},
            confidence=100.0
        ))

        return findings
