import re
import unicodedata
import tldextract
from typing import List, Tuple, Set, Optional
from app.schemas.response import RawFinding
from app.analyzers.url_analyzer import RECOGNIZED_AUTHENTIC_DOMAINS

GENERIC_INFRASTRUCTURE_TOKENS: Set[str] = {
    "staging", "test-environment", "deployment-slot", "unverified-api",
    "ingress-node", "ad-server", "tracking-pixel", "domain-broker",
    "web-proxy", "traffic-redirect", "preview-environment", "ab-test",
    "load-balancer", "ephemeral-storage", "subdomain-routing",
    "content-stream", "lead-capture", "redirect-rotator", "maintenance-node",
    "cdn-test", "tracker-gateway", "shortener-jump", "lead-funnel",
    "placeholder-staging", "redirect-junction", "campaign-funnel",
    "feature-preview", "pre-release-check", "sender-tracking", "bulk-email"
}

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
    ("trezor", ["trezor.io"]),
    ("ledger", ["ledger.com"]),
    ("exodus", ["exodus.com"]),
    ("phantom", ["phantom.app"]),
    ("trustwallet", ["trustwallet.com"]),
    ("pancakeswap", ["pancakeswap.finance"]),
    ("uniswap", ["uniswap.org"]),

    # Recruitment & Career Portals
    ("linkedin", ["linkedin.com"]),
    ("indeed", ["indeed.com"]),
    ("naukri", ["naukri.com"]),
    ("workday", ["workday.com", "myworkdayjobs.com"]),
    ("glassdoor", ["glassdoor.com"]),
]


# ---------------------------------------------------------------------------
# CAL-03 / CAL-04: Controlled normalization, IDNA, confusables, edit distance
# ---------------------------------------------------------------------------

# Unambiguous leetspeak substitutions (single obvious visual replacement).
UNAMBIGUOUS_SUBSTITUTIONS = {"0": "o", "3": "e", "4": "a", "5": "s", "8": "b", "@": "a", "$": "s"}

# Ambiguous substitutions (1 -> l / i / t). Context-bounded: only evaluated inside
# tokens of at least 4 characters, and only ever compared against known brand
# tokens (a candidate is never scored on its own), which prevents collateral
# matches on ordinary English words.
AMBIGUOUS_SUBSTITUTIONS = {"1": ("l", "i", "t")}

# Minimum token length required before ambiguous substitutions are generated.
MIN_AMBIGUOUS_TOKEN_LEN = 4

# Hard cap on generated whole-domain candidates (cartesian product is bounded).
MAX_NORMALIZATION_CANDIDATES = 16

# Curated Unicode confusable skeleton map (Cyrillic / Greek / Latin look-alikes).
# Deliberately narrow: NFKD already folds compatibility forms (fullwidth, ligatures,
# accented letters); this map only covers characters that survive NFKD but still
# visually impersonate ASCII letters. No broad character replacement is applied.
CONFUSABLE_CHAR_MAP = {
    # Cyrillic look-alikes
    "а": "a", "в": "b", "г": "r", "е": "e", "ё": "e", "з": "3", "и": "n",
    "і": "i", "й": "n", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "ь": "b", "ѕ": "s", "ј": "j",
    "һ": "h", "ґ": "g", "ќ": "k", "ў": "y",
    # Greek look-alikes
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "σ": "s", "ς": "s", "τ": "t", "υ": "y", "χ": "x", "γ": "y",
    # Latin supplement look-alikes
    "ı": "i", "ø": "o", "ł": "l", "đ": "d", "ð": "d", "þ": "th", "ŋ": "n",
    "ſ": "s", "ɑ": "a", "ɡ": "g",
}

# Controlled compound suffixes: a single label may glue a brand directly to one of
# these (e.g. "microsoftonline", "appleid"). Bare plurals ("s"/"es") are excluded
# so ordinary words such as "stripes" or "chases" never count as brand matches.
COMPOUND_SUFFIXES: Set[str] = {
    "online", "login", "secure", "verify", "account", "support", "bank",
    "wallet", "pay", "app", "portal", "mail", "id", "auth", "signin",
    "update", "billing", "official", "global", "net", "center",
}

# Context signals that corroborate a *fuzzy* (edit-distance) brand match.
# Fuzzy matches are only accepted when at least one of these is present, which
# keeps ordinary dictionary words (e.g. "revolute", "stripes") unflagged.
HIGH_RISK_TLD_CORROBORATION: Set[str] = HIGH_RISK_TLDS

AUTH_CONTEXT_TOKENS: Set[str] = {
    "login", "signin", "sign", "account", "portal", "verify", "verification",
    "update", "auth", "secure", "security", "banking", "billing", "wallet",
    "passcode", "credential", "otp", "kyc", "support", "recover", "recovery",
    "webscr", "password", "claim", "invoice", "payment",
}


def _token_candidates(token: str) -> List[str]:
    """Generates bounded normalization candidates for a single domain token."""
    base = token.lower().replace("rn", "m").replace("vv", "w")
    for src, dst in UNAMBIGUOUS_SUBSTITUTIONS.items():
        base = base.replace(src, dst)

    variants = {base}
    # Ambiguous substitutions only apply in appropriate contexts:
    # long enough to be meaningful, and only as comparison candidates against
    # known brand tokens (see generate_normalization_candidates).
    if len(token) >= MIN_AMBIGUOUS_TOKEN_LEN and any(ch in token for ch in AMBIGUOUS_SUBSTITUTIONS):
        for src, alts in AMBIGUOUS_SUBSTITUTIONS.items():
            if src in base:
                for alt in alts:
                    variants.add(base.replace(src, alt))
    return list(variants)


def generate_normalization_candidates(text: str) -> List[str]:
    """
    Generates controlled visual-similarity and leetspeak substitution candidates.

    Candidates are produced per label token (splitting on '-', '.' and '_') rather
    than through one global character mapping, so substitutions stay inside the
    token where they occur. The resulting whole-domain candidates are only ever
    compared against explicitly known brand tokens.
    """
    if not text:
        return [text]

    parts = re.split(r"([-._])", text.lower())
    token_options: List[List[str]] = []
    for part in parts:
        if not part or re.fullmatch(r"[-._]", part):
            token_options.append([part])
        else:
            token_options.append(_token_candidates(part))

    results = [""]
    for options in token_options:
        next_results: List[str] = []
        for prefix in results:
            for option in options:
                if len(next_results) >= MAX_NORMALIZATION_CANDIDATES:
                    break
                next_results.append(prefix + option)
        results = next_results or [""]
    return results


def decode_idna_label(label: str) -> str:
    """Decodes a single punycode (xn--) label to Unicode; returns input on failure."""
    if not label.startswith("xn--"):
        return label
    try:
        decoded = label[4:].encode("ascii").decode("punycode")
        # Reject undecodable garbage that would corrupt skeleton matching
        if decoded and all(ch.isprintable() for ch in decoded):
            return unicodedata.normalize("NFKC", decoded)
    except (UnicodeError, ValueError):
        pass
    return label


def decode_idna_host(host: str) -> str:
    """IDNA-normalizes a host: decodes punycode labels and applies NFKC folding."""
    if not host:
        return host
    if "xn--" not in host:
        return unicodedata.normalize("NFKC", host)
    labels = host.split(".")
    return ".".join(decode_idna_label(lbl) for lbl in labels)


def unicode_confusable_skeleton(text: str) -> str:
    """
    Builds a confusable skeleton for visual-similarity comparison:
    NFKD normalization, combining-mark removal, lowercasing, then the curated
    confusable character map. The original text is preserved for evidence.
    """
    if not text:
        return text
    decomposed = unicodedata.normalize("NFKD", text)
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    lowered = stripped.lower()
    return "".join(CONFUSABLE_CHAR_MAP.get(ch, ch) for ch in lowered)


def bounded_edit_distance(a: str, b: str, cap: int) -> int:
    """Levenshtein distance with early termination once the cap is exceeded."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            val = min(prev[j] + 1, current[j - 1] + 1, prev[j - 1] + (ca != cb))
            current.append(val)
            if val < row_min:
                row_min = val
        if row_min > cap:
            return cap + 1
        prev = current
    return prev[-1]


def brand_edit_distance_cap(brand: str) -> Optional[int]:
    """
    Carefully bounded edit-distance allowance per brand length:
    - brand length <= 4: exact token matching only (no fuzzy matching)
    - brand length 5-8: distance <= 1
    - brand length >= 9: distance <= 2
    Returns None when fuzzy matching must not be attempted.
    """
    n = len(brand)
    if n <= 4:
        return None
    if n <= 8:
        return 1
    return 2


def has_fuzzy_match_corroboration(
    hostname: str,
    domain: str,
    subdomain: str,
    suffix: str,
) -> bool:
    """
    Requires an independent risk signal before accepting an edit-distance brand
    match: high-risk TLD, punycode/IDNA host, leet digits in the registrable
    label, or authentication-context tokens. Prevents fuzzy matching from
    flagging ordinary English words on ordinary domains.
    """
    if suffix in HIGH_RISK_TLD_CORROBORATION:
        return True
    if "xn--" in hostname:
        return True
    if any(ch in domain for ch in "0123456789@$"):
        return True
    tokens = set(re.split(r"[.\-_]", f"{domain}.{subdomain}".lower())) - {""}
    if tokens & AUTH_CONTEXT_TOKENS:
        return True
    return False


def _ordered_label_tokens(label: str) -> List[List[str]]:
    """
    Ordered token lists per dotted label part (hyphen/underscore aware).
    Ordering enables hyphen-window matching while never joining across '.'
    label boundaries.
    """
    lists: List[List[str]] = []
    for part in (label or "").lower().split("."):
        toks = [t for t in re.split(r"[-_]", part) if t]
        if toks:
            lists.append(toks)
    return lists


def _hyphen_window_match(brand: str, ordered_token_lists: List[List[str]]) -> bool:
    """
    Hyphen-tolerant brand matching: consecutive tokens joined must equal the
    brand exactly (e.g. 'wells-fargo-alert' -> window 'wells'+'fargo' ==
    'wellsfargo'). Short brands (<=4 chars) are excluded — they are
    exact-token only per CAL-03.
    """
    if len(brand) <= 4:
        return False
    for lst in ordered_token_lists:
        n = len(lst)
        for size in range(2, min(5, n) + 1):
            for i in range(n - size + 1):
                if "".join(lst[i:i + size]) == brand:
                    return True
    return False


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

        # CAL-03 / CAL-04: IDNA-decoded and confusable-skeleton representations.
        # The original domain strings remain the source of evidence and reporting.
        decoded_domain = decode_idna_host(domain)
        decoded_subdomain = decode_idna_host(subdomain)
        skeleton_domain = unicode_confusable_skeleton(decoded_domain)
        skeleton_subdomain = unicode_confusable_skeleton(decoded_subdomain)

        def _label_tokens(label: str) -> Set[str]:
            return {tok for tok in re.split(r"[.\-_]", label.lower()) if tok}

        # Ordered (window-matchable) token sequences per label part
        ordered_original = _ordered_label_tokens(domain) + _ordered_label_tokens(subdomain)
        ordered_decoded = _ordered_label_tokens(decoded_domain) + _ordered_label_tokens(decoded_subdomain)
        ordered_skeleton = _ordered_label_tokens(skeleton_domain) + _ordered_label_tokens(skeleton_subdomain)

        decoded_tokens = _label_tokens(decoded_domain) | _label_tokens(decoded_subdomain)
        skeleton_tokens = _label_tokens(skeleton_domain) | _label_tokens(skeleton_subdomain)
        decoded_dehyphen = decoded_domain.replace("-", "")
        skeleton_dehyphen = skeleton_domain.replace("-", "")

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
                        "registeredDomain": registered_domain,
                        "dedupKey": f"DECEPTIVE_HOSTNAME:{normalized_domain.lower()}",
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
                        "registeredDomain": registered_domain,
                        "dedupKey": f"DECEPTIVE_HOSTNAME:{normalized_domain.lower()}",
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
                    "registeredDomain": registered_domain,
                    "dedupKey": f"DECEPTIVE_HOSTNAME:{normalized_domain.lower()}",
                },
                confidence=88.0
            ))

        # 5. Token-Based & Visual-Similarity Brand Impersonation (CAL-03 & CAL-04)
        # Matching pipeline (in order):
        #   a) exact token / controlled-compound match on the original labels
        #   b) exact match on the confusable skeleton (Unicode homographs / IDNA)
        #   c) controlled leetspeak candidates (per-token, context-bounded)
        #   d) carefully bounded token-level edit distance (corroboration-gated)
        # Indiscriminate substring matching is never used.
        cand_domains = generate_normalization_candidates(domain)
        cand_subdomains = generate_normalization_candidates(subdomain)

        def _compound_token_match(brand: str, tokens: Set[str], dehyphen: str, short: bool) -> bool:
            if short:
                return brand in tokens or dehyphen == brand
            if brand in tokens:
                return True
            for tok in tokens:
                if tok.startswith(brand) and tok[len(brand):] in COMPOUND_SUFFIXES:
                    return True
            return False

        fuzzy_cap_candidates: Set[str] = set()
        for c_dom in cand_domains:
            fuzzy_cap_candidates |= {tok for tok in re.split(r"[.\-_]", c_dom) if tok}
        for c_sub in cand_subdomains:
            fuzzy_cap_candidates |= {tok for tok in re.split(r"[.\-_]", c_sub) if tok}
        fuzzy_cap_candidates |= decoded_tokens | skeleton_tokens

        for brand, legitimate_domains in TARGETED_BRANDS:
            is_legit = any(
                registered_domain == legit or registered_domain.endswith("." + legit)
                for legit in legitimate_domains
            )
            if is_legit:
                continue

            is_short = len(brand) <= 4

            # 5a. Canonical match: exact tokens, dehyphen equality, controlled compounds,
            #     hyphen-window joins (wells-fargo -> wellsfargo)
            has_canonical = (
                _compound_token_match(brand, all_tokens, dehyphen_domain, is_short)
                or _compound_token_match(brand, decoded_tokens, decoded_dehyphen, is_short)
                or _hyphen_window_match(brand, ordered_original)
                or _hyphen_window_match(brand, ordered_decoded)
            )

            # 5b. Confusable-skeleton match (Cyrillic/Greek homographs, IDNA forms)
            has_skeleton = False
            if not has_canonical:
                has_skeleton = (
                    _compound_token_match(brand, skeleton_tokens, skeleton_dehyphen, is_short)
                    or _hyphen_window_match(brand, ordered_skeleton)
                )

            # 5c. Typo / leetspeak candidate match (per-token, context-bounded)
            has_typosquat = False
            if not has_canonical and not has_skeleton:
                for c_dom in cand_domains:
                    c_tokens = {tok for tok in re.split(r"[.\-_]", c_dom) if tok}
                    c_dehyphen = c_dom.replace("-", "")
                    if (
                        _compound_token_match(brand, c_tokens, c_dehyphen, is_short)
                        or _hyphen_window_match(brand, _ordered_label_tokens(c_dom))
                    ):
                        has_typosquat = True
                        break
                if not has_typosquat:
                    for c_sub in cand_subdomains:
                        c_sub_tokens = {tok for tok in re.split(r"[.\-_]", c_sub) if tok}
                        c_sub_dehyphen = c_sub.replace(".", "").replace("-", "")
                        if (
                            _compound_token_match(brand, c_sub_tokens, c_sub_dehyphen, is_short)
                            or _hyphen_window_match(brand, _ordered_label_tokens(c_sub))
                        ):
                            has_typosquat = True
                            break

            # 5d. Bounded token-level edit distance (corroboration-gated)
            has_edit_distance = False
            if not (has_canonical or has_skeleton or has_typosquat):
                cap = brand_edit_distance_cap(brand)
                if cap is not None and has_fuzzy_match_corroboration(
                    normalized_domain, domain, subdomain, suffix
                ):
                    for tok in fuzzy_cap_candidates:
                        if abs(len(tok) - len(brand)) > cap:
                            continue
                        # Plural/possessive forms are ordinary words, never typosquats
                        if tok in (brand + "s", brand + "es"):
                            continue
                        if bounded_edit_distance(tok, brand, cap) <= cap:
                            has_edit_distance = True
                            break

            if has_canonical or has_skeleton or has_typosquat or has_edit_distance:
                is_typo_case = has_skeleton or has_typosquat or has_edit_distance
                if has_skeleton:
                    title = f"Homoglyph / Confusable Domain Impersonation: {brand.capitalize()}"
                    match_method = "confusableSkeleton"
                elif has_edit_distance:
                    title = f"Typosquatting / Leetspeak Impersonation: {brand.capitalize()}"
                    match_method = "boundedEditDistance"
                elif has_typosquat:
                    title = f"Typosquatting / Leetspeak Impersonation: {brand.capitalize()}"
                    match_method = "normalizationCandidate"
                else:
                    title = f"Brand Impersonation Detected: {brand.capitalize()}"
                    match_method = "exactToken"

                if is_typo_case:
                    description = (
                        f"The domain mimics '{brand}' through controlled visual/character normalization "
                        f"(e.g. {domain}), targeting users of official domains ({', '.join(legitimate_domains)})."
                    )
                else:
                    description = (
                        f"The domain contains the brand term '{brand}', but is not affiliated with official "
                        f"domain(s) ({', '.join(legitimate_domains)}). High likelihood of credential harvesting."
                    )

                evidence = {
                    "targetedBrand": brand,
                    "domain": domain,
                    "subdomain": subdomain,
                    "registeredDomain": registered_domain,
                    "isTyposquat": is_typo_case,
                    "matchMethod": match_method,
                    "dedupKey": f"DECEPTIVE_HOSTNAME:{normalized_domain.lower()}",
                }
                # Preserve original evidence while exposing normalized representations
                if decoded_domain != domain or decoded_subdomain != subdomain:
                    evidence["idnaDecodedDomain"] = decoded_domain
                    evidence["idnaDecodedSubdomain"] = decoded_subdomain
                if skeleton_domain != decoded_domain:
                    evidence["confusableSkeleton"] = skeleton_domain

                findings.append(RawFinding(
                    category="PHISHING_INDICATOR",
                    severity="CRITICAL",
                    title=title,
                    description=description,
                    evidence=evidence,
                    confidence=94.0 if is_typo_case else 92.0
                ))

        # 6. Generic Staging or Ephemeral Infrastructure Pattern Detection (Phase 7.3)
        matched_infra_tokens = [
            tok for tok in GENERIC_INFRASTRUCTURE_TOKENS
            if tok in normalized_domain.lower()
        ]
        if matched_infra_tokens and registered_domain not in RECOGNIZED_AUTHENTIC_DOMAINS:
            findings.append(RawFinding(
                category="DOMAIN_REPUTATION",
                severity="INFO",
                title="Generic Staging or Ephemeral Infrastructure Pattern",
                description="Hostname exhibits naming conventions typical of unverified staging, development, or routing infrastructure.",
                evidence={
                    "signal": "STAGING_PATTERN",
                    "matchedTokens": matched_infra_tokens,
                    "registeredDomain": registered_domain,
                    "isInformationalInfrastructure": True,
                    "dedupKey": "INFRA_STAGING_PATTERN",
                },
                confidence=80.0,
            ))

        # 7. Informational domain taxonomy finding
        findings.append(RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Domain Taxonomy Verified",
            description=f"Extracted domain: {domain}, suffix: {suffix}, subdomains: {subdomain or 'none'}.",
            evidence={"subdomain": subdomain, "domain": domain, "suffix": suffix, "registeredDomain": registered_domain},
            confidence=100.0
        ))

        return findings
