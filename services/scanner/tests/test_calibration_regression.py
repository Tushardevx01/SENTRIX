import pytest
from app.scoring.risk_engine import RiskAggregationEngine
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.schemas.response import RawFinding


def test_posture_findings_capped_at_15():
    """CAL-01: Verifies that cumulative defense-in-depth posture findings cannot exceed 15 points or trigger SUSPICIOUS."""
    engine = RiskAggregationEngine()
    findings = [
        RawFinding(category="WEB_SECURITY", severity="LOW", title="Missing Strict-Transport-Security (HSTS)", description="d", confidence=90.0),
        RawFinding(category="WEB_SECURITY", severity="LOW", title="Missing Content-Security-Policy (CSP)", description="d", confidence=85.0),
        RawFinding(category="WEB_SECURITY", severity="LOW", title="Missing Clickjacking Defenses", description="d", confidence=85.0),
        RawFinding(category="WEB_SECURITY", severity="LOW", title="Missing X-Content-Type-Options Header", description="d", confidence=90.0),
        RawFinding(category="WEB_SECURITY", severity="LOW", title="Server Header Leaks Exact Software Version", description="d", confidence=95.0),
        RawFinding(category="TLS_SECURITY", severity="LOW", title="No Embedded Certificate Transparency (CT) SCTs in Leaf Certificate", description="d", confidence=80.0),
    ]
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "SUCCESS",
        "webSecurityAnalyzer": "SUCCESS",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, status, is_complete, threat_types, risk_factors, reasons = engine.evaluate(findings, statuses)

    # 6 findings * 5 points = 30 points raw, but MUST be capped at 15
    assert score == 15
    assert verdict == "BENIGN"
    assert status == "COMPLETE"
    assert is_complete is True
    assert len(risk_factors) == 0


def test_authentic_domain_login_path_suppression():
    """CAL-02: Legitimate authentication paths on recognized domains do not trigger lexical phishing warnings."""
    analyzer = UrlAnalyzer()
    
    # Official GitHub login
    findings_gh = analyzer.analyze("https://github.com/login", "github.com")
    keyword_findings_gh = [f for f in findings_gh if "Sensitive Authentication Keywords" in f.title]
    assert len(keyword_findings_gh) == 0

    # Official Google Accounts signin
    findings_goog = analyzer.analyze("https://accounts.google.com/signin", "google.com")
    keyword_findings_goog = [f for f in findings_goog if "Sensitive Authentication Keywords" in f.title]
    assert len(keyword_findings_goog) == 0

    # Official PayPal customer signin
    findings_pp = analyzer.analyze("https://www.paypal.com/signin", "paypal.com")
    keyword_findings_pp = [f for f in findings_pp if "Sensitive Authentication Keywords" in f.title]
    assert len(keyword_findings_pp) == 0


def test_untrusted_domain_login_path_still_penalized():
    """CAL-02: Authentication paths on untrusted or spoofed domains MUST be penalized."""
    analyzer = UrlAnalyzer()

    # Phishing landing on untrusted domain
    findings = analyzer.analyze("http://untrusted-phish.xyz/login", "untrusted-phish.xyz")
    keyword_findings = [f for f in findings if "Sensitive Authentication Keywords" in f.title]
    assert len(keyword_findings) > 0
    assert keyword_findings[0].severity in {"MEDIUM", "HIGH"}

    # Subdomain stacking simulation
    findings_stack = analyzer.analyze("http://paypal.com.attacker.xyz/signin", "attacker.xyz")
    keyword_findings_stack = [f for f in findings_stack if "Sensitive Authentication Keywords" in f.title]
    assert len(keyword_findings_stack) > 0


def test_domain_short_brand_token_boundary():
    """CAL-03: Token-based matching prevents collateral false positives on ordinary words."""
    analyzer = DomainAnalyzer()

    # Collateral matches on SBI and Citi must NOT trigger
    findings_sbi = analyzer.analyze("isbilling.com")
    assert not any("Brand Impersonation" in f.title or "Sbi" in f.title for f in findings_sbi)

    findings_citi = analyzer.analyze("simplicity.org")
    assert not any("Brand Impersonation" in f.title or "Citi" in f.title for f in findings_citi)

    # Actual brand impersonation MUST trigger
    findings_sbi_phish = analyzer.analyze("sbi-card-verification.net")
    assert any("Sbi" in f.title for f in findings_sbi_phish)

    # Hyphen-tolerant Wells Fargo matching
    findings_wf = analyzer.analyze("wells-fargo-alert.info")
    assert any("Wellsfargo" in f.title for f in findings_wf)

    # BofA abbreviation
    findings_bofa = analyzer.analyze("b0fa-secure-portal.com")
    assert any("Bofa" in f.title for f in findings_bofa)


def test_leetspeak_multi_candidate_substitutions():
    """CAL-04: Multi-candidate normalization captures ambiguous substitutions like 1/t/i."""
    analyzer = DomainAnalyzer()

    # WhatsApp with 1 replacing t
    findings_wa = analyzer.analyze("wha1sapp-web-connect.com")
    assert any("Whatsapp" in f.title for f in findings_wa)

    # Spotify with 1 replacing i
    findings_sp = analyzer.analyze("spot1fy-premium.com")
    assert any("Spotify" in f.title for f in findings_sp)

    # PayPal with 1 replacing l
    findings_pp = analyzer.analyze("paypa1.com")
    assert any("Paypal" in f.title for f in findings_pp)


def test_finding_deduplication():
    """CAL-06: Overlapping findings sharing dedupKey are only counted once in scoring."""
    engine = RiskAggregationEngine()
    findings = [
        RawFinding(
            category="URL_ANOMALY",
            severity="HIGH",
            title="Direct IP Address in URL",
            description="Numeric IP in URL",
            evidence={"hostname": "198.51.100.42", "dedupKey": "HOST_RAW_IP"},
            confidence=95.0,
        ),
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="HIGH",
            title="Direct Numeric IP Host Resolution",
            description="Host is raw IP",
            evidence={"hostname": "198.51.100.42", "dedupKey": "HOST_RAW_IP"},
            confidence=90.0,
        ),
    ]
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "SUCCESS",
        "webSecurityAnalyzer": "SUCCESS",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, status, is_complete, threat_types, risk_factors, reasons = engine.evaluate(findings, statuses)

    # 2 duplicate HIGH findings (weight 25 each) MUST deduplicate to 25, not 50!
    assert score == 25
    assert verdict == "BENIGN"
    assert len(risk_factors) == 1
