from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine
from app.schemas.response import RawFinding


def test_url_analyzer_detects_embedded_credentials():
    analyzer = UrlAnalyzer()
    findings = analyzer.analyze("https://legit.com@phishing-target.xyz/login", "phishing-target.xyz")
    severities = [f.severity for f in findings]
    assert "CRITICAL" in severities


def test_domain_analyzer_detects_brand_impersonation():
    analyzer = DomainAnalyzer()
    findings = analyzer.analyze("paypal-security-update.account-verify.xyz")
    titles = [f.title for f in findings]
    assert any("Brand Impersonation" in title for title in titles)


def test_risk_aggregation_scoring():
    engine = RiskAggregationEngine()
    findings = [
        RawFinding(
            category="PHISHING_INDICATOR",
            severity="CRITICAL",
            title="Credential Phishing Form",
            description="Test finding",
            confidence=95.0,
            evidence={}
        ),
        RawFinding(
            category="URL_ANOMALY",
            severity="HIGH",
            title="Punycode Homoglyph",
            description="Test finding",
            confidence=90.0,
            evidence={}
        )
    ]
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "SUCCESS",
        "webSecurityAnalyzer": "SUCCESS",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, analysis_status, is_complete, threats, risk_factors, reasons = engine.evaluate(
        findings, statuses
    )
    assert score >= 65
    assert verdict in {"SUSPICIOUS", "MALICIOUS"}
    assert len(risk_factors) == 2
    assert is_complete is True
    assert analysis_status == "COMPLETE"


def test_domain_analyzer_detects_government_impersonation():
    analyzer = DomainAnalyzer()
    findings = analyzer.analyze("incometax-refund-gov.xyz")
    titles = [f.title for f in findings]
    severities = [f.severity for f in findings]
    assert any("Government" in t for t in titles)
    assert "CRITICAL" in severities


def test_domain_analyzer_detects_academic_impersonation():
    analyzer = DomainAnalyzer()
    findings = analyzer.analyze("harvard-scholarship-portal.top")
    titles = [f.title for f in findings]
    assert any("Academic" in t or "Education" in t for t in titles)


def test_domain_analyzer_detects_banking_and_typosquatting():
    analyzer = DomainAnalyzer()
    # Banking: SBI bank impersonation on suspicious domain
    findings_bank = analyzer.analyze("sbi-card-verification.net")
    titles_bank = [f.title for f in findings_bank]
    assert any("Sbi" in t for t in titles_bank)

    # Typosquatting / leetspeak (paypa1 instead of paypal)
    findings_typo = analyzer.analyze("paypa1-security-check.com")
    titles_typo = [f.title for f in findings_typo]
    assert any("Typosquatting" in t for t in titles_typo)


def test_domain_analyzer_detects_recruitment_scam():
    analyzer = DomainAnalyzer()
    findings = analyzer.analyze("careers-portal-interview.top")
    titles = [f.title for f in findings]
    assert any("Recruitment" in t for t in titles)

