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
    score, verdict, confidence, threats, risk_factors = engine.evaluate(findings)
    assert score >= 65
    assert verdict in {"SUSPICIOUS", "MALICIOUS"}
    assert len(risk_factors) == 2
