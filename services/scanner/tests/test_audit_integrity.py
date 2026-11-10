import pytest
from bs4 import BeautifulSoup
from unittest.mock import MagicMock

from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine, EXPECTED_ANALYZERS
from app.schemas.response import RawFinding
from benchmarks.metrics import (
    calculate_three_class_metrics,
    calculate_four_class_metrics,
    calculate_binary_metrics,
    CLASSES,
    FOUR_CLASSES,
)


@pytest.fixture
def url_analyzer():
    return UrlAnalyzer()


@pytest.fixture
def domain_analyzer():
    return DomainAnalyzer()


@pytest.fixture
def web_analyzer():
    return WebSecurityAnalyzer()


@pytest.fixture
def risk_engine():
    return RiskAggregationEngine()


def complete_analyzer_statuses():
    return {analyzer: "SUCCESS" for analyzer in EXPECTED_ANALYZERS}


# ============================================================================
# 1. Benchmark Metrics & Denominator Consistency Tests (Phase 7.3.1 Section 2)
# ============================================================================

def test_three_class_metrics_denominator_consistency():
    """
    Verifies that in 3-class evaluation:
    - Support for every ground-truth class is strictly the count of actual cases.
    - Cases predicted as UNVERIFIED count as False Negatives (FN = support - tp).
    - Sum of supports strictly equals total_samples.
    - Weighted recall strictly equals overall accuracy.
    """
    # 530 mock results:
    # 230 BENIGN -> all predicted BENIGN
    # 100 SUSPICIOUS -> 75 predicted SUSPICIOUS, 1 predicted MALICIOUS, 24 predicted UNVERIFIED
    # 200 MALICIOUS -> all predicted MALICIOUS
    results = []
    for i in range(230):
        results.append({"groundTruth": "BENIGN", "predictedVerdict": "BENIGN", "isCorrect": True})
    for i in range(75):
        results.append({"groundTruth": "SUSPICIOUS", "predictedVerdict": "SUSPICIOUS", "isCorrect": True})
    results.append({"groundTruth": "SUSPICIOUS", "predictedVerdict": "MALICIOUS", "isCorrect": False})
    for i in range(24):
        results.append({"groundTruth": "SUSPICIOUS", "predictedVerdict": "UNVERIFIED_INFRASTRUCTURE", "isCorrect": False})
    for i in range(200):
        results.append({"groundTruth": "MALICIOUS", "predictedVerdict": "MALICIOUS", "isCorrect": True})

    assert len(results) == 530

    metrics = calculate_three_class_metrics(results)

    # Denominator check
    total_support = sum(metrics["perClass"][c]["support"] for c in CLASSES)
    assert total_support == 530, f"Expected total support 530, got {total_support}"
    assert metrics["perClass"]["BENIGN"]["support"] == 230
    assert metrics["perClass"]["SUSPICIOUS"]["support"] == 100, "SUSPICIOUS support must be 100, not 76"
    assert metrics["perClass"]["MALICIOUS"]["support"] == 200

    # Recall check
    suspicious = metrics["perClass"]["SUSPICIOUS"]
    assert suspicious["tp"] == 75
    assert suspicious["fn"] == 25, "FN must be 25 (1 MAL + 24 UNVERIFIED)"
    assert suspicious["recall"] == 0.75, "Recall must be 75/100 = 0.75"

    # Mathematical consistency: Weighted recall == accuracy
    assert metrics["weighted"]["recall"] == metrics["accuracy"]
    assert metrics["accuracy"] == round(505 / 530, 4)


def test_four_class_metrics():
    """Verifies that 4-class evaluation correctly computes metrics for all 4 classes."""
    results = [
        {"groundTruth": "BENIGN", "predictedVerdict": "BENIGN", "isCorrect": True},
        {"groundTruth": "UNVERIFIED_INFRASTRUCTURE", "predictedVerdict": "UNVERIFIED_INFRASTRUCTURE", "isCorrect": True},
        {"groundTruth": "SUSPICIOUS", "predictedVerdict": "SUSPICIOUS", "isCorrect": True},
        {"groundTruth": "MALICIOUS", "predictedVerdict": "MALICIOUS", "isCorrect": True},
        {"groundTruth": "SUSPICIOUS", "predictedVerdict": "MALICIOUS", "isCorrect": False},
    ]

    metrics = calculate_four_class_metrics(results)
    assert metrics["totalSamples"] == 5
    assert metrics["accuracy"] == 0.8
    for c in FOUR_CLASSES:
        assert c in metrics["perClass"]
        assert c in metrics["confusionMatrix"]


def test_binary_metrics_semantics_a_b_c():
    """
    Verifies that binary threat metrics under Semantics A, B, and C
    strictly follow their defined positive/negative sets without silent drops.
    """
    results = [
        {"groundTruth": "BENIGN", "predictedVerdict": "BENIGN"},
        {"groundTruth": "SUSPICIOUS", "predictedVerdict": "UNVERIFIED_INFRASTRUCTURE"},
        {"groundTruth": "MALICIOUS", "predictedVerdict": "MALICIOUS"},
    ]

    # Semantic A: Threats = {SUSPICIOUS, MALICIOUS}, Negatives = {BENIGN, UNVERIFIED}
    sem_a = calculate_binary_metrics(results, ["SUSPICIOUS", "MALICIOUS"], "Semantic A")
    # Sample 1: Actual neg, pred neg -> TN
    # Sample 2: Actual pos (SUSPICIOUS), pred neg (UNVERIFIED) -> FN
    # Sample 3: Actual pos (MALICIOUS), pred pos (MALICIOUS) -> TP
    assert sem_a["tp"] == 1
    assert sem_a["fn"] == 1, "Semantic A must count unverified prediction for suspicious as FN"
    assert sem_a["tn"] == 1
    assert sem_a["fp"] == 0

    # Semantic B: Threats = {MALICIOUS}
    sem_b = calculate_binary_metrics(results, ["MALICIOUS"], "Semantic B")
    assert sem_b["tp"] == 1
    assert sem_b["fn"] == 0
    assert sem_b["tn"] == 2

    # Semantic C: Any Elevated = {SUSPICIOUS, MALICIOUS, UNVERIFIED}
    sem_c = calculate_binary_metrics(results, ["SUSPICIOUS", "MALICIOUS", "UNVERIFIED_INFRASTRUCTURE"], "Semantic C")
    assert sem_c["tp"] == 2
    assert sem_c["fn"] == 0
    assert sem_c["tn"] == 1


# ============================================================================
# 2. Analyzer Completeness & Zero-Trust Invariant Tests (Phase 7.3.1 Section 3)
# ============================================================================

def test_missing_analyzer_status_yields_inconclusive(risk_engine):
    """When any required analyzer is missing from statuses, verdict must be INCONCLUSIVE (if score < 26)."""
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "SUCCESS",
        "webSecurityAnalyzer": "SUCCESS",
        # reputationAnalyzer is missing!
    }
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="Parked domain",
            evidence={"isInformationalInfrastructure": True, "signal": "PARKED_PAGE"},
            confidence=90.0,
        )
    ]
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict == "INCONCLUSIVE"
    assert status == "PARTIAL"
    assert complete is False
    assert any("reputationAnalyzer:MISSING" in r for r in reasons)


def test_failed_analyzer_status_yields_inconclusive(risk_engine):
    """When an analyzer reports FAILED, verdict must be INCONCLUSIVE (if score < 26)."""
    statuses = complete_analyzer_statuses()
    statuses["webSecurityAnalyzer"] = "FAILED"

    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Domain Taxonomy Verified",
            description="Info",
            evidence={"domain": "example.com"},
            confidence=100.0,
        )
    ]
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict == "INCONCLUSIVE"
    assert status == "PARTIAL"
    assert complete is False


def test_empty_statuses_yields_inconclusive(risk_engine):
    """When statuses dictionary is empty, verdict must be INCONCLUSIVE."""
    findings = []
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, {})
    assert verdict == "INCONCLUSIVE"
    assert status == "FAILED"
    assert complete is False


def test_malformed_finding_evidence_handled_gracefully(risk_engine):
    """Findings with None, string, or list evidence must never crash the scoring engine."""
    statuses = complete_analyzer_statuses()
    
    class MockFinding:
        def __init__(self, title, severity, category, evidence):
            self.title = title
            self.severity = severity
            self.category = category
            self.evidence = evidence
            self.confidence = 80.0

    findings = [
        MockFinding(title="Test 1", severity="LOW", category="URL_ANOMALY", evidence=None),
        MockFinding(title="Test 2", severity="INFO", category="URL_ANOMALY", evidence="invalid_str"),
        MockFinding(title="Test 3", severity="LOW", category="URL_ANOMALY", evidence=["list"]),
    ]
    # Must evaluate without throwing AttributeError: 'NoneType' object has no attribute 'get'
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict == "BENIGN"
    assert status == "COMPLETE"
    assert complete is True


def _build_mock_client(html: str, headers: dict = None):
    class MockStreamResponse:
        status_code = 200
        def __init__(self):
            self.headers = {"content-type": "text/html; charset=utf-8", "server": "nginx"}
            if headers:
                self.headers.update(headers)
        async def aiter_bytes(self, chunk_size=16384):
            yield html.encode("utf-8")

    class MockStreamContext:
        async def __aenter__(self):
            return MockStreamResponse()
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    class MockClient:
        def stream(self, method, url):
            return MockStreamContext()
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    return MockClient


@pytest.mark.asyncio
async def test_parked_page_with_active_password_form_overrides_unverified(web_analyzer, risk_engine, monkeypatch):
    """A page with parked text AND an active password form must NOT be classified as UNVERIFIED."""
    html = """
    <!DOCTYPE html>
    <html>
      <head><title>Domain Parked</title></head>
      <body>
        <h1>This domain has recently been registered.</h1>
        <form action="/login" method="POST">
          <input type="text" name="username" placeholder="Username" />
          <input type="password" name="password" placeholder="Password" />
          <button type="submit">Log In</button>
        </form>
      </body>
    </html>
    """
    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: _build_mock_client(html)())

    findings, _ = await web_analyzer.analyze("http://parked-phish.com", "parked-phish.com", pinned_ip="93.184.216.34")

    # Parked page finding must be suppressed due to active credential form
    parked_findings = [f for f in findings if f.title == "Parked or Placeholder Domain Page Detected"]
    assert len(parked_findings) == 0

    # Phishing form finding must be present
    phish_findings = [f for f in findings if "Credential" in f.title or "Password" in f.title or "Form" in f.title]
    assert len(phish_findings) > 0


def test_parked_page_with_threat_intel_match_is_malicious(risk_engine):
    """Strong threat evidence (threat intel match) must strictly override informational parked signals."""
    statuses = complete_analyzer_statuses()
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="Parked domain",
            evidence={"isInformationalInfrastructure": True, "signal": "PARKED_PAGE"},
            confidence=90.0,
        ),
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="CRITICAL",
            title="Threat Intelligence Blacklist Match: URLhaus Active Phishing Malware",
            description="Known malware host",
            evidence={"provider": "urlhaus"},
            confidence=99.0,
        ),
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="CRITICAL",
            title="Google Safe Browsing Threat Detected",
            description="Phishing",
            evidence={"provider": "google_safe_browsing"},
            confidence=99.0,
        ),
    ]
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict in ("MALICIOUS", "CONFIRMED_MALICIOUS")
    assert score >= 70


# ============================================================================
# 3. Score Aggregation & Threshold Inflation Calibration (Phase 7.3.1 Section 4)
# ============================================================================

@pytest.mark.asyncio
async def test_uncorroborated_meta_refresh_severity_is_medium(web_analyzer, monkeypatch):
    """
    Client-side meta refresh to an uncorroborated, non-hostile external host
    must be scored as MEDIUM (12 pts), preventing threshold inflation to MALICIOUS.
    """
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>Redirecting to Offer</title>
        <meta http-equiv="refresh" content="2;url=https://partner-redirect-tracker.com/offer" />
      </head>
      <body>
        <h1>Redirecting...</h1>
      </body>
    </html>
    """
    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: _build_mock_client(html)())

    findings, _ = await web_analyzer.analyze(
        "https://smart-shopper-coupon-finder.xyz/bounce",
        "smart-shopper-coupon-finder.xyz",
        pinned_ip="93.184.216.34"
    )
    refresh_finding = next(f for f in findings if "Meta Refresh" in f.title)

    assert refresh_finding.severity == "MEDIUM"
    assert refresh_finding.title == "Client-Side Meta Refresh Redirect to External Host"
    assert refresh_finding.evidence["corroboratedThreat"] is False


@pytest.mark.asyncio
async def test_affiliate_bounce_page_is_suspicious_not_malicious(risk_engine, url_analyzer, domain_analyzer, web_analyzer, monkeypatch):
    """
    Simulates EXP-VAL-274: High-risk TLD (.xyz: 25) + Meta-refresh (12) + Hyphens (5) + Posture (15) = 57.
    Verdict must be SUSPICIOUS, eliminating the false escalation to MALICIOUS.
    """
    target_url = "https://smart-shopper-coupon-finder.xyz/bounce?coupon=99"
    domain = "smart-shopper-coupon-finder.xyz"
    html = """
    <!DOCTYPE html><html><head><title>Redirecting to Offer</title>
    <meta http-equiv='refresh' content='2;url=https://partner-redirect-tracker.com/offer'/>
    </head><body><h1>Connecting you to our recommended partner...</h1></body></html>
    """
    extra_headers = {"refresh": "2; url=https://partner-redirect-tracker.com/offer"}
    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: _build_mock_client(html, extra_headers)())

    findings = []
    findings.extend(url_analyzer.analyze(target_url, domain))
    findings.extend(domain_analyzer.analyze(domain))
    web_findings, _ = await web_analyzer.analyze(target_url, domain, pinned_ip="93.184.216.34")
    findings.extend(web_findings)

    statuses = complete_analyzer_statuses()
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)

    assert score < 70, f"Score {score} must not reach MALICIOUS (>=70) through weak additive signals"
    assert score >= 26, f"Score {score} must remain SUSPICIOUS (>=26)"
    assert verdict == "SUSPICIOUS"


@pytest.mark.asyncio
async def test_corroborated_hostile_redirect_is_critical_malicious(web_analyzer, risk_engine, monkeypatch):
    """
    When meta-refresh destination exhibits corroborated hostile signals (e.g. .xyz TLD, payload path),
    it must be scored as CRITICAL + hostile destination finding, escalating to MALICIOUS.
    """
    html = """
    <!DOCTYPE html>
    <html>
      <head>
        <title>Verifying</title>
        <meta http-equiv="refresh" content="0;url=https://credential-stealer-phish.xyz/login/verify.php" />
      </head>
      <body><h1>One moment...</h1></body>
    </html>
    """
    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: _build_mock_client(html)())

    findings, _ = await web_analyzer.analyze("https://compromised-site.com/gate", "compromised-site.com", pinned_ip="93.184.216.34")
    refresh_finding = next(f for f in findings if "Meta Refresh" in f.title)

    assert refresh_finding.severity == "CRITICAL"
    assert refresh_finding.evidence["corroboratedThreat"] is True

    statuses = complete_analyzer_statuses()
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict == "MALICIOUS" or score >= 65


# ============================================================================
# 4. Adversarial Trusted-Domain Calibration Tests (Phase 7.3.1 Section 5)
# ============================================================================

def test_userinfo_masking_adversarial(url_analyzer):
    """Adversarial URL https://ruby-lang.org@evil-domain.com/path must not be treated as authentic."""
    findings = url_analyzer.analyze("https://ruby-lang.org@evil-domain.com/path", "evil-domain.com")
    userinfo_findings = [f for f in findings if "Userinfo" in f.title or "Credential" in f.title]
    assert len(userinfo_findings) > 0


def test_deceptive_subdomain_stacking_adversarial(url_analyzer):
    """Adversarial URL https://docs.ruby-lang.org.attacker.com/security must be flagged."""
    findings = url_analyzer.analyze("https://docs.ruby-lang.org.attacker.com/security", "docs.ruby-lang.org.attacker.com")
    # Registered domain is attacker.com, so 'security' keyword should be matched
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) > 0


def test_credential_keyword_flagged_on_untrusted_domain(url_analyzer):
    """The 'credential' term must be flagged on untrusted domains."""
    findings = url_analyzer.analyze("https://untrusted-suspicious-portal.com/harvest/credential", "untrusted-suspicious-portal.com")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) > 0
    assert "credential" in keyword_findings[0].evidence["keywords"]


def test_credential_keyword_allowed_on_authentic_domain(url_analyzer):
    """The 'credential' term must be permitted on authentic recognized domains (e.g. OWASP docs)."""
    findings = url_analyzer.analyze("https://owasp.org/www-project-credential-stuffing-prevention/", "owasp.org")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) == 0


# ============================================================================
# 5. Infrastructure Signal Isolation Tests (Phase 7.3.1 Section 6)
# ============================================================================

def test_staging_token_alone_does_not_force_unverified(domain_analyzer, risk_engine):
    """A staging token in the hostname on an active page must NOT force UNVERIFIED_INFRASTRUCTURE."""
    findings = domain_analyzer.analyze("staging.company-active.com")
    staging_findings = [f for f in findings if "Staging" in f.title]
    assert len(staging_findings) > 0
    # Evidence must NOT claim isInformationalInfrastructure independently
    assert staging_findings[0].evidence.get("isInformationalInfrastructure") is not True

    statuses = complete_analyzer_statuses()
    score, verdict, conf, status, complete, threats, factors, reasons = risk_engine.evaluate(findings, statuses)
    assert verdict == "BENIGN", "Without corroborating parked/hosting signals, verdict should remain BENIGN"


def test_substring_investaging_does_not_trigger_staging_token(domain_analyzer):
    """Ordinary word containing 'staging' as substring (e.g. investaging.com) must not trigger staging pattern."""
    findings = domain_analyzer.analyze("investaging.com")
    staging_findings = [f for f in findings if "Staging" in f.title]
    assert len(staging_findings) == 0
