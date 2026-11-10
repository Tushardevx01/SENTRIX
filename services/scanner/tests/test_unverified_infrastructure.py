import pytest
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine, EXPECTED_ANALYZERS
from app.schemas.response import RawFinding


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
# 1. Authentic Documentation Calibration Tests (Phase 7.3 Section 5)
# ============================================================================

def test_ruby_lang_documentation_calibration(url_analyzer):
    """docs.ruby-lang.org/en/master/security_rdoc.html must not be penalized for 'security' keyword."""
    findings = url_analyzer.analyze("https://docs.ruby-lang.org/en/master/security_rdoc.html", "docs.ruby-lang.org")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) == 0


def test_podman_documentation_calibration(url_analyzer):
    """docs.podman.io/en/latest/Security.html must not be penalized for 'Security' keyword."""
    findings = url_analyzer.analyze("https://docs.podman.io/en/latest/Security.html", "docs.podman.io")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) == 0


def test_owasp_documentation_calibration(url_analyzer):
    """owasp.org/www-community/attacks/Credential_Stuffing must not be penalized for 'Credential' keyword."""
    findings = url_analyzer.analyze("https://owasp.org/www-community/attacks/Credential_Stuffing", "owasp.org")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) == 0


def test_unrecognized_domain_credential_keyword_remains_flagged(url_analyzer):
    """Non-authentic domains with 'credential' in path must remain strictly flagged."""
    findings = url_analyzer.analyze("https://unverified-credential-portal.xyz/login/credential", "unverified-credential-portal.xyz")
    keyword_findings = [f for f in findings if f.title == "Sensitive Authentication Keywords in URL"]
    assert len(keyword_findings) == 1
    assert "credential" in keyword_findings[0].evidence["keywords"]


def test_authority_masking_with_authentic_domain_remains_critical(url_analyzer):
    """Phishing using authentic domain in userinfo (e.g. microsoft.com@attacker.xyz) must remain CRITICAL."""
    findings = url_analyzer.analyze("https://microsoft.com@cloud-credential-vault.top/auth", "cloud-credential-vault.top")
    authority_findings = [f for f in findings if f.title == "Embedded User Credentials / Authority Masking"]
    assert len(authority_findings) == 1
    assert authority_findings[0].severity == "CRITICAL"


# ============================================================================
# 2. Generic Staging & Ephemeral Pattern Detection Tests (Phase 7.3 Section 3)
# ============================================================================

def test_generic_staging_token_detection(domain_analyzer):
    """Hostnames containing generic staging or development tokens must emit an informational finding."""
    findings = domain_analyzer.analyze("alpha-beta-staging-test-environment.net")
    staging_findings = [f for f in findings if f.title == "Generic Staging or Ephemeral Infrastructure Pattern"]
    assert len(staging_findings) == 1
    assert staging_findings[0].severity == "INFO"
    assert staging_findings[0].evidence["signal"] == "STAGING_PATTERN"
    assert "staging" in staging_findings[0].evidence["matchedTokens"]


def test_deployment_slot_pattern_detection(domain_analyzer):
    """Deployment slot hostname pattern must emit an informational staging finding."""
    findings = domain_analyzer.analyze("test-staging-deployment-slot-9.website")
    staging_findings = [f for f in findings if f.title == "Generic Staging or Ephemeral Infrastructure Pattern"]
    assert len(staging_findings) == 1
    assert "deployment-slot" in staging_findings[0].evidence["matchedTokens"]


def test_authentic_domain_does_not_emit_unverified_staging(domain_analyzer):
    """Authentic recognized platforms must not emit unverified infrastructure warnings."""
    findings = domain_analyzer.analyze("azure.com")
    staging_findings = [f for f in findings if f.title == "Generic Staging or Ephemeral Infrastructure Pattern"]
    assert len(staging_findings) == 0


# ============================================================================
# 3. Parked Landing Page Detection Tests (Phase 7.3 Section 3)
# ============================================================================

@pytest.mark.asyncio
async def test_parked_page_dom_detection(web_analyzer, monkeypatch):
    """Parked HTML body without forms must emit Parked or Placeholder Domain Page Detected."""
    html = (
        "<!DOCTYPE html><html><head><title>Domain Parked</title></head>"
        "<body><h1>Welcome to fast-content-delivery-cdn-test.club</h1>"
        "<p>This domain has recently been registered. Please check back soon.</p></body></html>"
    )

    class MockStreamResponse:
        status_code = 200
        headers = {"content-type": "text/html; charset=utf-8", "server": "nginx"}
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

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings, metadata = await web_analyzer.analyze(
        "http://fast-content-delivery-cdn-test.club",
        "fast-content-delivery-cdn-test.club",
        pinned_ip="93.184.216.34"
    )

    parked_findings = [f for f in findings if f.title == "Parked or Placeholder Domain Page Detected"]
    assert len(parked_findings) == 1
    assert parked_findings[0].severity == "INFO"
    assert parked_findings[0].evidence["isInformationalInfrastructure"] is True


@pytest.mark.asyncio
async def test_parked_page_with_active_password_form_not_clean(web_analyzer, monkeypatch):
    """If a page has parked title but active password input, it must NOT be treated as harmless parked page."""
    html = (
        "<!DOCTYPE html><html><head><title>Domain Parked</title></head>"
        "<body><form action='/steal' method='POST'>"
        "<input type='text' name='username'><input type='password' name='passwd'>"
        "<input type='submit' value='Login'></form></body></html>"
    )

    class MockStreamResponse:
        status_code = 200
        headers = {"content-type": "text/html; charset=utf-8", "server": "nginx"}
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

    monkeypatch.setattr("httpx.AsyncClient", lambda *args, **kwargs: MockClient())

    findings, metadata = await web_analyzer.analyze(
        "http://fake-parked-phish.club",
        "fake-parked-phish.club",
        pinned_ip="93.184.216.34"
    )

    parked_findings = [f for f in findings if f.title == "Parked or Placeholder Domain Page Detected"]
    assert len(parked_findings) == 0


# ============================================================================
# 4. Risk Engine Verdict Assignment & Invariants (Phase 7.3 Section 2 & 6)
# ============================================================================

def test_unverified_infrastructure_verdict_assignment(risk_engine):
    """Low-scoring domain with parked page finding must be assigned UNVERIFIED_INFRASTRUCTURE."""
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="The destination resolves to a parked domain.",
            evidence={"isInformationalInfrastructure": True, "dedupKey": "INFRA_PARKED_PAGE"},
            confidence=90.0,
        ),
        RawFinding(
            category="WEB_SECURITY",
            severity="LOW",
            title="Missing Strict-Transport-Security (HSTS)",
            description="Lacks HSTS",
            evidence={"isPosture": True, "dedupKey": "POSTURE_MISSING_HSTS"},
            confidence=90.0,
        ),
    ]

    score, verdict, confidence, status, complete, threat_types, risk_factors, inconclusive = risk_engine.evaluate(
        findings, complete_analyzer_statuses()
    )

    assert verdict == "UNVERIFIED_INFRASTRUCTURE"
    assert score <= 25
    assert complete is True
    assert "Unverified / Parked Infrastructure (INFO)" in risk_factors


def test_threat_override_invariant_malicious_overrides_parked_page(risk_engine):
    """Strong malicious finding (score >= 70) strictly overrides UNVERIFIED_INFRASTRUCTURE."""
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="The destination resolves to a parked domain.",
            evidence={"isInformationalInfrastructure": True, "dedupKey": "INFRA_PARKED_PAGE"},
            confidence=90.0,
        ),
        RawFinding(
            category="PHISHING_INDICATOR",
            severity="CRITICAL",
            title="Brand Impersonation Detected: Box",
            description="Impersonates Box",
            evidence={"targetedBrand": "box"},
            confidence=95.0,
        ),
        RawFinding(
            category="PHISHING_INDICATOR",
            severity="CRITICAL",
            title="Cryptocurrency Seed-Phrase Harvesting Form Detected",
            description="Harvests mnemonic",
            evidence={},
            confidence=98.0,
        ),
    ]

    score, verdict, confidence, status, complete, threat_types, risk_factors, inconclusive = risk_engine.evaluate(
        findings, complete_analyzer_statuses()
    )

    assert verdict in ("MALICIOUS", "CONFIRMED_MALICIOUS")
    assert score >= 70


def test_active_suspicious_override_invariant(risk_engine):
    """Active threat indicators reaching score >= 26 yield SUSPICIOUS, not UNVERIFIED_INFRASTRUCTURE."""
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="The destination resolves to a parked domain.",
            evidence={"isInformationalInfrastructure": True, "dedupKey": "INFRA_PARKED_PAGE"},
            confidence=90.0,
        ),
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="HIGH",
            title="High-Risk Top-Level Domain (TLD)",
            description="High risk TLD",
            evidence={"dedupKey": "TLD_HIGH_RISK"},
            confidence=85.0,
        ),
        RawFinding(
            category="URL_ANOMALY",
            severity="LOW",
            title="Repeated Hyphenation in Hostname",
            description="Hyphens",
            evidence={"dedupKey": "HOST_HYPHENS"},
            confidence=65.0,
        ),
    ]

    score, verdict, confidence, status, complete, threat_types, risk_factors, inconclusive = risk_engine.evaluate(
        findings, complete_analyzer_statuses()
    )

    assert verdict == "SUSPICIOUS"
    assert score >= 26


def test_zero_trust_invariant_incomplete_analysis_yields_inconclusive(risk_engine):
    """Incomplete analyzer status must ALWAYS yield INCONCLUSIVE, never UNVERIFIED_INFRASTRUCTURE."""
    findings = [
        RawFinding(
            category="DOMAIN_REPUTATION",
            severity="INFO",
            title="Parked or Placeholder Domain Page Detected",
            description="The destination resolves to a parked domain.",
            evidence={"isInformationalInfrastructure": True, "dedupKey": "INFRA_PARKED_PAGE"},
            confidence=90.0,
        ),
    ]

    # Partial execution: webSecurityAnalyzer failed or missing
    partial_statuses = {"urlAnalyzer": "SUCCESS", "domainAnalyzer": "SUCCESS", "tlsAnalyzer": "SUCCESS"}

    score, verdict, confidence, status, complete, threat_types, risk_factors, inconclusive = risk_engine.evaluate(
        findings, partial_statuses
    )

    assert verdict == "INCONCLUSIVE"
    assert complete is False
    assert status == "PARTIAL"
