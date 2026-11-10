"""
Security Regression and Domain Intelligence Test Suite for Tranco Top-10K Integration (Phase 7.1).

Covers:
1. Legitimate JetBrains authentication portal
2. Legitimate Okta authentication portal
3. Legitimate Snowflake authentication portal
4. Legitimate Datadog authentication portal
5. Legitimate Login.gov authentication portal
6. Legitimate Coursera authentication portal
7. Legitimate Etsy authentication portal
8. Subdomain deception: jetbrains.com.attacker.example
9. Subdomain deception: login.jetbrains.com.attacker.example
10. Typosquatted popular brands (0kta-login.com, jetbr1ans.com)
11. Unicode / IDNA confusables (xn--okt-7ka.com)
12. Malicious content / phishing form on a popular domain (threat unsuppressed)
13. Popular domain missing from downloaded dataset (graceful fallback)
14. Corrupted, empty, and unavailable dataset files (fault tolerance)
15. Dataset replacement during active scanner requests (atomic thread-safe reload)
"""

import os
import json
import tempfile
import threading
from pathlib import Path
import pytest

from app.intelligence.tranco_provider import TrancoIntelligenceProvider, BUNDLED_FALLBACK_DOMAINS
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine
from app.schemas.response import RawFinding


@pytest.fixture
def url_analyzer():
    return UrlAnalyzer()


# -----------------------------------------------------------------------------
# 1-7: Legitimate SaaS Authentication Portals
# -----------------------------------------------------------------------------

def test_legitimate_jetbrains_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://account.jetbrains.com/login", "account.jetbrains.com")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate JetBrains login should not be flagged as a phishing indicator"


def test_legitimate_okta_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://login.okta.com/signin/v1/identifier", "login.okta.com")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate Okta signin should not be flagged as a phishing indicator"


def test_legitimate_snowflake_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://auth.snowflake.com/account/login", "auth.snowflake.com")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate Snowflake auth should not be flagged as a phishing indicator"


def test_legitimate_datadog_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://app.datadoghq.com/account/login", "app.datadoghq.com")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate Datadog account login should not be flagged as a phishing indicator"


def test_legitimate_login_gov_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://secure.login.gov/sign_in", "secure.login.gov")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate login.gov signin should not be flagged as a phishing indicator"


def test_legitimate_coursera_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://accounts.coursera.org/login", "accounts.coursera.org")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate Coursera accounts login should not be flagged as a phishing indicator"


def test_legitimate_etsy_authentication(url_analyzer):
    findings = url_analyzer.analyze("https://secure.etsy.com/signin", "secure.etsy.com")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) == 0, "Legitimate Etsy signin should not be flagged as a phishing indicator"


# -----------------------------------------------------------------------------
# 8-9: Deceptive Subdomain Stacking / Attacker-Controlled Destinations
# -----------------------------------------------------------------------------

def test_deceptive_subdomain_jetbrains_attacker(url_analyzer):
    """Popular brand in subdomain under untrusted registrable domain must NOT receive trusted treatment."""
    findings = url_analyzer.analyze("https://jetbrains.com.attacker.example/login", "jetbrains.com.attacker.example")
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) > 0, "jetbrains.com.attacker.example must be flagged for phishing keywords"
    assert any("Sensitive Authentication Keywords" in f.title for f in phish_findings)


def test_deceptive_subdomain_login_jetbrains_attacker(url_analyzer):
    findings = url_analyzer.analyze(
        "https://login.jetbrains.com.attacker.example/auth",
        "login.jetbrains.com.attacker.example"
    )
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
    assert len(phish_findings) > 0, "Subdomain stacking with brand name must not be suppressed"


# -----------------------------------------------------------------------------
# 10: Typosquatted Popular Brands
# -----------------------------------------------------------------------------

def test_typosquatted_popular_brands(url_analyzer):
    """Typosquatted domain variations must not match popular domain intelligence."""
    for url, host in [
        ("https://0kta-login.com/signin", "0kta-login.com"),
        ("https://jetbr1ans.com/login", "jetbr1ans.com"),
        ("https://courser4.org/signin", "courser4.org"),
    ]:
        findings = url_analyzer.analyze(url, host)
        phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]
        assert len(phish_findings) > 0, f"{url} must trigger phishing keyword finding"


# -----------------------------------------------------------------------------
# 11: Unicode / IDNA Confusables
# -----------------------------------------------------------------------------

def test_unicode_and_idna_confusables(url_analyzer):
    """Punycode/homograph domains must never receive authentic domain dampening."""
    # xn--okt-7ka.com is okta.com with Cyrillic 'а'
    findings = url_analyzer.analyze("https://xn--okt-7ka.com/login", "xn--okt-7ka.com")
    anomaly_findings = [f for f in findings if f.category == "URL_ANOMALY"]
    phish_findings = [f for f in findings if f.category == "PHISHING_INDICATOR"]

    assert any("Punycode" in f.title for f in anomaly_findings), "Punycode domain must trigger anomaly finding"
    assert len(phish_findings) > 0, "Punycode domain must not have authentication keywords suppressed"


# -----------------------------------------------------------------------------
# 12: Malicious Content Hosted on a Popular Domain (Threats Unsuppressed)
# -----------------------------------------------------------------------------

def test_malicious_content_on_popular_domain_unsuppressed():
    """
    Even if a domain is popular (e.g. github.com, drive.google.com), active malicious
    evidence (credential harvesting form, external exfiltration) must score full severity.
    """
    risk_engine = RiskAggregationEngine()

    # Simulate URL analyzer output (keyword suppressed on authentic host)
    url_findings = [
        RawFinding(
            category="URL_ANOMALY",
            severity="INFO",
            title="Clean Authority",
            description="Authentic domain structure.",
            confidence=90.0,
        )
    ]
    # Simulate WebSecurityAnalyzer detecting credential harvesting and exfiltration
    active_threat_findings = [
        RawFinding(
            category="WEB_SECURITY",
            severity="CRITICAL",
            title="Payment / Financial Credential Harvesting Form Detected",
            description="Phishing form collecting credit card data.",
            evidence={"formAction": "http://evil-collector.xyz/steal.php"},
            confidence=100.0,
        ),
        RawFinding(
            category="WEB_SECURITY",
            severity="CRITICAL",
            title="Form Submits Sensitive Credentials to External Third-Party Host",
            description="Form action submits to external host.",
            evidence={"actionHost": "evil-collector.xyz"},
            confidence=100.0,
        ),
    ]

    score, verdict, confidence, analysis_status, analysis_complete, risk_factors, threats, _ = risk_engine.evaluate(
        findings=url_findings + active_threat_findings,
        analyzer_statuses={
            "urlAnalyzer": "SUCCESS",
            "domainAnalyzer": "SUCCESS",
            "tlsAnalyzer": "SUCCESS",
            "webSecurityAnalyzer": "SUCCESS",
            "reputationAnalyzer": "SUCCESS",
        },
    )

    assert verdict in ("MALICIOUS", "CONFIRMED_MALICIOUS"), "Compromised popular domain with active phishing must be classified as MALICIOUS or CONFIRMED_MALICIOUS"
    assert score >= 70, f"Expected riskScore >= 70, got {score}"


# -----------------------------------------------------------------------------
# 13: Popular Domain Missing from Downloaded Dataset (Graceful Fallback)
# -----------------------------------------------------------------------------

def test_missing_popular_domain_fallback():
    """A popular domain absent from an arbitrary dataset still gets checked against static fallback."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({
            "source": "Minimal Test",
            "version": "1.0",
            "domains": ["rare-domain.com", "example.org"] + [f"dom{i}.com" for i in range(120)]
        }, tf)
        temp_path = tf.name

    try:
        prov = TrancoIntelligenceProvider(dataset_path=Path(temp_path))
        assert prov.is_popular_domain("rare-domain.com") is True
        # Missing domain is simply evaluated as non-popular without crash
        assert prov.is_popular_domain("unlisted-brand.com") is False
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# -----------------------------------------------------------------------------
# 14: Fault Tolerance: Corrupted, Empty, Stale, and Unavailable Dataset Files
# -----------------------------------------------------------------------------

def test_corrupted_dataset_file_falls_back_gracefully():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write("{ this is invalid json !!!")
        temp_path = tf.name

    try:
        prov = TrancoIntelligenceProvider(dataset_path=Path(temp_path))
        meta = prov.get_metadata()
        assert meta["status"] == "DEGRADED_CORRUPT"
        # Bundled fallback domains remain operational
        assert prov.is_popular_domain("google.com") is True
        assert prov.is_popular_domain("github.com") is True
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_empty_dataset_file_falls_back_gracefully():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        tf.write("")
        temp_path = tf.name

    try:
        prov = TrancoIntelligenceProvider(dataset_path=Path(temp_path))
        meta = prov.get_metadata()
        assert meta["status"] == "DEGRADED_CORRUPT"
        assert prov.is_popular_domain("okta.com") is True
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_unavailable_dataset_file_falls_back_gracefully():
    non_existent = Path("/tmp/definitely_not_existing_tranco_12345.json")
    prov = TrancoIntelligenceProvider(dataset_path=non_existent)
    meta = prov.get_metadata()
    assert meta["status"] == "DEGRADED_FALLBACK"
    assert prov.is_popular_domain("microsoft.com") is True


# -----------------------------------------------------------------------------
# 15: Concurrency Safety: Dataset Replacement During Active Scanner Requests
# -----------------------------------------------------------------------------

def test_dataset_replacement_during_active_requests():
    """Simulates active concurrent queries while reloading a new dataset in the background."""
    provider = TrancoIntelligenceProvider()
    errors = []
    stop_event = threading.Event()

    def query_worker():
        while not stop_event.is_set():
            try:
                # Concurrent queries
                _ = provider.is_popular_domain("jetbrains.com")
                _ = provider.is_popular_domain("unknown-attacker.xyz")
                _ = provider.get_metadata()
            except Exception as e:
                errors.append(e)

    threads = [threading.Thread(target=query_worker) for _ in range(5)]
    for t in threads:
        t.start()

    # Create replacement dataset and reload while workers are actively reading
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({
            "source": "Tranco Update Test",
            "version": "1.0.1",
            "checksumSha256": "abcdef123456",
            "domains": ["jetbrains.com", "okta.com", "new-popular-service.io"] + [f"batch{i}.net" for i in range(150)]
        }, tf)
        temp_path = tf.name

    try:
        for _ in range(10):
            success = provider.reload(new_path=Path(temp_path))
            assert success is True
    finally:
        stop_event.set()
        for t in threads:
            t.join()
        if os.path.exists(temp_path):
            os.remove(temp_path)

    assert len(errors) == 0, f"Concurrent lookups encountered errors during reload: {errors}"
    assert provider.is_popular_domain("new-popular-service.io") is True
