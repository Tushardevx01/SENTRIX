import pytest
from app.scoring.risk_engine import RiskAggregationEngine
from app.schemas.response import RawFinding


def test_complete_clean_scan_yields_benign():
    engine = RiskAggregationEngine()
    findings = []
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "SUCCESS",
        "webSecurityAnalyzer": "SUCCESS",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, status, is_complete, threats, risk_factors, reasons = engine.evaluate(
        findings, statuses
    )

    assert score == 0
    assert verdict == "BENIGN"
    assert status == "COMPLETE"
    assert is_complete is True
    assert confidence >= 90
    assert len(reasons) == 0


def test_incomplete_scan_never_yields_benign():
    engine = RiskAggregationEngine()
    findings = []  # No findings discovered because analyzers timed out / failed
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "FAILED",
        "webSecurityAnalyzer": "TIMEOUT",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, status, is_complete, threats, risk_factors, reasons = engine.evaluate(
        findings, statuses
    )

    # ZERO-TRUST INVARIANT: Missing findings due to failures MUST NEVER be deemed BENIGN!
    assert verdict == "INCONCLUSIVE"
    assert status == "PARTIAL"
    assert is_complete is False
    assert confidence < 80  # Penalty applied
    assert len(reasons) >= 2
    assert any("tlsAnalyzer" in r for r in reasons)
    assert any("webSecurityAnalyzer" in r for r in reasons)


def test_total_failure_yields_inconclusive():
    engine = RiskAggregationEngine()
    findings = []
    statuses = {
        "urlAnalyzer": "FAILED",
        "domainAnalyzer": "FAILED",
        "tlsAnalyzer": "FAILED",
        "webSecurityAnalyzer": "FAILED",
        "reputationAnalyzer": "FAILED",
    }
    score, verdict, confidence, status, is_complete, threats, risk_factors, reasons = engine.evaluate(
        findings, statuses
    )

    assert verdict == "INCONCLUSIVE"
    assert status == "FAILED"
    assert is_complete is False
    assert confidence <= 50


def test_partial_scan_with_critical_finding_yields_malicious():
    engine = RiskAggregationEngine()
    findings = [
        RawFinding(
            category="PHISHING_INDICATOR",
            severity="CRITICAL",
            title="Confirmed Phishing Threat",
            description="Identified phishing campaign",
            confidence=95.0,
            evidence={},
        ),
        RawFinding(
            category="BLACKLIST",
            severity="CRITICAL",
            title="Known Malware Host",
            description="Active threat feed match",
            confidence=90.0,
            evidence={},
        ),
    ]
    statuses = {
        "urlAnalyzer": "SUCCESS",
        "domainAnalyzer": "SUCCESS",
        "tlsAnalyzer": "FAILED",
        "webSecurityAnalyzer": "TIMEOUT",
        "reputationAnalyzer": "SUCCESS",
    }
    score, verdict, confidence, status, is_complete, threats, risk_factors, reasons = engine.evaluate(
        findings, statuses
    )

    # Real threat signals must still trigger MALICIOUS verdict even if other analyzers failed
    assert score >= 70
    assert verdict == "MALICIOUS"
    assert status == "PARTIAL"
    assert is_complete is False
    # Confidence should still suffer penalty from incomplete execution
    assert confidence < 95.0
