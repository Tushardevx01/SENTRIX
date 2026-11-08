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


# ---------------------------------------------------------------------------
# Phase 6.3 evidence-based calibration regressions (dev benchmark iterations)
# ---------------------------------------------------------------------------

_FULL_STATUSES = {
    "urlAnalyzer": "SUCCESS",
    "domainAnalyzer": "SUCCESS",
    "tlsAnalyzer": "SUCCESS",
    "webSecurityAnalyzer": "SUCCESS",
    "reputationAnalyzer": "SUCCESS",
}


def test_hostname_keyword_dedupes_with_domain_impersonation():
    """CAL-06: hostname-only keyword findings and domain-analyzer hostname
    findings share one stable dedup key, so a deceptive hostname is counted
    once (fixes DEV-067 over-classification)."""
    url_analyzer = UrlAnalyzer()
    domain_analyzer = DomainAnalyzer()
    host = "socialsecurity-benefits-verify.net"

    kw = [f for f in url_analyzer.analyze(f"http://{host}", host)
          if "Sensitive Authentication Keywords" in f.title]
    gov = [f for f in domain_analyzer.analyze(host)
           if "Government / Public Authority Impersonation" in f.title]

    assert kw and gov
    assert kw[0].evidence["dedupKey"] == f"DECEPTIVE_HOSTNAME:{host}"
    assert gov[0].evidence["dedupKey"] == f"DECEPTIVE_HOSTNAME:{host}"

    # Scoring counts the shared characteristic once (highest severity wins).
    engine = RiskAggregationEngine()
    score, verdict, *_ = engine.evaluate([gov[0], kw[0]], _FULL_STATUSES)
    assert score == 40  # CRITICAL only; the overlapping HIGH keyword is deduped


def test_path_query_keywords_keep_distinct_findings():
    """CAL-06: dedup must not hide distinct evidence — a keyword matched in the
    path/query describes a different characteristic than the hostname."""
    url_analyzer = UrlAnalyzer()
    findings = url_analyzer.analyze(
        "http://brand-lookalike-host.net/login", "brand-lookalike-host.net"
    )
    kw = [f for f in findings if "Sensitive Authentication Keywords" in f.title]
    assert kw
    # "login" matched in the path -> no hostname-shared dedup key
    assert "dedupKey" not in kw[0].evidence


def test_phish_is_exact_token_keyword_only():
    """CAL-03: token-only keyword matching — 'phish' counts as a hostname/path
    token, never as a substring of an unrelated word."""
    url_analyzer = UrlAnalyzer()

    # Positive: expired-ssl-phish.net/login (DEV-076) must collect 'phish'
    findings = url_analyzer.analyze(
        "https://expired-ssl-phish.net/login", "expired-ssl-phish.net"
    )
    kw = [f for f in findings if "Sensitive Authentication Keywords" in f.title]
    assert kw and "phish" in kw[0].evidence["keywords"]
    assert "login" in kw[0].evidence["keywords"]  # 2 terms -> HIGH severity
    assert kw[0].severity == "HIGH"

    # Negative: 'phish' buried inside a longer token must NOT match
    findings_neg = url_analyzer.analyze(
        "https://laphish-market.example/area", "laphish-market.example"
    )
    kw_neg = [f for f in findings_neg if "Sensitive Authentication Keywords" in f.title]
    assert not kw_neg


def test_substring_brand_false_positives_removed():
    """CAL-03: token/compound matching eliminated substring impersonation FPs
    (revolute.com, stripes.com, chases.com) while real lookalikes still hit."""
    analyzer = DomainAnalyzer()

    for benign in ("revolute.com", "stripes.com", "chases.com"):
        findings = analyzer.analyze(benign)
        assert not any(
            "Impersonation" in f.title or "Brand Impersonation" in f.title
            for f in findings
        ), f"substring FP on {benign}"

    # Real hyphen/abbreviation lookalikes still detected
    assert any("Wellsfargo" in f.title for f in analyzer.analyze("wells-fargo-alert.info"))
    assert any("Bofa" in f.title for f in analyzer.analyze("b0fa-secure-portal.com"))
    assert any("Paypal" in f.title for f in analyzer.analyze("paypa1.com"))


def test_confusable_skeleton_homograph_detection():
    """CAL-04: Cyrillic homographs normalize to a confusable skeleton that
    still matches the targeted brand, preserving the original domain as evidence."""
    analyzer = DomainAnalyzer()
    # 'раypal' uses Cyrillic р (U+0440) and а (U+0430)
    homograph = "раypal-secure.example.com"
    findings = analyzer.analyze(homograph)
    hits = [f for f in findings if "Homoglyph / Confusable Domain Impersonation" in f.title]
    assert hits
    assert "Paypal" in hits[0].title
    # Original domain preserved in evidence
    assert hits[0].evidence["domain"]
    assert hits[0].evidence.get("matchMethod") in {"confusableSkeleton", "exactToken", "normalizationCandidate"}


def test_subdomain_stacking_not_trusted_as_authentic():
    """CAL-02: brand-in-subdomain attacker domains are never treated as
    authentic recognized domains, so auth-path penalties still apply."""
    url_analyzer = UrlAnalyzer()
    findings = url_analyzer.analyze(
        "https://paypal.com.attacker.example/login", "paypal.com.attacker.example"
    )
    kw = [f for f in findings if "Sensitive Authentication Keywords" in f.title]
    assert kw, "attacker-controlled stacked domain must keep keyword penalties"


def test_referrer_policy_is_capped_posture():
    """CAL-01: the new Missing Referrer-Policy observation is posture — it can
    never push a page toward SUSPICIOUS on its own."""
    from app.scoring.risk_engine import POSTURE_TITLES, is_posture_finding

    finding = RawFinding(
        category="WEB_SECURITY",
        severity="LOW",
        title="Missing Referrer-Policy Header",
        description="d",
        evidence={"header": "Referrer-Policy", "isPosture": True},
        confidence=85.0,
    )
    assert "Missing Referrer-Policy Header" in POSTURE_TITLES
    assert is_posture_finding(finding) is True

    engine = RiskAggregationEngine()
    score, verdict, *_ = engine.evaluate([finding], _FULL_STATUSES)
    assert score == 5 and verdict == "BENIGN"


def test_finding_provenance_stamped():
    """CAL-06: analyzer provenance is stamped onto evidence at collection time."""
    from app.main import _stamp_finding_provenance

    f1 = RawFinding(category="URL_ANOMALY", severity="LOW", title="t", description="d", confidence=50.0)
    f2 = RawFinding(
        category="URL_ANOMALY", severity="LOW", title="t2", description="d",
        evidence={"analyzer": "domainAnalyzer"}, confidence=50.0,
    )
    _stamp_finding_provenance([f1, f2], "urlAnalyzer")
    assert f1.evidence["analyzer"] == "urlAnalyzer"
    # Existing provenance is never overwritten
    assert f2.evidence["analyzer"] == "domainAnalyzer"


# --- Web security: hostile destinations & concealed iframes (CAL-05/06) ----

def _dom_findings(html_body: str, url: str, domain: str):
    """Runs WebSecurityAnalyzer offline against a mocked HTTP response."""
    import asyncio
    from unittest.mock import patch
    from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
    from benchmarks.harness import build_mock_http_client

    client = build_mock_http_client({"status_code": 200, "headers": {}, "html_body": html_body})
    analyzer = WebSecurityAnalyzer()
    with patch("httpx.AsyncClient", return_value=client):
        return asyncio.run(analyzer.analyze(url, domain, pinned_ip="93.184.216.34"))[0]


def test_meta_refresh_to_hostile_destination_is_corroborated():
    """CAL-05: hostile meta-refresh destinations get corroborating evidence —
    CRITICAL redirect + HIGH destination-reputation findings (fixes DEV-070/071)."""
    html = ('<html><head><meta http-equiv="refresh" '
            'content="0;url=http://attacker-landing.biz/payload"/></head>'
            '<body>Redirecting...</body></html>')
    findings = _dom_findings(html, "http://redirect-chain-bounce.com/step1", "redirect-chain-bounce.com")

    meta = [f for f in findings if "Meta Refresh Redirect to Untrusted Destination" in f.title]
    assert meta and meta[0].severity == "CRITICAL"

    hostile = [f for f in findings if f.title == "Redirect Destination Exhibits Hostile Indicators"]
    assert len(hostile) == 1
    assert hostile[0].severity == "HIGH"
    assert hostile[0].evidence["dedupKey"] == "HOSTILE_DESTINATION:attacker-landing.biz"
    assert hostile[0].evidence["indicators"]


def test_meta_refresh_to_unknown_external_host_not_auto_critical():
    """CAL-05: an unknown destination alone is never treated as malicious —
    no CRITICAL, no hostile-destination escalation without corroboration."""
    html = ('<html><head><meta http-equiv="refresh" '
            'content="0;url=https://medium.com/some-article"/></head>'
            '<body>Redirecting...</body></html>')
    findings = _dom_findings(html, "http://neutral-host.example/page", "neutral-host.example")

    meta = [f for f in findings if "Meta Refresh" in f.title]
    # Calibrated in Phase 7.3.1: uncorroborated external destination redirect is MEDIUM (12 pts), preventing threshold inflation
    assert meta and meta[0].severity in ("MEDIUM", "HIGH")
    assert not any(f.title == "Redirect Destination Exhibits Hostile Indicators" for f in findings)
    assert not any(f.severity == "CRITICAL" for f in findings)


def test_hidden_iframe_hostile_payload_escalates_with_shared_key():
    """CAL-05/06: concealed iframe loading a hostile payload destination is
    CRITICAL evidence sharing the HIDDEN_IFRAME key, plus a destination finding
    (fixes DEV-074)."""
    html = ('<html><body><h1>Sponsored Ad</h1>'
            '<iframe src="http://silent-exploit-drop.biz/kit" style="display:none"></iframe>'
            '</body></html>')
    findings = _dom_findings(html, "http://exploit-carrier-page.com/ad.html", "exploit-carrier-page.com")

    base = [f for f in findings if f.title == "Hidden IFrame Detected"]
    payload = [f for f in findings if f.title == "Concealed IFrame Loads Hostile Payload Destination"]
    hostile = [f for f in findings if f.title == "Redirect Destination Exhibits Hostile Indicators"]

    assert base and payload
    assert payload[0].severity == "CRITICAL"
    assert base[0].evidence["dedupKey"] == payload[0].evidence["dedupKey"] == "HIDDEN_IFRAME"
    assert hostile and hostile[0].severity == "HIGH"
    assert hostile[0].evidence["dedupKey"] == "HOSTILE_DESTINATION:silent-exploit-drop.biz"

    # Scoring: HIDDEN_IFRAME collapses to the CRITICAL (40), not 40+12
    engine = RiskAggregationEngine()
    score, *_ = engine.evaluate([base[0], payload[0]], _FULL_STATUSES)
    assert score == 40


def test_hidden_iframe_benign_embed_not_escalated():
    """CAL-05: a hidden iframe pointing at a non-hostile host stays a MEDIUM
    concealment observation — no fabricated CRITICAL payload evidence."""
    html = ('<html><body><iframe src="https://cdn.example-widget.com/serve.js" '
            'style="display:none"></iframe></body></html>')
    findings = _dom_findings(html, "http://neutral-widgets.example/page", "neutral-widgets.example")

    assert any(f.title == "Hidden IFrame Detected" for f in findings)
    assert not any(f.title == "Concealed IFrame Loads Hostile Payload Destination" for f in findings)
    assert not any(f.title == "Redirect Destination Exhibits Hostile Indicators" for f in findings)


def test_hostile_destination_requires_corroboration():
    """CAL-05 helper: differing host alone is not hostile; high-abuse TLD or
    credential-style path is required."""
    from app.analyzers.web_security_analyzer import evaluate_hostile_destination

    hostile, ev = evaluate_hostile_destination("http://attacker-landing.biz/payload", "page.example")
    assert hostile and ev["indicators"]

    not_hostile, ev2 = evaluate_hostile_destination("https://medium.com/some-article", "page.example")
    assert not not_hostile and not ev2["indicators"]

    same_host, _ = evaluate_hostile_destination("https://page.example/local", "page.example")
    assert not same_host
