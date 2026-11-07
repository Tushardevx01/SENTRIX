import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.intelligence.connectors import ThreatIntelligenceClient, ThreatProviderResult
from app.analyzers.reputation_analyzer import ReputationAnalyzer


@pytest.mark.asyncio
async def test_urlhaus_disabled_returns_skipped():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", False):
        client = ThreatIntelligenceClient()
        res = await client.query_urlhaus("https://example.com")
        assert res.status == "SKIPPED"
        assert res.outcome == "SKIPPED"
        assert res.details is None


@pytest.mark.asyncio
async def test_urlhaus_clean_response_returns_no_match():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", True):
        client = ThreatIntelligenceClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            res = await client.query_urlhaus("https://example.com")

            assert res.status == "SUCCESS"
            assert res.outcome == "NO_MATCH"
            assert res.details == {"query_status": "no_results"}


@pytest.mark.asyncio
async def test_urlhaus_malicious_match():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", True):
        client = ThreatIntelligenceClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "tags": ["elf", "mozi"],
            "reporter": "abuse_hunter",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/"
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            res = await client.query_urlhaus("https://malware.xyz/payload.bin")

            assert res.status == "SUCCESS"
            assert res.outcome == "MATCH"
            assert res.details["threat"] == "malware_download"
            assert "mozi" in res.details["tags"]


@pytest.mark.asyncio
async def test_urlhaus_timeout_returns_error():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", True):
        client = ThreatIntelligenceClient()
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Connection timed out")
            res = await client.query_urlhaus("https://timeout-site.com")

            assert res.status == "FAILED"
            assert res.outcome == "ERROR"
            assert "timed out" in res.error_message


@pytest.mark.asyncio
async def test_urlhaus_rate_limit_and_5xx_errors():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", True):
        client = ThreatIntelligenceClient()

        # 429 Rate limit
        resp_429 = MagicMock()
        resp_429.status_code = 429
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = resp_429
            res = await client.query_urlhaus("https://example.com")
            assert res.status == "FAILED"
            assert res.outcome == "ERROR"
            assert "429" in res.error_message

        # 503 Server error
        resp_503 = MagicMock()
        resp_503.status_code = 503
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = resp_503
            res = await client.query_urlhaus("https://example.com")
            assert res.status == "FAILED"
            assert res.outcome == "ERROR"
            assert "503" in res.error_message


@pytest.mark.asyncio
async def test_urlhaus_invalid_json():
    with patch("app.intelligence.connectors.settings.URLHAUS_ENABLED", True):
        client = ThreatIntelligenceClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            res = await client.query_urlhaus("https://bad-json.com")
            assert res.status == "FAILED"
            assert res.outcome == "ERROR"
            assert "Invalid JSON" in res.error_message


@pytest.mark.asyncio
async def test_google_safe_browsing_unconfigured():
    with patch("app.intelligence.connectors.settings.GOOGLE_SAFE_BROWSING_API_KEY", ""):
        client = ThreatIntelligenceClient()
        res = await client.query_google_safe_browsing("https://example.com")
        assert res.status == "SKIPPED"
        assert res.outcome == "SKIPPED"
        assert res.details is None


@pytest.mark.asyncio
async def test_google_safe_browsing_match():
    with patch("app.intelligence.connectors.settings.GOOGLE_SAFE_BROWSING_API_KEY", "dummy-key"):
        client = ThreatIntelligenceClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "matches": [
                {
                    "threatType": "MALWARE",
                    "platformType": "ANY_PLATFORM"
                }
            ]
        }

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            res = await client.query_google_safe_browsing("https://malware.test")

            assert res.status == "SUCCESS"
            assert res.outcome == "MATCH"
            assert res.details["threatType"] == "MALWARE"


@pytest.mark.asyncio
async def test_google_safe_browsing_no_match():
    with patch("app.intelligence.connectors.settings.GOOGLE_SAFE_BROWSING_API_KEY", "dummy-key"):
        client = ThreatIntelligenceClient()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_resp
            res = await client.query_google_safe_browsing("https://clean.test")

            assert res.status == "SUCCESS"
            assert res.outcome == "NO_MATCH"


@pytest.mark.asyncio
async def test_google_safe_browsing_auth_error_and_timeout():
    with patch("app.intelligence.connectors.settings.GOOGLE_SAFE_BROWSING_API_KEY", "dummy-key"):
        client = ThreatIntelligenceClient()

        # 403 Forbidden
        mock_403 = MagicMock()
        mock_403.status_code = 403
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = mock_403
            res = await client.query_google_safe_browsing("https://clean.test")
            assert res.status == "FAILED"
            assert res.outcome == "ERROR"
            assert "authentication failed" in res.error_message
            # Ensure key is NOT leaked in error
            assert "dummy-key" not in res.error_message

        # Timeout
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Timeout")
            res = await client.query_google_safe_browsing("https://clean.test")
            assert res.status == "FAILED"
            assert res.outcome == "ERROR"


@pytest.mark.asyncio
async def test_reputation_analyzer_all_providers_disabled():
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer.intel_client, "query_urlhaus", new_callable=AsyncMock) as mock_u, \
         patch.object(analyzer.intel_client, "query_google_safe_browsing", new_callable=AsyncMock) as mock_g:
        mock_u.return_value = ThreatProviderResult(
            provider="urlhaus", status="SKIPPED", outcome="SKIPPED", details=None
        )
        mock_g.return_value = ThreatProviderResult(
            provider="googleSafeBrowsing", status="SKIPPED", outcome="SKIPPED", details=None
        )

        findings, overall_status, meta = await analyzer.analyze("https://example.com", "example.com")
        assert overall_status == "SKIPPED"
        assert meta["isComplete"] is False
        assert any("Disabled" in f.title for f in findings)


@pytest.mark.asyncio
async def test_reputation_analyzer_outage_never_claims_clean():
    """CRITICAL: If all enabled threat feeds fail, the analyzer must report FAILED and never claim clean!"""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer.intel_client, "query_urlhaus", new_callable=AsyncMock) as mock_u, \
         patch.object(analyzer.intel_client, "query_google_safe_browsing", new_callable=AsyncMock) as mock_g:
        mock_u.return_value = ThreatProviderResult(
            provider="urlhaus",
            status="FAILED",
            outcome="ERROR",
            error_message="Connection timed out"
        )
        mock_g.return_value = ThreatProviderResult(
            provider="googleSafeBrowsing",
            status="FAILED",
            outcome="ERROR",
            error_message="503 Service Unavailable"
        )

        findings, overall_status, meta = await analyzer.analyze("https://example.com", "example.com")
        assert overall_status == "FAILED"
        assert meta["isComplete"] is False
        # Must NOT contain "No Threat Intelligence Blacklist Matches"
        assert not any("No Threat Intelligence Blacklist Matches" in f.title for f in findings)
        # Must report unreachable feeds
        assert any("Unreachable" in f.title for f in findings)


@pytest.mark.asyncio
async def test_reputation_analyzer_partial_coverage():
    """One provider succeeds clean, one fails. Result must be PARTIAL coverage, not concealing failure."""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer.intel_client, "query_urlhaus", new_callable=AsyncMock) as mock_u, \
         patch.object(analyzer.intel_client, "query_google_safe_browsing", new_callable=AsyncMock) as mock_g:
        mock_u.return_value = ThreatProviderResult(
            provider="urlhaus",
            status="SUCCESS",
            outcome="NO_MATCH",
            details={"query_status": "no_results"}
        )
        mock_g.return_value = ThreatProviderResult(
            provider="googleSafeBrowsing",
            status="FAILED",
            outcome="ERROR",
            error_message="Rate limit 429"
        )

        findings, overall_status, meta = await analyzer.analyze("https://example.com", "example.com")
        assert overall_status == "PARTIAL"
        assert meta["isComplete"] is False
        # Documents partial clearance, not unconditional clean
        assert any("Partial Threat Intelligence Clearance" in f.title for f in findings)
        assert any("Feed Unreachable" in f.title for f in findings)


@pytest.mark.asyncio
async def test_reputation_analyzer_preserves_malicious_finding_on_partial_failure():
    """If one provider detects malware and another fails, the malicious finding must be preserved!"""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer.intel_client, "query_urlhaus", new_callable=AsyncMock) as mock_u, \
         patch.object(analyzer.intel_client, "query_google_safe_browsing", new_callable=AsyncMock) as mock_g:
        mock_u.return_value = ThreatProviderResult(
            provider="urlhaus",
            status="SUCCESS",
            outcome="MATCH",
            details={"threat": "emotet_dropper", "reporter": "sec_team"}
        )
        mock_g.return_value = ThreatProviderResult(
            provider="googleSafeBrowsing",
            status="FAILED",
            outcome="ERROR",
            error_message="500 Internal Error"
        )

        findings, overall_status, meta = await analyzer.analyze("https://malware.com", "malware.com")
        assert overall_status == "PARTIAL"
        # CRITICAL finding must be preserved!
        criticals = [f for f in findings if f.severity == "CRITICAL"]
        assert len(criticals) == 1
        assert "URL Listed in URLhaus" in criticals[0].title


@pytest.mark.asyncio
async def test_reputation_analyzer_all_providers_succeed_clean():
    """When all enabled providers succeed with no matches, clean finding is produced."""
    analyzer = ReputationAnalyzer()
    with patch.object(analyzer.intel_client, "query_urlhaus", new_callable=AsyncMock) as mock_u, \
         patch.object(analyzer.intel_client, "query_google_safe_browsing", new_callable=AsyncMock) as mock_g:
        mock_u.return_value = ThreatProviderResult(
            provider="urlhaus",
            status="SUCCESS",
            outcome="NO_MATCH",
            details={"query_status": "no_results"}
        )
        mock_g.return_value = ThreatProviderResult(
            provider="googleSafeBrowsing",
            status="SUCCESS",
            outcome="NO_MATCH",
            details={"matches": []}
        )

        findings, overall_status, meta = await analyzer.analyze("https://safe-domain.com", "safe-domain.com")
        assert overall_status == "SUCCESS"
        assert meta["isComplete"] is True
        assert any("No Threat Intelligence Blacklist Matches" in f.title for f in findings)
