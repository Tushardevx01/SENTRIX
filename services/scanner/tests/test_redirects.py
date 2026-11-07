import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from contextlib import asynccontextmanager
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer


@pytest.mark.asyncio
async def test_redirect_to_private_ip_is_blocked():
    analyzer = WebSecurityAnalyzer()

    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"location": "http://127.0.0.1/secret"}

    async def empty_stream():
        if False:
            yield b""

    mock_resp.aiter_bytes = empty_stream

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        yield mock_resp

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.stream = mock_stream_ctx
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client

        findings, meta = await analyzer.analyze(
            "https://example.com/start", "example.com", pinned_ip="93.184.216.34"
        )

        # Target redirected to 127.0.0.1; SSRF guard must catch and block it
        ssrf_findings = [f for f in findings if "SSRF" in f.title or "Private" in f.title or f.severity == "CRITICAL"]
        assert len(ssrf_findings) > 0
        assert any("SSRF" in f.title for f in ssrf_findings)


@pytest.mark.asyncio
async def test_redirect_loop_detection():
    analyzer = WebSecurityAnalyzer()

    # Response A redirects to B, B redirects to A
    resp_a = MagicMock()
    resp_a.status_code = 301
    resp_a.headers = {"location": "https://example.com/b"}

    resp_b = MagicMock()
    resp_b.status_code = 301
    resp_b.headers = {"location": "https://example.com/a"}

    async def empty_stream():
        if False:
            yield b""

    resp_a.aiter_bytes = empty_stream
    resp_b.aiter_bytes = empty_stream

    responses = [resp_a, resp_b, resp_a]
    resp_idx = 0

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        nonlocal resp_idx
        idx = min(resp_idx, len(responses) - 1)
        resp_idx += 1
        yield responses[idx]

    with patch("httpx.AsyncClient") as mock_client_cls, \
         patch("app.safety.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        mock_client = AsyncMock()
        mock_client.stream = mock_stream_ctx
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client

        findings, meta = await analyzer.analyze(
            "https://example.com/a", "example.com", pinned_ip="93.184.216.34"
        )

        assert len(meta.get("redirectChain", [])) <= 3
        loop_findings = [f for f in findings if "Loop" in f.title]
        assert len(loop_findings) > 0


@pytest.mark.asyncio
async def test_excessive_redirects_bounded_at_five():
    analyzer = WebSecurityAnalyzer()

    async def empty_stream():
        if False:
            yield b""

    # Successive hops: hop0 -> hop1 -> hop2 -> ...
    resp_counter = 0

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        nonlocal resp_counter
        resp_counter += 1
        r = MagicMock()
        r.status_code = 302
        r.headers = {"location": f"https://example.com/hop{resp_counter}"}
        r.aiter_bytes = empty_stream
        yield r

    with patch("httpx.AsyncClient") as mock_client_cls, \
         patch("app.safety.ssrf_guard.resolve_and_validate_hostname", return_value=["93.184.216.34"]):
        mock_client = AsyncMock()
        mock_client.stream = mock_stream_ctx
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client

        findings, meta = await analyzer.analyze(
            "https://example.com/hop0", "example.com", pinned_ip="93.184.216.34"
        )

        # Chain must not exceed 6 (origin + 5 hops max)
        assert len(meta.get("redirectChain", [])) <= 6
        excessive = [f for f in findings if "Excessive" in f.title]
        assert len(excessive) > 0
