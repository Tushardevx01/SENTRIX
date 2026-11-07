import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from contextlib import asynccontextmanager
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
import httpx


@pytest.mark.asyncio
async def test_streaming_body_truncation_on_large_payload():
    analyzer = WebSecurityAnalyzer()

    # Generate chunks exceeding MAX_RESPONSE_BYTES (1 MB)
    chunk_size = 256 * 1024
    chunks = [b"A" * chunk_size for _ in range(6)]  # 1.5 MB total

    async def mock_stream(chunk_size=None):
        for c in chunks:
            yield c

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"content-type": "text/html; charset=utf-8"}
    mock_resp.aiter_bytes = mock_stream

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
            "https://example.com/huge", "example.com", pinned_ip="93.184.216.34"
        )

        assert meta.get("isTruncated") is True
        trunc_findings = [f for f in findings if "Truncated" in f.title or "1 MB" in f.description]
        assert len(trunc_findings) > 0


@pytest.mark.asyncio
async def test_non_html_content_type_bypasses_dom_parsing():
    analyzer = WebSecurityAnalyzer()

    async def mock_stream():
        yield b'{"status": "ok", "message": "not html"}'

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {
        "content-type": "application/json",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=31536000",
    }
    mock_resp.aiter_bytes = mock_stream

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
            "https://example.com/api/data", "example.com", pinned_ip="93.184.216.34"
        )

        assert meta.get("isTruncated") is False
        # Should not flag missing HTML form or password input issues on JSON endpoint
        html_form_findings = [f for f in findings if "Form" in f.title or "Password" in f.title]
        assert len(html_form_findings) == 0


@pytest.mark.asyncio
async def test_read_timeout_handling():
    analyzer = WebSecurityAnalyzer()

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        raise httpx.ReadTimeout("Read timed out")
        yield MagicMock()

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_client = MagicMock()
        mock_client.stream = mock_stream_ctx
        mock_client.__aenter__.return_value = mock_client
        mock_client.__aexit__.return_value = None
        mock_client_cls.return_value = mock_client

        findings, meta = await analyzer.analyze(
            "https://example.com/slow", "example.com", pinned_ip="93.184.216.34"
        )

        # Must record timeout finding cleanly without throwing
        timeout_findings = [f for f in findings if "Timed Out" in f.title]
        assert len(timeout_findings) > 0
        assert meta.get("isTruncated") is False
