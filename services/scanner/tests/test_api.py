import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app
from app.config import settings


@pytest.mark.asyncio
async def test_health_endpoint():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert "UrlAnalyzer" in data["analyzers"]


@pytest.mark.asyncio
async def test_analyze_requires_auth():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/api/v1/analyze", json={
            "url": "https://example.com",
            "scanId": "scan123",
            "normalizedDomain": "example.com"
        })
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_analyze_rejects_ssrf():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/analyze",
            headers={"X-Scanner-Secret": settings.SCANNER_API_SECRET},
            json={
                "url": "http://127.0.0.1:8080/secret",
                "scanId": "scan123",
                "normalizedDomain": "127.0.0.1"
            }
        )
        assert res.status_code == 400
        assert res.json()["error"] == "SSRF_VIOLATION"
