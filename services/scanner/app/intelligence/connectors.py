from typing import Optional, Dict, Any
import httpx
from app.config import settings


class ThreatIntelligenceClient:
    """Connector client for external reputation feeds and threat intelligence APIs."""

    def __init__(self):
        self.google_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.urlhaus_enabled = settings.URLHAUS_ENABLED

    async def query_urlhaus(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Queries the URLhaus API for verified malware and phishing distributions."""
        if not self.urlhaus_enabled:
            return None

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                data = {"url": target_url}
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data)
                if resp.status_code == 200:
                    payload = resp.json()
                    if payload.get("query_status") == "ok":
                        return {
                            "status": "MALICIOUS",
                            "threat": payload.get("threat"),
                            "tags": payload.get("tags", []),
                            "reporter": payload.get("reporter"),
                            "urlhaus_reference": payload.get("urlhaus_reference")
                        }
        except Exception:
            # External feeds failing should not break scanner operations
            pass
        return None

    async def query_google_safe_browsing(self, target_url: str) -> Optional[Dict[str, Any]]:
        """Queries Google Safe Browsing Lookup API v4 if an API key is provided."""
        if not self.google_key:
            return None

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.google_key}"
        body = {
            "client": {
                "clientId": "sentrix-platform",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": target_url}]
            }
        }
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.post(endpoint, json=body)
                if resp.status_code == 200:
                    data = resp.json()
                    matches = data.get("matches", [])
                    if matches:
                        return {
                            "status": "MALICIOUS",
                            "threatType": matches[0].get("threatType"),
                            "platformType": matches[0].get("platformType")
                        }
        except Exception:
            pass
        return None
