from typing import Optional, Dict, Any
from dataclasses import dataclass
import logging
import httpx
from app.config import settings

logger = logging.getLogger("sentrix.intelligence")


@dataclass
class ThreatProviderResult:
    """Structured result from an external threat intelligence provider query."""
    provider: str
    status: str  # "SUCCESS" | "FAILED" | "SKIPPED"
    outcome: str  # "MATCH" | "NO_MATCH" | "ERROR" | "SKIPPED"
    details: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class ThreatIntelligenceClient:
    """Connector client for external reputation feeds and threat intelligence APIs."""

    def __init__(self):
        self.google_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
        self.urlhaus_enabled = settings.URLHAUS_ENABLED

    async def query_urlhaus(self, target_url: str) -> ThreatProviderResult:
        """Queries the URLhaus API for verified malware and phishing distributions."""
        if not self.urlhaus_enabled:
            return ThreatProviderResult(
                provider="urlhaus",
                status="SKIPPED",
                outcome="SKIPPED",
                details=None,
                error_message="URLhaus feed is disabled by configuration"
            )

        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                data = {"url": target_url}
                resp = await client.post("https://urlhaus-api.abuse.ch/v1/url/", data=data)

                if resp.status_code == 429:
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="FAILED",
                        outcome="ERROR",
                        error_message="URLhaus rate limit exceeded (HTTP 429)"
                    )
                if resp.status_code >= 500:
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="FAILED",
                        outcome="ERROR",
                        error_message=f"URLhaus server error (HTTP {resp.status_code})"
                    )
                if resp.status_code >= 400:
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="FAILED",
                        outcome="ERROR",
                        error_message=f"URLhaus client error (HTTP {resp.status_code})"
                    )

                try:
                    payload = resp.json()
                except Exception:
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="FAILED",
                        outcome="ERROR",
                        error_message="Invalid JSON response received from URLhaus"
                    )

                query_status = payload.get("query_status")
                if query_status == "ok":
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="SUCCESS",
                        outcome="MATCH",
                        details={
                            "threat": payload.get("threat"),
                            "tags": payload.get("tags", []),
                            "reporter": payload.get("reporter"),
                            "urlhaus_reference": payload.get("urlhaus_reference")
                        }
                    )
                elif query_status == "no_results":
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="SUCCESS",
                        outcome="NO_MATCH",
                        details={"query_status": "no_results"}
                    )
                else:
                    return ThreatProviderResult(
                        provider="urlhaus",
                        status="FAILED",
                        outcome="ERROR",
                        error_message=f"URLhaus returned unexpected query status: {query_status}"
                    )

        except httpx.TimeoutException:
            logger.warning("URLhaus intelligence query timed out")
            return ThreatProviderResult(
                provider="urlhaus",
                status="FAILED",
                outcome="ERROR",
                error_message="Connection timed out while contacting URLhaus"
            )
        except httpx.ConnectError:
            logger.warning("URLhaus connection failed")
            return ThreatProviderResult(
                provider="urlhaus",
                status="FAILED",
                outcome="ERROR",
                error_message="Failed to establish connection to URLhaus feed"
            )
        except Exception as exc:
            logger.warning(f"URLhaus query error: {type(exc).__name__}")
            return ThreatProviderResult(
                provider="urlhaus",
                status="FAILED",
                outcome="ERROR",
                error_message="Unexpected error communicating with URLhaus feed"
            )

    async def query_google_safe_browsing(self, target_url: str) -> ThreatProviderResult:
        """Queries Google Safe Browsing Lookup API v4 if an API key is provided."""
        if not self.google_key:
            return ThreatProviderResult(
                provider="googleSafeBrowsing",
                status="SKIPPED",
                outcome="SKIPPED",
                details=None,
                error_message="Google Safe Browsing API key is not configured"
            )

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

                if resp.status_code in (401, 403):
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="FAILED",
                        outcome="ERROR",
                        error_message="Google Safe Browsing authentication failed or quota denied"
                    )
                if resp.status_code == 429:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="FAILED",
                        outcome="ERROR",
                        error_message="Google Safe Browsing rate limit exceeded (HTTP 429)"
                    )
                if resp.status_code >= 500:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="FAILED",
                        outcome="ERROR",
                        error_message=f"Google Safe Browsing server error (HTTP {resp.status_code})"
                    )
                if resp.status_code >= 400:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="FAILED",
                        outcome="ERROR",
                        error_message=f"Google Safe Browsing HTTP error {resp.status_code}"
                    )

                try:
                    data = resp.json()
                except Exception:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="FAILED",
                        outcome="ERROR",
                        error_message="Invalid JSON response received from Google Safe Browsing"
                    )

                matches = data.get("matches", [])
                if matches:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="SUCCESS",
                        outcome="MATCH",
                        details={
                            "threatType": matches[0].get("threatType"),
                            "platformType": matches[0].get("platformType")
                        }
                    )
                else:
                    return ThreatProviderResult(
                        provider="googleSafeBrowsing",
                        status="SUCCESS",
                        outcome="NO_MATCH",
                        details={"matches": []}
                    )

        except httpx.TimeoutException:
            logger.warning("Google Safe Browsing query timed out")
            return ThreatProviderResult(
                provider="googleSafeBrowsing",
                status="FAILED",
                outcome="ERROR",
                error_message="Connection timed out while contacting Google Safe Browsing"
            )
        except httpx.ConnectError:
            logger.warning("Google Safe Browsing connection failed")
            return ThreatProviderResult(
                provider="googleSafeBrowsing",
                status="FAILED",
                outcome="ERROR",
                error_message="Failed to establish connection to Google Safe Browsing API"
            )
        except Exception as exc:
            logger.warning(f"Google Safe Browsing query error: {type(exc).__name__}")
            return ThreatProviderResult(
                provider="googleSafeBrowsing",
                status="FAILED",
                outcome="ERROR",
                error_message="Unexpected error communicating with Google Safe Browsing API"
            )
