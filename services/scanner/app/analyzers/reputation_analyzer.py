from typing import List
from app.schemas.response import RawFinding
from app.intelligence.connectors import ThreatIntelligenceClient


class ReputationAnalyzer:
    """Verifies target URLs and hostnames against global threat feeds and blacklists."""

    def __init__(self):
        self.intel_client = ThreatIntelligenceClient()

    async def analyze(self, target_url: str, normalized_domain: str) -> List[RawFinding]:
        findings: List[RawFinding] = []

        # 1. URLhaus reputation check
        urlhaus_hit = await self.intel_client.query_urlhaus(target_url)
        if urlhaus_hit:
            findings.append(RawFinding(
                category="BLACKLIST",
                severity="CRITICAL",
                title="URL Listed in URLhaus Threat Database",
                description=f"The URL was verified by URLhaus intelligence as active malware or phishing distribution ({urlhaus_hit.get('threat', 'malware')}).",
                evidence=urlhaus_hit,
                confidence=99.0
            ))

        # 2. Google Safe Browsing
        gsb_hit = await self.intel_client.query_google_safe_browsing(target_url)
        if gsb_hit:
            findings.append(RawFinding(
                category="BLACKLIST",
                severity="CRITICAL",
                title="Google Safe Browsing Match Detected",
                description=f"Google Safe Browsing identified the target URL as malicious ({gsb_hit.get('threatType')}).",
                evidence=gsb_hit,
                confidence=98.0
            ))

        if not findings:
            findings.append(RawFinding(
                category="DOMAIN_REPUTATION",
                severity="INFO",
                title="No Threat Intelligence Blacklist Matches",
                description="Target host and URL are not currently listed in active open threat intelligence feeds.",
                evidence={"checkedFeeds": ["URLhaus", "GoogleSafeBrowsing"]},
                confidence=85.0
            ))

        return findings
