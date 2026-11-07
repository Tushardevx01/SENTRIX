from typing import List, Tuple, Dict, Any
from app.schemas.response import RawFinding
from app.intelligence.connectors import ThreatIntelligenceClient, ThreatProviderResult


class ReputationAnalyzer:
    """Verifies target URLs and hostnames against global threat feeds and blacklists."""

    def __init__(self):
        self.intel_client = ThreatIntelligenceClient()

    async def analyze(
        self, target_url: str, normalized_domain: str
    ) -> Tuple[List[RawFinding], str, Dict[str, Any]]:
        findings: List[RawFinding] = []

        # 1. Query external threat feeds
        urlhaus_res: ThreatProviderResult = await self.intel_client.query_urlhaus(target_url)
        gsb_res: ThreatProviderResult = await self.intel_client.query_google_safe_browsing(target_url)

        results = [urlhaus_res, gsb_res]
        provider_statuses = {r.provider: r.status for r in results}

        enabled_providers = [r for r in results if r.status != "SKIPPED"]
        successful_providers = [r for r in enabled_providers if r.status == "SUCCESS"]
        failed_providers = [r for r in enabled_providers if r.status == "FAILED"]
        skipped_providers = [r for r in results if r.status == "SKIPPED"]

        # 2. Process affirmative malicious matches (preserve genuine threat signals)
        if urlhaus_res.outcome == "MATCH" and urlhaus_res.details:
            findings.append(
                RawFinding(
                    category="BLACKLIST",
                    severity="CRITICAL",
                    title="URL Listed in URLhaus Threat Database",
                    description=(
                        f"The URL was verified by URLhaus intelligence as active malware or phishing distribution "
                        f"({urlhaus_res.details.get('threat', 'malware')})."
                    ),
                    evidence=urlhaus_res.details,
                    confidence=99.0,
                )
            )

        if gsb_res.outcome == "MATCH" and gsb_res.details:
            findings.append(
                RawFinding(
                    category="BLACKLIST",
                    severity="CRITICAL",
                    title="Google Safe Browsing Match Detected",
                    description=(
                        f"Google Safe Browsing identified the target URL as malicious "
                        f"({gsb_res.details.get('threatType')})."
                    ),
                    evidence=gsb_res.details,
                    confidence=98.0,
                )
            )

        # 3. Determine overall reputation status and coverage findings
        failure_reasons = [
            f"{r.provider}: {r.error_message}"
            for r in failed_providers
            if r.error_message
        ]

        if len(enabled_providers) == 0:
            # Case 1: All providers disabled
            overall_status = "SKIPPED"
            is_complete = False
            findings.append(
                RawFinding(
                    category="DOMAIN_REPUTATION",
                    severity="INFO",
                    title="Threat Intelligence Feeds Disabled",
                    description="External threat intelligence feeds (URLhaus, Google Safe Browsing) are disabled or unconfigured in platform settings.",
                    evidence={
                        "providerStatuses": provider_statuses,
                        "enabledCount": 0,
                    },
                    confidence=50.0,
                )
            )

        elif len(successful_providers) == 0 and len(failed_providers) > 0:
            # Case 2: All enabled providers failed (zero-trust: never assume clean on outage!)
            overall_status = "FAILED"
            is_complete = False
            findings.append(
                RawFinding(
                    category="DOMAIN_REPUTATION",
                    severity="INFO",
                    title="Threat Intelligence Feeds Unreachable",
                    description=(
                        f"All active threat intelligence feeds ({', '.join(r.provider for r in failed_providers)}) "
                        f"encountered network or upstream errors during lookup."
                    ),
                    evidence={
                        "providerStatuses": provider_statuses,
                        "failureReasons": failure_reasons,
                        "successfulCount": 0,
                        "failedCount": len(failed_providers),
                    },
                    confidence=40.0,
                )
            )

        elif len(failed_providers) > 0 and len(successful_providers) > 0:
            # Case 3: Partial provider success
            overall_status = "PARTIAL"
            is_complete = False
            # Report provider failure info
            for failed_r in failed_providers:
                findings.append(
                    RawFinding(
                        category="DOMAIN_REPUTATION",
                        severity="INFO",
                        title=f"Threat Intelligence Feed Unreachable: {failed_r.provider}",
                        description=f"The {failed_r.provider} threat feed could not be queried ({failed_r.error_message}).",
                        evidence={"provider": failed_r.provider, "error": failed_r.error_message},
                        confidence=40.0,
                    )
                )
            # If no malicious matches were found by the successful providers, document partial clearance
            if not any(f.severity == "CRITICAL" for f in findings):
                findings.append(
                    RawFinding(
                        category="DOMAIN_REPUTATION",
                        severity="INFO",
                        title="Partial Threat Intelligence Clearance",
                        description=(
                            f"Verified clean against {', '.join(r.provider for r in successful_providers)} with no matches, "
                            f"but {', '.join(r.provider for r in failed_providers)} was unreachable."
                        ),
                        evidence={
                            "checkedFeeds": [r.provider for r in successful_providers],
                            "failedFeeds": [r.provider for r in failed_providers],
                            "providerStatuses": provider_statuses,
                        },
                        confidence=70.0,
                    )
                )

        else:
            # Case 4: Every enabled provider succeeded
            overall_status = "SUCCESS"
            is_complete = True
            if not any(f.severity == "CRITICAL" for f in findings):
                findings.append(
                    RawFinding(
                        category="DOMAIN_REPUTATION",
                        severity="INFO",
                        title="No Threat Intelligence Blacklist Matches",
                        description="Target host and URL are not currently listed in active threat intelligence feeds.",
                        evidence={
                            "checkedFeeds": [r.provider for r in successful_providers],
                            "providerStatuses": provider_statuses,
                            "successfulCount": len(successful_providers),
                            "failedCount": 0,
                        },
                        confidence=85.0,
                    )
                )

        meta = {
            "providerStatuses": provider_statuses,
            "successfulCount": len(successful_providers),
            "failedCount": len(failed_providers),
            "skippedCount": len(skipped_providers),
            "isComplete": is_complete,
            "overallStatus": overall_status,
            "failureReasons": failure_reasons,
        }

        return findings, overall_status, meta
