from typing import List, Tuple, Dict, Set
from app.schemas.response import RawFinding

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
    "INFO": 0,
}

EXPECTED_ANALYZERS = [
    "urlAnalyzer",
    "domainAnalyzer",
    "tlsAnalyzer",
    "webSecurityAnalyzer",
    "reputationAnalyzer",
]

POSTURE_TITLES: Set[str] = {
    "Missing Strict-Transport-Security (HSTS)",
    "Missing Content-Security-Policy (CSP)",
    "Missing Clickjacking Defenses",
    "Missing X-Content-Type-Options Header",
    "Missing Referrer-Policy Header",
    "Server Header Leaks Exact Software Version",
    "X-Powered-By Header Reveals Application Framework",
    "Certificate Transparency: No Embedded SCTs in Leaf Certificate",
    "No Embedded Certificate Transparency (CT) SCTs in Leaf Certificate",
}

MAX_POSTURE_CONTRIBUTION = 15


def is_posture_finding(f: RawFinding) -> bool:
    """Identifies defense-in-depth posture observations vs active security threat indicators."""
    ev = getattr(f, "evidence", None)
    if isinstance(ev, dict) and (ev.get("isPosture") or ev.get("is_posture")):
        return True
    if f.title in POSTURE_TITLES:
        return True
    if f.category == "WEB_SECURITY" and f.title.startswith("Missing "):
        return True
    if f.category == "TLS_SECURITY" and "SCT" in f.title:
        return True
    return False


def get_dedup_key(f: RawFinding) -> str:
    """Returns a stable deduplication identity for overlapping security characteristics."""
    ev = getattr(f, "evidence", None)
    if isinstance(ev, dict):
        if "dedupKey" in ev:
            return str(ev["dedupKey"])
        if "dedup_key" in ev:
            return str(ev["dedup_key"])
    norm_title = f.title.strip().lower()
    return f"{f.category}:{norm_title}"


class RiskAggregationEngine:
    """
    Computes explainable, evidence-based threat risk scores,
    analysis completeness ratings, and zero-trust classification verdicts.
    """

    def evaluate(
        self,
        findings: List[RawFinding],
        analyzer_statuses: Dict[str, str]
    ) -> Tuple[int, str, int, str, bool, List[str], List[str], List[str]]:
        risk_factors: List[str] = []
        threat_types_set = set()
        inconclusive_reasons: List[str] = []

        confidence_sum = 0.0
        counted_findings = 0

        # Separate and deduplicate threat findings vs posture observations
        threat_dedup_map: Dict[str, Tuple[int, RawFinding]] = {}
        posture_dedup_map: Dict[str, Tuple[int, RawFinding]] = {}

        for f in findings:
            sev = f.severity.upper()
            weight = SEVERITY_WEIGHTS.get(sev, 0)
            confidence_sum += f.confidence
            counted_findings += 1

            dedup_key = get_dedup_key(f)

            if is_posture_finding(f):
                # Retain highest weight for this posture characteristic
                if dedup_key not in posture_dedup_map or weight > posture_dedup_map[dedup_key][0]:
                    posture_dedup_map[dedup_key] = (weight, f)
            else:
                # Active threat indicator
                if dedup_key not in threat_dedup_map or weight > threat_dedup_map[dedup_key][0]:
                    threat_dedup_map[dedup_key] = (weight, f)

        # Compute threat score and extract factors from deduplicated active threats
        for weight, f in threat_dedup_map.values():
            sev = f.severity.upper()
            if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                factor_desc = f"{f.title} ({sev})"
                if factor_desc not in risk_factors:
                    risk_factors.append(factor_desc)
                threat_types_set.add(f.category)

        threat_score = sum(weight for weight, _ in threat_dedup_map.values())

        # Compute bounded posture contribution (capped at 15 points)
        raw_posture_score = sum(weight for weight, _ in posture_dedup_map.values())
        capped_posture_score = min(MAX_POSTURE_CONTRIBUTION, raw_posture_score)

        # Total combined risk score (0 to 100)
        raw_score = threat_score + capped_posture_score
        risk_score = min(100, max(0, raw_score))

        # Determine Analyzer Execution Completeness (Zero-Trust Invariant: ONLY explicit SUCCESS is complete)
        # Missing analyzer statuses MUST NOT silently count as success!
        missing_analyzers = [name for name in EXPECTED_ANALYZERS if name not in analyzer_statuses]
        non_success_analyzers = [k for k, v in analyzer_statuses.items() if v != "SUCCESS"]
        incomplete_analyzers = sorted(list(set(missing_analyzers + non_success_analyzers)))
        success_analyzers = [k for k, v in analyzer_statuses.items() if v == "SUCCESS"]

        if not incomplete_analyzers:
            analysis_status = "COMPLETE"
            analysis_complete = True
        elif success_analyzers:
            analysis_status = "PARTIAL"
            analysis_complete = False
            details = [f"{k}:{analyzer_statuses.get(k, 'MISSING')}" for k in incomplete_analyzers]
            inconclusive_reasons.append(
                f"Partial inspection: {len(incomplete_analyzers)} analyzer(s) did not complete successfully ({', '.join(details)})."
            )
        else:
            analysis_status = "FAILED"
            analysis_complete = False
            inconclusive_reasons.append("Critical failure: All network security analyzers failed or were unreachable.")

        # Determine if unverified infrastructure signals are present (Phase 7.3 / 7.3.1)
        # Contextual requirement: Generic tokens alone do not suffice without corroborating
        # infrastructure evidence (e.g. parked/placeholder page, unverified plain HTTP hosting).
        def _is_unverified_signal(f: RawFinding) -> bool:
            ev = getattr(f, "evidence", None)
            if not isinstance(ev, dict):
                return False
            if ev.get("isInformationalInfrastructure") is True:
                return True
            if ev.get("signal") in ("PARKED_PAGE", "UNVERIFIED_HOSTING"):
                return True
            return False

        has_unverified_infra_signal = any(
            _is_unverified_signal(f) or
            f.title in (
                "Parked or Placeholder Domain Page Detected",
                "Unverified Infrastructure / Plain HTTP Hosting",
            )
            for f in findings
        )

        # Assign Verdict (Zero-Trust Rules: Incomplete results must NEVER be classified as confidently BENIGN)
        if risk_score >= 70:
            verdict = "MALICIOUS"
        elif risk_score >= 26:
            verdict = "SUSPICIOUS"
        elif analysis_status != "COMPLETE":
            # Missing or failed analyzer results must NEVER be taken as proof of safety or verified infrastructure!
            verdict = "INCONCLUSIVE"
            inconclusive_reasons.append("Low risk score cannot be confirmed due to incomplete analyzer execution.")
        elif has_unverified_infra_signal:
            verdict = "UNVERIFIED_INFRASTRUCTURE"
            factor_desc = "Unverified / Parked Infrastructure (INFO)"
            if factor_desc not in risk_factors:
                risk_factors.append(factor_desc)
            threat_types_set.add("DOMAIN_REPUTATION")
        else:
            verdict = "BENIGN"

        # Calculate Confidence with penalties for missing/failed analyzers
        if counted_findings > 0:
            base_confidence = confidence_sum / counted_findings
        else:
            base_confidence = 92.0 if analysis_status == "COMPLETE" else 50.0

        if analysis_status == "COMPLETE":
            confidence = int(round(min(99, max(60, base_confidence))))
        elif analysis_status == "PARTIAL":
            confidence = int(round(min(65, max(40, base_confidence * 0.7))))
        else:
            confidence = int(round(min(40, max(20, base_confidence * 0.4))))

        return (
            risk_score,
            verdict,
            confidence,
            analysis_status,
            analysis_complete,
            list(threat_types_set),
            risk_factors,
            inconclusive_reasons,
        )
