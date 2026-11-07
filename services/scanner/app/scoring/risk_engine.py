from typing import List, Tuple, Dict
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
        raw_score = 0
        risk_factors: List[str] = []
        threat_types_set = set()
        inconclusive_reasons: List[str] = []

        confidence_sum = 0.0
        counted_findings = 0

        for f in findings:
            sev = f.severity.upper()
            weight = SEVERITY_WEIGHTS.get(sev, 0)
            raw_score += weight
            confidence_sum += f.confidence
            counted_findings += 1

            if sev in {"CRITICAL", "HIGH", "MEDIUM"}:
                risk_factors.append(f"{f.title} ({sev})")
                threat_types_set.add(f.category)

        # Cap risk score between 0 and 100
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

        # Assign Verdict (Zero-Trust Rules: Incomplete results must NEVER be classified as confidently BENIGN)
        if risk_score >= 70:
            verdict = "MALICIOUS"
        elif risk_score >= 26:
            verdict = "SUSPICIOUS"
        else:
            # Score is low (0 - 25)
            if analysis_status == "COMPLETE":
                verdict = "BENIGN"
            else:
                # Missing or failed analyzer results must NEVER be taken as proof of safety!
                verdict = "INCONCLUSIVE"
                inconclusive_reasons.append("Low risk score cannot be confirmed as BENIGN due to incomplete analyzer execution.")

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
