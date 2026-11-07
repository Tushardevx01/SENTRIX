from typing import List, Tuple
from app.schemas.response import RawFinding

SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5,
    "INFO": 0,
}


class RiskAggregationEngine:
    """Computes transparent, explainable threat scores and classification verdicts."""

    def evaluate(self, findings: List[RawFinding]) -> Tuple[int, str, int, List[str], List[str]]:
        raw_score = 0
        risk_factors: List[str] = []
        threat_types_set = set()

        confidence_sum = 0.0
        counted_findings = 0

        for f in findings:
            weight = SEVERITY_WEIGHTS.get(f.severity.upper(), 0)
            raw_score += weight
            confidence_sum += f.confidence
            counted_findings += 1

            if f.severity.upper() in {"CRITICAL", "HIGH", "MEDIUM"}:
                risk_factors.append(f"{f.title} ({f.severity})")
                threat_types_set.add(f.category)

        # Cap score at 100
        risk_score = min(100, max(0, raw_score))

        # Assign verdict
        if risk_score >= 70:
            verdict = "MALICIOUS"
        elif risk_score >= 26:
            verdict = "SUSPICIOUS"
        else:
            verdict = "BENIGN"

        confidence = int(round(confidence_sum / max(1, counted_findings))) if counted_findings else 75
        confidence = min(99, max(50, confidence))

        return risk_score, verdict, confidence, list(threat_types_set), risk_factors
