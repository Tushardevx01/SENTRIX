from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class RawFinding(BaseModel):
    category: str = Field(..., description="Finding category enum")
    severity: str = Field(..., description="Finding severity: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(..., ge=0, le=100)


class CertificateInfo(BaseModel):
    issuer: str
    subject: str
    validFrom: str
    validUntil: str
    fingerprint: str
    hostnameMatched: bool
    rawDetails: Optional[Dict[str, Any]] = None


class AnalyzerStatuses(BaseModel):
    urlAnalyzer: str = "PENDING"
    domainAnalyzer: str = "PENDING"
    tlsAnalyzer: str = "PENDING"
    webSecurityAnalyzer: str = "PENDING"
    reputationAnalyzer: str = "PENDING"


class ScanSummary(BaseModel):
    threatTypes: List[str] = Field(default_factory=list)
    riskFactors: List[str] = Field(default_factory=list)
    mitreTactics: List[str] = Field(default_factory=list)
    redirectChain: List[str] = Field(default_factory=list)
    responseTimeMs: Optional[float] = None
    isTruncated: bool = False
    inconclusiveReasons: List[str] = Field(default_factory=list)


class AnalysisResponse(BaseModel):
    scanId: str
    targetUrl: str
    normalizedDomain: str
    ipAddress: Optional[str] = None
    riskScore: int = Field(..., ge=0, le=100)
    verdict: str = Field(..., description="BENIGN, SUSPICIOUS, MALICIOUS, INCONCLUSIVE")
    confidence: int = Field(..., ge=0, le=100)
    analysisStatus: str = Field(default="COMPLETE", description="COMPLETE, PARTIAL, FAILED")
    analysisComplete: bool = Field(default=True)
    analyzerStatuses: Dict[str, str]
    findings: List[RawFinding]
    certificate: Optional[CertificateInfo] = None
    summary: ScanSummary
