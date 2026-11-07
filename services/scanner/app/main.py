import time
from typing import Dict, Optional
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Header, HTTPException, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.schemas.request import AnalysisRequest
from app.schemas.response import (
    AnalysisResponse,
    AnalyzerStatuses,
    ScanSummary,
)
from app.safety.ssrf_guard import validate_url_safety, SSRFSecurityException
from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.tls_analyzer import TlsAnalyzer
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine

START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup validation
    if not settings.SCANNER_API_SECRET:
        raise RuntimeError("SCANNER_API_SECRET must be configured in environment.")
    yield


app = FastAPI(
    title="SENTRIX Threat Scanner Engine",
    description="Dedicated High-Performance Website & URL Threat Intelligence Analysis Engine",
    version="1.0.0",
    lifespan=lifespan,
)


def verify_internal_secret(
    x_scanner_secret: Optional[str] = Header(None, alias="X-Scanner-Secret", description="Internal authentication secret")
):
    if not x_scanner_secret or x_scanner_secret != settings.SCANNER_API_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing internal scanner authorization secret.",
        )
    return True


@app.exception_handler(SSRFSecurityException)
async def ssrf_exception_handler(request, exc: SSRFSecurityException):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": "SSRF_VIOLATION",
            "message": str(exc),
            "detail": "Target destination violated perimeter safety policies or targeted internal networks."
        }
    )


@app.get("/health", tags=["System"])
async def health_check():
    return {
        "status": "healthy",
        "service": "sentrix-scanner",
        "version": "1.0.0",
        "uptimeSeconds": round(time.time() - START_TIME, 2),
        "analyzers": [
            "UrlAnalyzer",
            "DomainAnalyzer",
            "TlsAnalyzer",
            "WebSecurityAnalyzer",
            "ReputationAnalyzer",
        ],
    }


@app.post(
    "/api/v1/analyze",
    response_model=AnalysisResponse,
    dependencies=[Depends(verify_internal_secret)],
    tags=["Analysis"],
)
async def run_threat_analysis(request: AnalysisRequest):
    # Step 1: Pre-flight SSRF & Network Safety Validation
    target_host, resolved_ips = validate_url_safety(request.url)
    primary_ip = resolved_ips[0] if resolved_ips else None

    # Step 2: Initialize Analyzers
    url_analyzer = UrlAnalyzer()
    domain_analyzer = DomainAnalyzer()
    tls_analyzer = TlsAnalyzer()
    web_analyzer = WebSecurityAnalyzer()
    reputation_analyzer = ReputationAnalyzer()
    risk_engine = RiskAggregationEngine()

    all_findings = []
    statuses: Dict[str, str] = {
        "urlAnalyzer": "PENDING",
        "domainAnalyzer": "PENDING",
        "tlsAnalyzer": "PENDING",
        "webSecurityAnalyzer": "PENDING",
        "reputationAnalyzer": "PENDING",
    }

    # 1. URL Analysis
    try:
        url_findings = url_analyzer.analyze(request.url, request.normalizedDomain)
        all_findings.extend(url_findings)
        statuses["urlAnalyzer"] = "SUCCESS"
    except Exception as e:
        statuses["urlAnalyzer"] = "FAILED"

    # 2. Domain Analysis
    try:
        domain_findings = domain_analyzer.analyze(request.normalizedDomain)
        all_findings.extend(domain_findings)
        statuses["domainAnalyzer"] = "SUCCESS"
    except Exception as e:
        statuses["domainAnalyzer"] = "FAILED"

    # 3. TLS / SSL Analysis
    certificate_info = None
    try:
        tls_findings, certificate_info = tls_analyzer.analyze(request.normalizedDomain)
        all_findings.extend(tls_findings)
        statuses["tlsAnalyzer"] = "SUCCESS"
    except Exception as e:
        statuses["tlsAnalyzer"] = "FAILED"

    # 4. Web Security & DOM Analysis
    redirect_chain = []
    response_time_ms = None
    try:
        web_findings, web_meta = await web_analyzer.analyze(request.url, request.normalizedDomain)
        all_findings.extend(web_findings)
        redirect_chain = web_meta.get("redirectChain", [])
        response_time_ms = web_meta.get("responseTimeMs")
        statuses["webSecurityAnalyzer"] = "SUCCESS"
    except Exception as e:
        statuses["webSecurityAnalyzer"] = "FAILED"

    # 5. Reputation & Blacklist Intelligence
    try:
        rep_findings = await reputation_analyzer.analyze(request.url, request.normalizedDomain)
        all_findings.extend(rep_findings)
        statuses["reputationAnalyzer"] = "SUCCESS"
    except Exception as e:
        statuses["reputationAnalyzer"] = "FAILED"

    # Step 3: Compute Aggregated Risk Score and Verdict
    score, verdict, confidence, threat_types, risk_factors = risk_engine.evaluate(all_findings)

    return AnalysisResponse(
        scanId=request.scanId,
        targetUrl=request.url,
        normalizedDomain=request.normalizedDomain,
        ipAddress=primary_ip,
        riskScore=score,
        verdict=verdict,
        confidence=confidence,
        analyzerStatuses=statuses,
        findings=all_findings,
        certificate=certificate_info,
        summary=ScanSummary(
            threatTypes=threat_types,
            riskFactors=risk_factors,
            mitreTactics=["Reconnaissance", "Initial Access", "Credential Access"] if verdict != "BENIGN" else [],
            redirectChain=redirect_chain,
            responseTimeMs=response_time_ms,
        )
    )
