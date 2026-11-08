import time
import ssl
import socket
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from unittest.mock import MagicMock, patch, AsyncMock
from contextlib import asynccontextmanager
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization

from app.analyzers.url_analyzer import UrlAnalyzer
from app.analyzers.domain_analyzer import DomainAnalyzer
from app.analyzers.tls_analyzer import TlsAnalyzer
from app.analyzers.web_security_analyzer import WebSecurityAnalyzer
from app.analyzers.reputation_analyzer import ReputationAnalyzer
from app.scoring.risk_engine import RiskAggregationEngine
from app.intelligence.connectors import ThreatProviderResult
from app.schemas.response import RawFinding


def generate_cert_der(
    cn: str = "example.com",
    issuer_cn: str = "DigiCert Global Root CA",
    not_before: Optional[datetime] = None,
    not_after: Optional[datetime] = None,
    key_size: int = 2048,
    is_ca: bool = False,
) -> bytes:
    """Generates valid or configurable X.509 DER certificate bytes for offline testing."""
    now = datetime.now(timezone.utc)
    if not_before is None:
        not_before = now - timedelta(days=30)
    if not_after is None:
        not_after = now + timedelta(days=60)

    priv = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subj = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)])
    iss = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(iss)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), critical=True)
    )
    return builder.sign(priv, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def build_mock_tls_socket(tls_cfg: Optional[Dict[str, Any]], domain: str):
    """Constructs a deterministic mock TLS socket for offline testing."""
    now = datetime.now(timezone.utc)
    if tls_cfg is None or tls_cfg.get("status") == "valid":
        issuer = tls_cfg.get("issuer", "DigiCert Global Root CA") if tls_cfg else "DigiCert Global Root CA"
        not_b = now - timedelta(days=30)
        not_a = now + timedelta(days=60)
        der = generate_cert_der(cn=domain, issuer_cn=issuer, not_before=not_b, not_after=not_a)
        cert_dict = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("organizationName", issuer),),),
            "notBefore": not_b.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_a.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else cert_dict
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    anomaly_type = tls_cfg.get("status")
    if anomaly_type == "expired":
        past_date = now - timedelta(days=10)
        not_b = past_date - timedelta(days=365)
        not_a = past_date
        der = generate_cert_der(cn=domain, issuer_cn="Test Public CA", not_before=not_b, not_after=not_a)
        mock_cert = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("organizationName", "Test Public CA"),),),
            "notBefore": not_b.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_a.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else mock_cert
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    elif anomaly_type == "self_signed":
        not_b = now - timedelta(days=10)
        not_a = now + timedelta(days=300)
        der = generate_cert_der(cn=domain, issuer_cn=domain, not_before=not_b, not_after=not_a)
        mock_cert = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("commonName", domain),),),
            "notBefore": not_b.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_a.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else mock_cert
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    elif anomaly_type == "distrusted_ca":
        ca_pattern = tls_cfg.get("ca_pattern", "wosign")
        issuer_name = "WoSign CA Free SSL Certificate G2" if ca_pattern == "wosign" else "DigiNotar Root CA"
        not_b = now - timedelta(days=30)
        not_a = now + timedelta(days=60)
        der = generate_cert_der(cn=domain, issuer_cn=issuer_name, not_before=not_b, not_after=not_a)
        cert_dict = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("organizationName", issuer_name),),),
            "notBefore": not_b.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_a.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else cert_dict
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    elif anomaly_type == "ca_leaf":
        not_b = now - timedelta(days=30)
        not_a = now + timedelta(days=60)
        der = generate_cert_der(cn=domain, issuer_cn="Testing Authority", not_before=not_b, not_after=not_a, is_ca=True)
        cert_dict = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("organizationName", "Testing Authority"),),),
            "notBefore": not_b.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": not_a.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else cert_dict
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    elif anomaly_type == "excessive_validity":
        issued = datetime(2026, 4, 1, 0, 0, 0, tzinfo=timezone.utc)
        expires = issued + timedelta(days=395)
        der = generate_cert_der(cn=domain, issuer_cn="Sectigo Public CA", not_before=issued, not_after=expires)
        cert_dict = {
            "subject": ((("commonName", domain),),),
            "issuer": ((("organizationName", "Sectigo Public CA"),),),
            "notBefore": issued.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": expires.strftime("%b %d %H:%M:%S %Y GMT"),
            "subjectAltName": (("DNS", domain),),
        }
        mock_sock = MagicMock()
        mock_sock.getpeercert.side_effect = lambda binary_form=False: der if binary_form else cert_dict
        mock_sock.version.return_value = "TLSv1.3"
        mock_sock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_sock.__enter__.return_value = mock_sock
        mock_sock.__exit__.return_value = None
        return mock_sock, None

    elif anomaly_type == "unreachable":
        return None, ConnectionRefusedError("Connection refused on port 443")

    return build_mock_tls_socket(None, domain)


def build_mock_http_client(http_cfg: Optional[Dict[str, Any]]):
    """Creates a mock AsyncClient yielding deterministic HTTP headers and body."""
    if http_cfg is None:
        status_code = 200
        headers = {
            "content-type": "text/html; charset=utf-8",
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
        }
        body = b"<!DOCTYPE html><html><head><title>Safe</title></head><body><h1>Welcome</h1></body></html>"
    else:
        status_code = http_cfg.get("status_code", 200)
        headers = {k.lower(): v for k, v in http_cfg.get("headers", {}).items()}
        if "content-type" not in headers:
            headers["content-type"] = "text/html; charset=utf-8"
        raw_body_str = http_cfg.get("html_body", "<!DOCTYPE html><html><body><h1>Safe</h1></body></html>")
        body = raw_body_str.encode("utf-8")

    async def mock_stream(chunk_size=16384):
        yield body

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.headers = headers
    mock_resp.aiter_bytes = mock_stream

    @asynccontextmanager
    async def mock_stream_ctx(method, url):
        yield mock_resp

    mock_client = AsyncMock()
    mock_client.stream = mock_stream_ctx
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = None
    return mock_client


class OfflinePipelineRunner:
    """Executes the exact production SENTRIX scanning pipeline using deterministic offline contexts."""

    def __init__(self):
        self.url_analyzer = UrlAnalyzer()
        self.domain_analyzer = DomainAnalyzer()
        self.tls_analyzer = TlsAnalyzer()
        self.web_analyzer = WebSecurityAnalyzer()
        self.reputation_analyzer = ReputationAnalyzer()
        self.risk_engine = RiskAggregationEngine()

    @staticmethod
    def _stamp_provenance(findings: List[RawFinding], analyzer_name: str) -> None:
        """CAL-06: stamp analyzer provenance onto evidence at collection time."""
        for f in findings:
            if isinstance(f.evidence, dict) and "analyzer" not in f.evidence:
                f.evidence["analyzer"] = analyzer_name

    async def run_case(self, case: Dict[str, Any]) -> Dict[str, Any]:
        start_time = time.perf_counter()

        target_url = case["url"]
        domain = case["normalizedDomain"]
        mock_ctx = case.get("mockContext", {})

        all_findings: List[RawFinding] = []
        statuses: Dict[str, str] = {
            "urlAnalyzer": "PENDING",
            "domainAnalyzer": "PENDING",
            "tlsAnalyzer": "PENDING",
            "webSecurityAnalyzer": "PENDING",
            "reputationAnalyzer": "PENDING",
        }

        # 1. URL Analysis (pure lexical)
        try:
            url_findings = self.url_analyzer.analyze(target_url, domain)
            self._stamp_provenance(url_findings, "urlAnalyzer")
            all_findings.extend(url_findings)
            statuses["urlAnalyzer"] = "SUCCESS"
        except Exception:
            statuses["urlAnalyzer"] = "FAILED"

        # 2. Domain Analysis (taxonomy & heuristics)
        try:
            dom_findings = self.domain_analyzer.analyze(domain)
            self._stamp_provenance(dom_findings, "domainAnalyzer")
            all_findings.extend(dom_findings)
            statuses["domainAnalyzer"] = "SUCCESS"
        except Exception:
            statuses["domainAnalyzer"] = "FAILED"

        # 3. TLS Analysis (deterministic mock socket)
        tls_cfg = mock_ctx.get("tls")
        mock_sock, tls_err = build_mock_tls_socket(tls_cfg, domain)
        try:
            if tls_err and isinstance(tls_err, ConnectionRefusedError):
                with patch("socket.create_connection", side_effect=tls_err):
                    findings_tls, cert_info = self.tls_analyzer.analyze(domain, target_ip="93.184.216.34")
            else:
                with patch("socket.create_connection"), \
                     patch.object(ssl.SSLContext, "wrap_socket", return_value=mock_sock):
                    findings_tls, cert_info = self.tls_analyzer.analyze(domain, target_ip="93.184.216.34")

            self._stamp_provenance(findings_tls, "tlsAnalyzer")
            all_findings.extend(findings_tls)
            statuses["tlsAnalyzer"] = "SUCCESS"
        except Exception:
            statuses["tlsAnalyzer"] = "FAILED"

        # 4. Web Security & DOM Analysis (deterministic mock client)
        http_cfg = mock_ctx.get("http")
        mock_client = build_mock_http_client(http_cfg)
        try:
            with patch("httpx.AsyncClient", return_value=mock_client):
                web_findings, web_meta = await self.web_analyzer.analyze(
                    target_url, domain, pinned_ip="93.184.216.34"
                )
            self._stamp_provenance(web_findings, "webSecurityAnalyzer")
            all_findings.extend(web_findings)
            statuses["webSecurityAnalyzer"] = "SUCCESS"
        except Exception:
            statuses["webSecurityAnalyzer"] = "FAILED"

        # 5. Reputation Analysis (deterministic mock connectors)
        rep_cfg = mock_ctx.get("reputation", {})
        urlhaus_match = rep_cfg.get("urlhaus")
        gsb_match = rep_cfg.get("gsb")

        async def mock_urlhaus(u):
            if urlhaus_match:
                return ThreatProviderResult(
                    provider="urlhaus", status="SUCCESS", outcome="MATCH", details=urlhaus_match
                )
            return ThreatProviderResult(
                provider="urlhaus", status="SUCCESS", outcome="NO_MATCH", details=None
            )

        async def mock_gsb(u):
            if gsb_match:
                return ThreatProviderResult(
                    provider="google_safe_browsing", status="SUCCESS", outcome="MATCH", details=gsb_match
                )
            return ThreatProviderResult(
                provider="google_safe_browsing", status="SUCCESS", outcome="NO_MATCH", details=None
            )

        try:
            with patch.object(self.reputation_analyzer.intel_client, "query_urlhaus", side_effect=mock_urlhaus), \
                 patch.object(self.reputation_analyzer.intel_client, "query_google_safe_browsing", side_effect=mock_gsb):
                rep_findings, rep_status, rep_meta = await self.reputation_analyzer.analyze(target_url, domain)
            self._stamp_provenance(rep_findings, "reputationAnalyzer")
            all_findings.extend(rep_findings)
            statuses["reputationAnalyzer"] = rep_status
        except Exception:
            statuses["reputationAnalyzer"] = "FAILED"

        # 6. Production Risk Aggregation Engine (REAL unmodified evaluation)
        (
            score,
            verdict,
            confidence,
            analysis_status,
            analysis_complete,
            threat_types,
            risk_factors,
            inconclusive_reasons,
        ) = self.risk_engine.evaluate(all_findings, statuses)

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        ground_truth = case["groundTruth"]
        is_correct = (verdict == ground_truth)

        return {
            "id": case["id"],
            "url": target_url,
            "normalizedDomain": domain,
            "category": case["category"],
            "groundTruth": ground_truth,
            "predictedVerdict": verdict,
            "riskScore": score,
            "confidence": confidence,
            "analysisStatus": analysis_status,
            "analysisComplete": analysis_complete,
            "isCorrect": is_correct,
            "latencyMs": round(elapsed_ms, 2),
            "findingsCount": len(all_findings),
            "findings": [
                {"title": f.title, "severity": f.severity, "category": f.category}
                for f in all_findings
            ],
            "riskFactors": risk_factors,
            "threatTypes": threat_types,
        }
