'use client';

import React, { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldAlert,
  ArrowLeft,
  Clock,
  Globe,
  Layers,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Share2,
  Info,
  HelpCircle,
  Shield,
  Lock,
  Terminal,
  ExternalLink,
  ChevronRight,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { fetchScanReport } from '@/lib/api';
import { RiskScoreGauge } from '@/components/ui/RiskScoreGauge';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { FindingCard } from '@/components/ui/FindingCard';
import { CertificateCard } from '@/components/ui/CertificateCard';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type ScanReportDetail, VerdictEnum } from '@sentrix/shared';

export default function SecurityReportPage() {
  const params = useParams();
  const id = params?.id as string;

  const [report, setReport] = useState<ScanReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    fetchScanReport(id)
      .then((data) => {
        if (isMounted) {
          setReport(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Failed to load report');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [id]);

  const handleShare = () => {
    if (typeof window !== 'undefined') {
      navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (loading) {
    return <LoadingState message="Loading Forensic Security Report..." />;
  }

  if (error || !report) {
    return (
      <ErrorState
        title="Security Report Retrieval Error"
        message={error || 'Report not found for this identifier.'}
        onRetry={() => window.location.reload()}
      />
    );
  }

  const { scan, findings, certificate, summary } = report;

  // Determine MITRE ATT&CK Tactics
  const mitreTactics = [];
  if (scan.verdict === VerdictEnum.MALICIOUS || scan.riskScore >= 70) {
    mitreTactics.push({ id: 'T1566.002', name: 'Phishing: Spearphishing Link' });
    mitreTactics.push({ id: 'T1056.003', name: 'Credential Harvesting: Web Form' });
  } else if (scan.verdict === VerdictEnum.SUSPICIOUS) {
    mitreTactics.push({ id: 'T1583.001', name: 'Acquire Infrastructure: Domains' });
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-8 py-4 max-w-5xl mx-auto"
    >
      {/* Top Breadcrumb & Share Action */}
      <div className="flex items-center justify-between">
        <Link
          href="/scanner"
          className="inline-flex items-center gap-1.5 text-xs font-mono text-theme-muted hover:text-theme-text transition-colors font-medium"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Scanner</span>
        </Link>
        <div className="flex items-center gap-3">
          <button
            onClick={handleShare}
            type="button"
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-theme-border bg-theme-card hover:bg-theme-elevated text-xs font-mono text-theme-text transition-colors"
          >
            <Share2 className="w-3.5 h-3.5 text-theme-muted" />
            <span>{copied ? 'Link Copied!' : 'Share IOC'}</span>
          </button>
          <span className="text-xs font-mono text-theme-muted">
            Report ID: <span className="font-semibold text-theme-text">{scan._id.slice(-8)}</span>
          </span>
        </div>
      </div>

      {/* Main Forensic Header Banner */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-6 shadow-card">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
          <div className="lg:col-span-2 space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge verdict={scan.verdict} size="lg" />
              <span className="text-xs font-mono text-theme-muted bg-theme-elevated px-2.5 py-1 rounded-lg border border-theme-borderSubtle">
                Status: <strong className="text-theme-text">{scan.status}</strong>
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold font-mono text-theme-text break-all">
              {scan.submittedUrl}
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-theme-muted pt-1">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-theme-accent" />
                Domain: <strong className="text-theme-text">{scan.normalizedDomain}</strong>
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-theme-muted" />
                Scanned: {new Date(scan.createdAt).toLocaleString()}
              </span>
              {summary?.responseTimeMs && (
                <span className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-theme-success" />
                  Latency: {summary.responseTimeMs}ms
                </span>
              )}
            </div>
          </div>

          <div className="flex justify-center lg:justify-end border-t lg:border-t-0 lg:border-l border-theme-border pt-4 lg:pt-0">
            <RiskScoreGauge
              score={scan.riskScore}
              verdict={scan.verdict}
              confidence={scan.confidence}
            />
          </div>
        </div>
      </div>

      {/* Zero-Trust INCONCLUSIVE Notice Banner */}
      {(scan.verdict === VerdictEnum.INCONCLUSIVE ||
        scan.analysisComplete === false ||
        scan.analysisStatus === 'PARTIAL') && (
        <div className="bg-amber-50 dark:bg-amber-950/30 border border-amber-300 dark:border-amber-700/60 rounded-xl p-5 text-amber-900 dark:text-amber-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <h3 className="text-sm font-bold font-mono text-amber-800 dark:text-amber-300">
                ZERO-TRUST INCONCLUSIVE STATE TRIGGERED
              </h3>
              <p className="text-xs text-amber-800/90 dark:text-amber-200/90 leading-relaxed font-mono">
                One or more security analyzers could not verify this destination (e.g. host unreachable,
                connection timeout, or TLS handshake refusal). In accordance with SENTRIX zero-trust policy,
                absence of findings does <strong>NOT</strong> prove the target is benign.
              </p>
              {summary?.inconclusiveReasons && summary.inconclusiveReasons.length > 0 && (
                <ul className="list-disc list-inside text-xs text-amber-800 dark:text-amber-300 mt-2 space-y-0.5 font-mono">
                  {summary.inconclusiveReasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Streaming Response Truncation Notice */}
      {summary?.isTruncated && (
        <div className="bg-theme-elevated border border-theme-border rounded-xl px-4 py-3 text-xs font-mono text-theme-text flex items-center gap-2">
          <Info className="w-4 h-4 text-theme-info shrink-0" />
          <span>HTTP response body exceeded 1 MB streaming limit and was safely bounded during analysis.</span>
        </div>
      )}

      {/* Analyzer Pipeline Execution Matrix */}
      {scan.analyzerStatuses && (
        <div className="bg-theme-card border border-theme-border rounded-xl p-5 space-y-3 shadow-xs">
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-muted">
            SECURITY ANALYZER ENGINE STATUS
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
            {Object.entries(scan.analyzerStatuses).map(([key, status]) => (
              <div
                key={key}
                className="p-3 bg-theme-elevated border border-theme-borderSubtle rounded-lg flex items-center justify-between"
              >
                <span className="text-theme-text font-medium truncate capitalize">
                  {key.replace('Analyzer', '')}
                </span>
                <span
                  className={
                    status === 'SUCCESS'
                      ? 'text-theme-success font-semibold flex items-center gap-1'
                      : status === 'FAILED'
                      ? 'text-theme-danger font-semibold flex items-center gap-1'
                      : status === 'TIMEOUT'
                      ? 'text-theme-warning font-semibold flex items-center gap-1'
                      : 'text-theme-muted'
                  }
                >
                  {status === 'SUCCESS' && <CheckCircle2 className="w-3.5 h-3.5" />}
                  {status === 'FAILED' && <XCircle className="w-3.5 h-3.5" />}
                  {status === 'TIMEOUT' && <Clock className="w-3.5 h-3.5" />}
                  <span>{status}</span>
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TLS Certificate Section */}
      <section className="space-y-3">
        <h2 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
          <Lock className="w-4 h-4 text-theme-accent" />
          <span>SSL/TLS CRYPTOGRAPHIC EVALUATION</span>
        </h2>
        <CertificateCard certificate={certificate} />
      </section>

      {/* Security Findings Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-theme-accent" />
            <span>IDENTIFIED THREAT INDICATORS & EVIDENCE</span>
            <span className="px-2 py-0.5 rounded-full bg-theme-elevated text-xs font-mono text-theme-muted border border-theme-borderSubtle">
              {findings.length}
            </span>
          </h2>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 rounded-xl bg-theme-card border border-theme-border text-center text-theme-muted">
            <CheckCircle2 className="w-8 h-8 text-theme-success mx-auto mb-2" />
            <p className="text-sm font-bold text-theme-text font-mono">Zero Threat Indicators Identified</p>
            <p className="text-xs font-mono text-theme-muted mt-1">
              Target passed lexical heuristics, TLS verification, and reputation blacklists.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {findings.map((finding) => (
              <FindingCard key={finding._id} finding={finding} />
            ))}
          </div>
        )}
      </section>

      {/* Redirection Trace if any */}
      {summary?.redirectChain && summary.redirectChain.length > 1 && (
        <section className="space-y-3">
          <h3 className="text-sm font-bold font-mono text-theme-text">REDIRECTION CHAIN AUDIT</h3>
          <div className="p-4 bg-theme-card border border-theme-border rounded-xl font-mono text-xs text-theme-text space-y-2">
            {summary.redirectChain.map((step, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <span className="text-theme-accent font-bold">[{idx + 1}]</span>
                <span className="break-all">{step}</span>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* MITRE ATT&CK Mapping & SOC Remediation Guidance */}
      <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* MITRE ATT&CK */}
        <div className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-3">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-text flex items-center gap-2">
            <Terminal className="w-4 h-4 text-theme-accent" />
            <span>MITRE ATT&CK MAPPING</span>
          </h4>
          {mitreTactics.length > 0 ? (
            <div className="space-y-2">
              {mitreTactics.map((tac) => (
                <div
                  key={tac.id}
                  className="p-2.5 bg-theme-elevated rounded-lg border border-theme-borderSubtle text-xs font-mono flex items-center justify-between"
                >
                  <span className="font-semibold text-theme-text">{tac.name}</span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-theme-card text-theme-accent font-bold">
                    {tac.id}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs font-mono text-theme-muted">
              No hostile MITRE ATT&CK techniques observed for this target.
            </p>
          )}
        </div>

        {/* SOC Remediation */}
        <div className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-3">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-text flex items-center gap-2">
            <Shield className="w-4 h-4 text-theme-accent" />
            <span>RECOMMENDED MITIGATION ACTIONS</span>
          </h4>
          <ul className="text-xs font-mono text-theme-muted space-y-2">
            {scan.verdict === VerdictEnum.MALICIOUS ? (
              <>
                <li className="flex items-center gap-2 text-theme-danger">
                  <XCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>Block domain immediately at perimeter firewall / DNS resolver.</span>
                </li>
                <li className="flex items-center gap-2 text-theme-danger">
                  <XCircle className="w-3.5 h-3.5 shrink-0" />
                  <span>Revoke any credentials or session tokens submitted to this target.</span>
                </li>
                <li className="flex items-center gap-2 text-theme-text">
                  <CheckCircle2 className="w-3.5 h-3.5 text-theme-success shrink-0" />
                  <span>Publish IOC to community threat feed for peer verification.</span>
                </li>
              </>
            ) : scan.verdict === VerdictEnum.SUSPICIOUS ? (
              <>
                <li className="flex items-center gap-2 text-theme-warning">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Restrict user access and mandate multi-factor re-authentication.</span>
                </li>
                <li className="flex items-center gap-2 text-theme-text">
                  <CheckCircle2 className="w-3.5 h-3.5 text-theme-success shrink-0" />
                  <span>Monitor subsequent network connections to destination IP.</span>
                </li>
              </>
            ) : (
              <li className="flex items-center gap-2 text-theme-success">
                <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                <span>Standard traffic allowed. Periodic re-verification scheduled.</span>
              </li>
            )}
          </ul>
        </div>
      </section>
    </motion.div>
  );
}
