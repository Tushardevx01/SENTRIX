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
  Blocks,
  Sparkles,
  Network,
  RefreshCw,
  Lightbulb,
} from 'lucide-react';
import { motion } from 'framer-motion';
import {
  fetchScanReport,
  fetchScanStatus,
  fetchRelatedThreats,
  registerOnBlockchain,
  verifyOnBlockchain,
  fetchAIExplanation,
} from '@/lib/api';
import { RiskScoreGauge } from '@/components/ui/RiskScoreGauge';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { FindingCard } from '@/components/ui/FindingCard';
import { CertificateCard } from '@/components/ui/CertificateCard';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import {
  type ScanReportDetail,
  VerdictEnum,
  type IRelatedThreats,
  type IBlockchainRecord,
  type IBlockchainVerification,
  type IAIExplanation,
} from '@sentrix/shared';

export default function SecurityReportPage() {
  const params = useParams();
  const id = params?.id as string;

  const [report, setReport] = useState<ScanReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Module Integrations: Correlation, Blockchain, AI
  const [relatedThreats, setRelatedThreats] = useState<IRelatedThreats | null>(null);
  const [blockchainRecord, setBlockchainRecord] = useState<IBlockchainRecord | null>(null);
  const [blockchainVerification, setBlockchainVerification] = useState<IBlockchainVerification | null>(null);
  const [aiExplanation, setAiExplanation] = useState<IAIExplanation | null>(null);
  const [registeringChain, setRegisteringChain] = useState(false);
  const [verifyingChain, setVerifyingChain] = useState(false);

  useEffect(() => {
    if (!id) return;

    let isMounted = true;
    let pollTimer: NodeJS.Timeout | null = null;
    let consecutiveFailures = 0;

    const poll = async () => {
      try {
        // 1. Lightweight status poll using dedicated results endpoint
        const statusData = await fetchScanStatus(id);
        if (!isMounted) return;

        consecutiveFailures = 0; // Reset counter on success

        const status = statusData?.status;
        if (status === 'COMPLETED') {
          // Fetch complete forensic report once scan is COMPLETED
          const fullReport = await fetchScanReport(id);
          if (!isMounted) return;
          setReport(fullReport);
          setLoading(false);

          // Asynchronously load correlation graph, blockchain verification, and AI explanation
          fetchRelatedThreats(fullReport.scan.normalizedDomain)
            .then((r) => isMounted && setRelatedThreats(r))
            .catch(() => {});

          verifyOnBlockchain(id)
            .then((v) => {
              if (isMounted && v.verified) {
                setBlockchainVerification(v);
              }
            })
            .catch(() => {});

          fetchAIExplanation({
            contextType: 'SCAN',
            scanId: id,
            target: fullReport.scan.submittedUrl,
            riskScore: fullReport.scan.riskScore,
            verdict: fullReport.scan.verdict,
            findingsSummary: fullReport.findings.map((f) => f.title),
          })
            .then((res) => isMounted && setAiExplanation(res.explanation))
            .catch(() => {});

          return; // Stop polling on terminal COMPLETED
        }

        if (status === 'FAILED') {
          // Terminal FAILED state
          setReport({
            scan: {
              _id: statusData.scanId,
              submittedUrl: statusData.submittedUrl,
              normalizedDomain: statusData.normalizedDomain,
              status: 'FAILED',
              retryCount: statusData.retryCount || 0,
              errorMessage: statusData.error || 'Security inspection terminated',
              createdAt: statusData.createdAt || new Date().toISOString(),
              riskScore: 0,
              verdict: 'INCONCLUSIVE',
              confidence: 0,
              analyzerStatuses: statusData.analyzerStatuses || {},
            } as any,
            findings: [],
            certificate: null,
            summary: { threatTypes: [], riskFactors: [] },
          });
          setLoading(false);
          return; // Stop polling on terminal FAILED
        }

        // In-flight state: QUEUED or PROCESSING
        setReport({
          scan: {
            _id: statusData.scanId,
            submittedUrl: statusData.submittedUrl,
            normalizedDomain: statusData.normalizedDomain,
            status: statusData.status,
            retryCount: statusData.retryCount || 0,
            analyzerStatuses: statusData.analyzerStatuses,
            createdAt: statusData.createdAt || new Date().toISOString(),
            riskScore: 0,
            verdict: 'BENIGN',
            confidence: 0,
          } as any,
          findings: [],
          certificate: null,
          summary: { threatTypes: [], riskFactors: [] },
        });
        setLoading(false);

        // Schedule next poll tick
        pollTimer = setTimeout(poll, 1500);
      } catch (err: any) {
        if (!isMounted) return;
        consecutiveFailures++;
        if (consecutiveFailures < 3) {
          // Retry with slight backoff on transient network blip
          pollTimer = setTimeout(poll, 2000);
        } else {
          setError(err.message || 'Failed to communicate with scanner service');
          setLoading(false);
        }
      }
    };

    poll();

    return () => {
      isMounted = false;
      if (pollTimer) clearTimeout(pollTimer);
    };
  }, [id]);

  const handleShare = () => {
    if (typeof window !== 'undefined') {
      navigator.clipboard.writeText(window.location.href);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleRegisterOnChain = async () => {
    if (!id || registeringChain) return;
    setRegisteringChain(true);
    try {
      const rec = await registerOnBlockchain(id, 'SCAN');
      setBlockchainRecord(rec);
      const ver = await verifyOnBlockchain(id);
      setBlockchainVerification(ver);
    } catch {
      // non-blocking
    } finally {
      setRegisteringChain(false);
    }
  };

  const handleVerifyOnChain = async () => {
    if (!id || verifyingChain) return;
    setVerifyingChain(true);
    try {
      const ver = await verifyOnBlockchain(id);
      setBlockchainVerification(ver);
    } catch {
      // non-blocking
    } finally {
      setVerifyingChain(false);
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

  // In-flight state: Scan is QUEUED or PROCESSING
  const isInFlight =
    scan.status === 'QUEUED' ||
    scan.status === 'PROCESSING' ||
    scan.status === 'PENDING' ||
    scan.status === 'IN_PROGRESS';

  if (isInFlight) {
    return (
      <div className="space-y-8 py-6 max-w-4xl mx-auto">
        <div className="flex items-center justify-between">
          <Link
            href="/scanner"
            className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Scanner
          </Link>
          <span className="text-xs font-mono text-slate-500">
            Scan ID: <span className="text-slate-300">{scan._id}</span>
          </span>
        </div>

        {/* Live Processing Card */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-8 shadow-2xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-6">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-bold tracking-wider uppercase border ${
                    scan.status === 'QUEUED'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                      : 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30 animate-pulse'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5 animate-spin" />
                  {scan.status === 'QUEUED' ? 'Job Queued' : 'Analysis In Progress'}
                </span>
                <span className="text-xs font-mono text-slate-500">Live Polling (1.5s)</span>
              </div>
              <h1 className="text-xl font-bold text-white font-mono break-all">
                {scan.submittedUrl}
              </h1>
              <p className="text-xs font-mono text-slate-400 mt-1">
                Domain: <span className="text-slate-200">{scan.normalizedDomain}</span>
              </p>
            </div>
            <div className="text-right sm:border-l sm:border-slate-800 sm:pl-6">
              <span className="text-xs font-mono text-slate-500 block">Queue Retries</span>
              <span className="text-sm font-mono text-slate-300 font-bold">
                {scan.retryCount || 0} / 3
              </span>
            </div>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-300 space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold">
              <Clock className="w-4 h-4" />
              <span>
                {scan.status === 'QUEUED'
                  ? 'Scan job is queued in MongoDB; background worker claiming shortly...'
                  : 'Worker active: executing SSRF check, TLS handshake, DOM security analysis, and reputation lookups...'}
              </span>
            </div>
            <p className="text-slate-500 text-[11px]">
              This page updates automatically upon completion without requiring manual refresh.
            </p>
          </div>

          {/* Real-time Analyzer Pipeline Execution Matrix */}
          {scan.analyzerStatuses && (
            <div className="space-y-3">
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Security Pipeline Engine Matrix
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
                {Object.entries(scan.analyzerStatuses).map(([key, status]) => (
                  <div
                    key={key}
                    className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg flex items-center justify-between"
                  >
                    <span className="text-slate-300 truncate capitalize">
                      {key.replace('Analyzer', '')}
                    </span>
                    <span
                      className={
                        status === 'SUCCESS'
                          ? 'text-emerald-400 flex items-center gap-1 font-bold'
                          : status === 'FAILED'
                          ? 'text-red-400 flex items-center gap-1 font-bold'
                          : status === 'TIMEOUT'
                          ? 'text-amber-400 flex items-center gap-1 font-bold'
                          : 'text-slate-500 flex items-center gap-1'
                      }
                    >
                      {status === 'SUCCESS' && <CheckCircle2 className="w-3.5 h-3.5" />}
                      {status === 'FAILED' && <XCircle className="w-3.5 h-3.5" />}
                      {status === 'TIMEOUT' && <Clock className="w-3.5 h-3.5" />}
                      {status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // Failed state
  if (scan.status === 'FAILED') {
    return (
      <div className="space-y-8 py-6 max-w-3xl mx-auto">
        <div className="flex items-center justify-between">
          <Link
            href="/scanner"
            className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Scanner
          </Link>
          <span className="text-xs font-mono text-slate-500">
            Scan ID: <span className="text-slate-300">{scan._id}</span>
          </span>
        </div>

        <div className="bg-red-950/20 border border-red-900/60 rounded-xl p-8 shadow-xl space-y-4">
          <div className="flex items-center gap-3">
            <XCircle className="w-7 h-7 text-red-400 shrink-0" />
            <div>
              <h1 className="text-lg font-bold text-red-200">Security Inspection Terminated</h1>
              <p className="text-xs font-mono text-red-400 mt-0.5">
                The threat verification pipeline encountered an unrecoverable failure or security boundary violation.
              </p>
            </div>
          </div>

          <div className="p-4 bg-slate-950/80 border border-red-900/40 rounded-lg font-mono text-xs text-red-300">
            <span className="text-slate-500 block mb-1">Failure Reason:</span>
            <p className="font-semibold">{scan.errorMessage || 'Unknown execution error'}</p>
          </div>

          <div className="pt-2">
            <Link
              href="/scanner"
              className="inline-flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono rounded-lg transition-colors"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              Return to Scanner
            </Link>
          </div>
        </div>
      </div>
    );
  }

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
            type="button"
            onClick={handleRegisterOnChain}
            disabled={registeringChain || Boolean(blockchainVerification?.verified)}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-theme-accent/30 bg-theme-accent/10 hover:bg-theme-accent/20 text-xs font-mono text-theme-accent transition-colors disabled:opacity-60"
          >
            <Blocks className="w-3.5 h-3.5" />
            <span>
              {registeringChain
                ? 'Registering...'
                : blockchainVerification?.verified
                ? 'On-Chain Verified'
                : 'Anchor to Blockchain'}
            </span>
          </button>
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

      {/* Informational UNVERIFIED_INFRASTRUCTURE Notice Banner */}
      {scan.verdict === VerdictEnum.UNVERIFIED_INFRASTRUCTURE && (
        <div className="bg-slate-50 dark:bg-slate-900/60 border border-slate-300 dark:border-slate-700 rounded-xl p-5 text-slate-800 dark:text-slate-200">
          <div className="flex items-start gap-3">
            <Info className="w-5 h-5 text-slate-500 dark:text-slate-400 shrink-0 mt-0.5" />
            <div className="space-y-1.5">
              <h3 className="text-sm font-bold font-mono text-slate-900 dark:text-slate-100">
                UNVERIFIED INFRASTRUCTURE CLASSIFICATION
              </h3>
              <p className="text-xs text-slate-700 dark:text-slate-300 leading-relaxed font-mono">
                This destination exhibits characteristics of unverified, parked, staging, or low-reputation infrastructure with no active weaponization observed. Unverified infrastructure is not confirmed malicious, but is not verified as safe for enterprise authentication or credential entry.
              </p>
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
            ) : scan.verdict === VerdictEnum.UNVERIFIED_INFRASTRUCTURE ? (
              <>
                <li className="flex items-center gap-2 text-slate-700 dark:text-slate-300">
                  <Info className="w-3.5 h-3.5 shrink-0 text-slate-400" />
                  <span>Exercise caution: verify destination before submitting organizational credentials.</span>
                </li>
                <li className="flex items-center gap-2 text-theme-muted">
                  <Clock className="w-3.5 h-3.5 shrink-0" />
                  <span>Rescan periodically once production services are deployed.</span>
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

      {/* Module D: Grounded AI Threat Explanation & Assessment */}
      {aiExplanation && (
        <section className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-theme-border pb-3">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-text flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-theme-accent" />
              <span>AI Grounded Forensic Analysis & Briefing</span>
            </h4>
            <span className="text-[10px] font-mono text-theme-muted">
              Evidence-Backed • Strict Non-Hallucinatory Grounding
            </span>
          </div>

          <div className="p-3.5 rounded-lg bg-theme-elevated/40 border border-theme-border text-xs text-theme-text font-mono leading-relaxed">
            {aiExplanation.summary}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <span className="text-[11px] font-mono font-semibold text-theme-text flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                Forensic Reasoning & Anomaly Attribution
              </span>
              <ul className="space-y-1.5 text-xs text-theme-muted font-sans">
                {aiExplanation.reasoning.map((r, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="text-theme-accent font-bold">•</span>
                    <span>{r}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="space-y-2">
              <span className="text-[11px] font-mono font-semibold text-theme-text flex items-center gap-1.5">
                <Lightbulb className="w-3.5 h-3.5 text-emerald-500" />
                Actionable Defensive Precautions
              </span>
              <ul className="space-y-1.5 text-xs text-theme-muted font-sans">
                {aiExplanation.precautions.map((p, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {/* Module B: Threat Correlation & Campaign Cluster */}
      {relatedThreats && (
        <section className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-4 shadow-sm">
          <div className="flex items-center justify-between border-b border-theme-border pb-3">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-theme-accent" />
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-text">
                Cross-Vector Threat Correlation Graph
              </h4>
            </div>
            <Link
              href="/correlations"
              className="text-[11px] font-mono text-theme-accent hover:underline flex items-center gap-1"
            >
              Open Campaign Graph <ExternalLink className="w-3 h-3" />
            </Link>
          </div>

          {relatedThreats.campaigns.length === 0 &&
          relatedThreats.relatedScans.length <= 1 &&
          relatedThreats.relatedMessages.length === 0 ? (
            <p className="text-xs font-mono text-theme-muted py-2">
              Isolated target: No persistent campaigns or recurring infrastructure patterns identified across previous scans.
            </p>
          ) : (
            <div className="space-y-4">
              {/* Linked Campaigns */}
              {relatedThreats.campaigns.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-rose-400 font-bold block mb-1.5">
                    Associated Threat Campaigns ({relatedThreats.campaigns.length}):
                  </span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {relatedThreats.campaigns.map((camp) => (
                      <div
                        key={camp._id}
                        className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-xs font-mono space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-rose-300">{camp.name}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300">
                            {camp.threatType}
                          </span>
                        </div>
                        <p className="text-[11px] text-theme-muted line-clamp-2">{camp.summary}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Related Scans */}
              {relatedThreats.relatedScans.filter((s) => s._id !== scan._id).length > 0 && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-theme-muted block mb-1.5">
                    Linked Scans Sharing Domain / IP:
                  </span>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
                    {relatedThreats.relatedScans
                      .filter((s) => s._id !== scan._id)
                      .slice(0, 6)
                      .map((rs) => (
                        <Link
                          key={rs._id}
                          href={`/reports/${rs._id}`}
                          className="p-2.5 rounded-lg bg-theme-base border border-theme-border hover:border-theme-accent transition-colors flex items-center justify-between text-xs font-mono"
                        >
                          <span className="truncate max-w-[150px] text-theme-text text-[11px]">
                            {rs.submittedUrl}
                          </span>
                          <RiskBadge verdict={rs.verdict} size="sm" />
                        </Link>
                      ))}
                  </div>
                </div>
              )}

              {/* Related Messages */}
              {relatedThreats.relatedMessages.length > 0 && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-theme-muted block mb-1.5">
                    Linked Scam Messages Referencing Target:
                  </span>
                  <div className="space-y-1.5">
                    {relatedThreats.relatedMessages.slice(0, 3).map((rm) => (
                      <div
                        key={rm._id}
                        className="p-2.5 rounded-lg bg-theme-base border border-theme-border flex items-center justify-between text-xs font-mono"
                      >
                        <span className="truncate max-w-[320px] text-theme-muted text-[11px]">
                          &quot;{rm.preview}&quot;
                        </span>
                        <RiskBadge verdict={rm.classification} size="sm" />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      )}

      {/* Module C: Web3 Decentralized Threat Registry & Cryptographic Verification */}
      <section className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-4 shadow-sm">
        <div className="flex items-center justify-between border-b border-theme-border pb-3">
          <div className="flex items-center gap-2">
            <Blocks className="w-4 h-4 text-theme-accent" />
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-theme-text">
              Decentralized Threat Registry (Solidity 0.8.20 EVM)
            </h4>
          </div>
          <Link
            href="/blockchain"
            className="text-[11px] font-mono text-theme-accent hover:underline flex items-center gap-1"
          >
            Ledger Explorer <ExternalLink className="w-3 h-3" />
          </Link>
        </div>

        {blockchainVerification?.verified ? (
          <div className="p-4 rounded-lg bg-emerald-500/10 border border-emerald-500/30 space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between">
              <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                REPORT ANCHORED & CRYPTOGRAPHICALLY VERIFIED ON EVM
              </span>
              <button
                type="button"
                onClick={handleVerifyOnChain}
                disabled={verifyingChain}
                className="text-[11px] text-emerald-300 hover:underline flex items-center gap-1"
              >
                {verifyingChain ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                Re-verify Byte-for-Byte
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div>
                <span className="text-theme-muted block">Canonical SHA-256 Hash:</span>
                <code className="text-emerald-300 font-bold break-all block">
                  {blockchainVerification.calculatedHash}
                </code>
              </div>
              <div>
                <span className="text-theme-muted block">Transaction Hash:</span>
                <code className="text-theme-text break-all block">
                  {blockchainVerification.txHash}
                </code>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t border-emerald-500/20 text-[10px] text-theme-muted">
              <div>
                <span className="text-theme-text">Block:</span> #{blockchainVerification.blockNumber || 1}
              </div>
              <div>
                <span className="text-theme-text">Contract:</span>{' '}
                <span className="truncate inline-block max-w-[140px] align-bottom">
                  {blockchainVerification.contractAddress}
                </span>
              </div>
              <div>
                <span className="text-theme-text">Network:</span> EVM Sepolia / Hardhat
              </div>
            </div>
          </div>
        ) : (
          <div className="p-4 rounded-lg bg-theme-base border border-theme-border space-y-3 font-mono text-xs">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <span className="text-theme-text font-bold block">
                  Immutable Threat Intelligence Commitment
                </span>
                <p className="text-[11px] text-theme-muted mt-0.5">
                  Anchor this scan report to the blockchain to produce a cryptographic proof-of-threat that cannot be altered or deleted.
                </p>
              </div>
              <button
                type="button"
                onClick={handleRegisterOnChain}
                disabled={registeringChain}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-theme-accent text-white font-mono text-xs font-semibold hover:bg-theme-accent/90 disabled:opacity-50 transition-all shrink-0 shadow-sm"
              >
                <Blocks className="w-3.5 h-3.5" />
                {registeringChain ? 'Publishing to EVM...' : 'Anchor to ThreatRegistry.sol'}
              </button>
            </div>
          </div>
        )}
      </section>
    </motion.div>
  );
}
