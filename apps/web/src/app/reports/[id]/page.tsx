'use client';

import React, { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  ShieldAlert,
  ArrowLeft,
  ExternalLink,
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
} from 'lucide-react';
import { fetchScanReport } from '@/lib/api';
import { RiskScoreGauge } from '@/components/ui/RiskScoreGauge';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { FindingCard } from '@/components/ui/FindingCard';
import { CertificateCard } from '@/components/ui/CertificateCard';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type ScanReportDetail } from '@sentrix/shared';

export default function SecurityReportPage() {
  const params = useParams();
  const id = params?.id as string;

  const [report, setReport] = useState<ScanReportDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <div className="space-y-8 py-4">
      {/* Back button & Actions */}
      <div className="flex items-center justify-between">
        <Link
          href="/scanner"
          className="inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Scanner
        </Link>
        <span className="text-xs font-mono text-slate-500">
          Report ID: <span className="text-slate-300">{scan._id}</span>
        </span>
      </div>

      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
          <div className="lg:col-span-2 space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <RiskBadge verdict={scan.verdict} size="lg" />
              <span className="text-xs font-mono text-slate-400 bg-slate-800 px-2.5 py-1 rounded">
                Status: {scan.status}
              </span>
            </div>

            <h1 className="text-xl sm:text-2xl font-bold font-mono text-white break-all">
              {scan.submittedUrl}
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-xs font-mono text-slate-400 pt-1">
              <span className="flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-electric-400" />
                Domain: <strong className="text-slate-200">{scan.normalizedDomain}</strong>
              </span>
              <span className="flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Scanned: {new Date(scan.createdAt).toLocaleString()}
              </span>
              {summary?.responseTimeMs && (
                <span className="flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-emerald-400" />
                  Latency: {summary.responseTimeMs}ms
                </span>
              )}
            </div>
          </div>

          <div className="flex justify-center lg:justify-end border-t lg:border-t-0 lg:border-l border-slate-800 pt-4 lg:pt-0">
            <RiskScoreGauge
              score={scan.riskScore}
              verdict={scan.verdict}
              confidence={scan.confidence}
            />
          </div>
        </div>
      </div>

      {/* Inconclusive / Partial Analysis Notice */}
      {(scan.verdict === 'INCONCLUSIVE' || scan.analysisComplete === false || scan.analysisStatus === 'PARTIAL') && (
        <div className="bg-amber-950/40 border border-amber-600/50 rounded-xl p-4 text-amber-200">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <h3 className="text-sm font-bold font-mono text-amber-300">
                Inconclusive / Partial Inspection Notice
              </h3>
              <p className="text-xs text-amber-200/90 leading-relaxed">
                One or more security analyzers could not complete inspection (e.g. host unreachable, connection timeout, or TLS handshake refusal). In accordance with zero-trust security policy, absence of findings does <strong>NOT</strong> prove the target is benign.
              </p>
              {summary?.inconclusiveReasons && summary.inconclusiveReasons.length > 0 && (
                <ul className="list-disc list-inside text-xs text-amber-300/80 mt-2 space-y-0.5 font-mono">
                  {summary.inconclusiveReasons.map((reason, idx) => (
                    <li key={idx}>{reason}</li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Response Truncation Notice */}
      {summary?.isTruncated && (
        <div className="bg-slate-900/60 border border-slate-700 rounded-lg px-4 py-2.5 text-xs font-mono text-slate-300 flex items-center gap-2">
          <Info className="w-4 h-4 text-sky-400 shrink-0" />
          <span>HTTP response body exceeded 1 MB streaming limit and was safely truncated during analysis.</span>
        </div>
      )}

      {/* Analyzer Pipeline Execution Matrix */}
      {scan.analyzerStatuses && (
        <div className="bg-slate-900/40 border border-slate-800/80 rounded-xl p-4">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            Security Analyzer Engine Pipeline
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs font-mono">
            {Object.entries(scan.analyzerStatuses).map(([key, status]) => (
              <div
                key={key}
                className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg flex items-center justify-between"
              >
                <span className="text-slate-300 truncate capitalize">
                  {key.replace('Analyzer', '')}
                </span>
                <span
                  className={
                    status === 'SUCCESS'
                      ? 'text-emerald-400 flex items-center gap-1'
                      : status === 'FAILED'
                      ? 'text-red-400 flex items-center gap-1'
                      : status === 'TIMEOUT'
                      ? 'text-amber-400 flex items-center gap-1'
                      : 'text-slate-500'
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

      {/* TLS Certificate Section */}
      <section className="space-y-3">
        <h2 className="text-base font-bold text-white flex items-center gap-2">
          <span>SSL/TLS Cryptographic Evaluation</span>
        </h2>
        <CertificateCard certificate={certificate} />
      </section>

      {/* Security Findings Section */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <span>Identified Threat Indicators & Anomalies</span>
            <span className="px-2 py-0.5 rounded-full bg-slate-800 text-xs font-mono text-slate-300">
              {findings.length}
            </span>
          </h2>
        </div>

        {findings.length === 0 ? (
          <div className="p-8 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-slate-400">
            <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
            <p className="text-sm font-semibold text-slate-200">Zero Threat Indicators Identified</p>
            <p className="text-xs font-mono text-slate-500 mt-1">
              Target passed heuristic URL checks, TLS validation, and domain reputation filters.
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

      {/* Redirect & MITRE Context */}
      {summary?.redirectChain && summary.redirectChain.length > 1 && (
        <section className="space-y-3">
          <h3 className="text-sm font-bold text-white">Redirection Trace</h3>
          <div className="p-4 bg-slate-900/60 border border-slate-800 rounded-lg font-mono text-xs text-slate-300 space-y-2">
            {summary.redirectChain.map((step, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <span className="text-electric-400 font-bold">[{idx + 1}]</span>
                <span className="break-all">{step}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
