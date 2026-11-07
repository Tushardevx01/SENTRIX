'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldCheck,
  Search,
  AlertCircle,
  ArrowRight,
  Layers,
  Lock,
  Globe,
  Radio,
  Server,
  Zap,
  Activity,
  CheckCircle2,
  Clock,
  Sparkles,
  ExternalLink,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { submitUrlScan } from '@/lib/api';

function ScannerContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [url, setUrl] = useState('');
  const [deepScan, setDeepScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activeStage, setActiveStage] = useState(0);
  const [error, setError] = useState<string | null>(null);

  // Check if target param is present in URL
  useEffect(() => {
    const target = searchParams?.get('target');
    if (target) {
      setUrl(target);
    }
  }, [searchParams]);

  const stages = [
    { title: 'SSRF Perimeter Guard', desc: 'Pre-flight DNS resolution, RFC 1918 filter & cloud metadata check' },
    { title: 'Socket-Level Handshake', desc: 'Pinned TCP connection and anti-TOCTOU rebinding validation' },
    { title: 'TLS & Cipher Audit', desc: 'Direct X.509 certificate chain inspection and SAN validation' },
    { title: 'Lexical & Brand Heuristics', desc: 'Punycode detection, typosquatting & DOM form exfiltration' },
    { title: 'Threat Intelligence Feeds', desc: 'URLhaus malware queries and crowdsourced consensus' },
    { title: 'Risk Aggregation & Scoring', desc: 'Synthesizing 0–100 threat score and MITRE ATT&CK tactics' },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setActiveStage(0);

    // Progress animation timer
    const interval = setInterval(() => {
      setActiveStage((prev) => (prev < stages.length - 1 ? prev + 1 : prev));
    }, 450);

    try {
      const res = await submitUrlScan(url.trim(), deepScan);
      clearInterval(interval);
      if (res?.scanId) {
        router.push(`/reports/${res.scanId}`);
      }
    } catch (err: any) {
      clearInterval(interval);
      setError(err.message || 'An error occurred during threat analysis.');
      setLoading(false);
    }
  };

  const sampleUrls = [
    'https://login.microsoftonline-verification.xyz',
    'https://paypal-security-update.com/signin',
    'https://github.com',
  ];

  return (
    <div className="max-w-4xl mx-auto space-y-8 py-4">
      {/* Header Banner */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Interactive Sandbox Engine</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
          URL THREAT INSPECTION ENGINE
        </h1>
        <p className="text-xs text-theme-muted font-mono max-w-2xl">
          Submit any untrusted URL, hostname, or IP address to trigger comprehensive multi-vector
          forensic analysis in an isolated sandbox.
        </p>
      </div>

      {/* Main Inspection Form Card */}
      <div className="p-6 sm:p-8 rounded-xl border border-theme-border bg-theme-card shadow-card">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-mono font-semibold uppercase text-theme-text mb-2">
              Target Destination (URL, Hostname, or Domain)
            </label>
            <div className="flex items-center gap-3 p-3 bg-theme-bg border border-theme-border rounded-lg focus-within:border-theme-accent focus-within:ring-1 focus-within:ring-theme-accent/30 transition-all">
              <Search className="w-5 h-5 text-theme-muted shrink-0" />
              <input
                type="text"
                placeholder="https://example-verification-portal.xyz/login"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                disabled={loading}
                className="w-full bg-transparent text-theme-text placeholder:text-theme-muted text-sm font-mono focus:outline-none"
                required
              />
              {url && (
                <button
                  type="button"
                  onClick={() => setUrl('')}
                  className="text-xs font-mono text-theme-muted hover:text-theme-text"
                >
                  Clear
                </button>
              )}
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 mt-2 text-[11px] font-mono text-theme-muted">
              <span>Supports HTTPS/HTTP schemes, raw hostnames, and IP targets.</span>
              <div className="flex items-center gap-1.5">
                <span>Samples:</span>
                {sampleUrls.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setUrl(s)}
                    className="hover:text-theme-accent underline truncate max-w-[140px]"
                  >
                    {s.replace('https://', '')}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Deep Scan Toggle */}
          <div className="flex items-start gap-3 p-3.5 bg-theme-elevated rounded-lg border border-theme-borderSubtle">
            <input
              type="checkbox"
              id="deepScan"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
              disabled={loading}
              className="mt-0.5 w-4 h-4 rounded border-theme-border bg-theme-card text-theme-accent focus:ring-theme-accent/30"
            />
            <label htmlFor="deepScan" className="text-xs font-mono text-theme-muted cursor-pointer flex-1">
              <span className="font-semibold text-theme-text block">
                Deep Sandbox Inspection (Multi-hop redirects & extended DOM forms)
              </span>
              Enables iterative redirect tracing (max 5 hops) with per-hop SSRF validation and
              content-type verified streaming body analysis.
            </label>
          </div>

          {/* Error Banner */}
          {error && (
            <div className="p-4 bg-theme-danger/10 border border-theme-danger/30 rounded-lg flex items-start gap-3 text-xs font-mono text-theme-danger">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block text-theme-danger">Inspection Blocked / Error:</span>
                <p className="mt-0.5 leading-relaxed">{error}</p>
              </div>
            </div>
          )}

          {/* Action Button */}
          <button
            type="submit"
            disabled={loading || !url.trim()}
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-3.5 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-sm font-mono transition-opacity hover:opacity-90 disabled:opacity-50 shadow-sm"
          >
            {loading ? (
              <>
                <span className="w-4 h-4 rounded-full border-2 border-white dark:border-slate-950 border-t-transparent animate-spin" />
                <span>Executing SENTRIX Threat Pipeline...</span>
              </>
            ) : (
              <>
                <span>Launch Multi-Vector Threat Analysis</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>
      </div>

      {/* Animated Pipeline Stage Monitor when Loading */}
      {loading && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-card space-y-4"
        >
          <div className="flex items-center justify-between pb-3 border-b border-theme-border">
            <span className="text-xs font-mono font-bold text-theme-text flex items-center gap-2">
              <Activity className="w-4 h-4 text-theme-accent animate-pulse" />
              PIPELINE EXECUTION IN PROGRESS
            </span>
            <span className="text-xs font-mono text-theme-muted">
              Stage {activeStage + 1} of {stages.length}
            </span>
          </div>

          <div className="space-y-3">
            {stages.map((stg, index) => {
              const isPast = index < activeStage;
              const isCurrent = index === activeStage;

              return (
                <div
                  key={stg.title}
                  className={`flex items-start gap-3 p-3 rounded-lg border text-xs font-mono transition-all ${
                    isCurrent
                      ? 'border-theme-accent bg-theme-accent/5 text-theme-text shadow-xs'
                      : isPast
                      ? 'border-theme-success/30 bg-theme-success/5 text-theme-text'
                      : 'border-theme-borderSubtle bg-theme-elevated/40 text-theme-muted opacity-60'
                  }`}
                >
                  <div className="mt-0.5">
                    {isPast ? (
                      <CheckCircle2 className="w-4 h-4 text-theme-success shrink-0" />
                    ) : isCurrent ? (
                      <span className="w-4 h-4 rounded-full border-2 border-theme-accent border-t-transparent animate-spin block shrink-0" />
                    ) : (
                      <Clock className="w-4 h-4 text-theme-muted shrink-0" />
                    )}
                  </div>
                  <div className="flex-1">
                    <span className="font-semibold block">{stg.title}</span>
                    <span className="text-[11px] text-theme-muted leading-tight">{stg.desc}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
      )}

      {/* Analyzer Capabilities Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card space-y-2">
          <div className="flex items-center gap-2 text-theme-accent text-xs font-mono font-bold">
            <ShieldCheck className="w-4 h-4" />
            <span>01 / SSRF Perimeter</span>
          </div>
          <p className="text-xs text-theme-muted font-mono leading-relaxed">
            Strict resolution blocks loopback, private subnets (RFC 1918), and AWS/GCP metadata.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-theme-border bg-theme-card space-y-2">
          <div className="flex items-center gap-2 text-theme-accent text-xs font-mono font-bold">
            <Lock className="w-4 h-4" />
            <span>02 / TLS Handshake</span>
          </div>
          <p className="text-xs text-theme-muted font-mono leading-relaxed">
            Direct cryptographic inspection of X.509 cert chains, expiration timestamps, and SANs.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-theme-border bg-theme-card space-y-2">
          <div className="flex items-center gap-2 text-theme-accent text-xs font-mono font-bold">
            <Globe className="w-4 h-4" />
            <span>03 / Phishing & DOM</span>
          </div>
          <p className="text-xs text-theme-muted font-mono leading-relaxed">
            Detects homoglyphs, punycode spoofing, and form action credential harvesting targets.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function ScannerPage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-xs font-mono text-theme-muted">Loading scanner console...</div>}>
      <ScannerContent />
    </Suspense>
  );
}
