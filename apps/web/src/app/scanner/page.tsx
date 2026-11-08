'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import {
  ShieldCheck,
  Search,
  ArrowRight,
  Lock,
  Globe,
  Radio,
  Terminal,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Fingerprint,
} from 'lucide-react';
import { submitUrlScan } from '@/lib/api';

function ScannerContent() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const [url, setUrl] = useState('');
  const [deepScan, setDeepScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activeStage, setActiveStage] = useState(0);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const target = searchParams?.get('target');
    if (target) {
      setUrl(target);
    }
  }, [searchParams]);

  const stages = [
    { title: 'SSRF Perimeter Guard', desc: 'Pre-flight DNS check, RFC 1918 filter & cloud metadata drop' },
    { title: 'Socket-Level Handshake', desc: 'Pinned TCP connection and anti-TOCTOU rebinding validation' },
    { title: 'TLS & Cipher Audit', desc: 'Direct X.509 chain inspection and SC-081v3 validity schedule' },
    { title: 'Lexical & Brand Heuristics', desc: 'Punycode detection, typosquatting & DOM credential harvesting' },
    { title: 'Threat Intelligence Feeds', desc: 'URLhaus malware queries and historical IOC graph matching' },
    { title: 'Risk Engine Scoring', desc: 'Evidence aggregation, posture ceiling & MITRE ATT&CK assignment' },
  ];

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);
    setActiveStage(0);

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
    { label: 'Microsoft Phishing', url: 'https://login.microsoftonline-verification.xyz' },
    { label: 'PayPal Spoof', url: 'https://paypal-security-update.com/signin' },
    { label: 'Ledger Web3 Phish', url: 'https://ledger-hardware-wallet-verify.net' },
    { label: 'Clean Target', url: 'https://apple.com' },
  ];

  return (
    <div className="space-y-8 max-w-4xl mx-auto py-4">
      {/* Top Banner */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-xs font-mono text-neutral-700 dark:text-neutral-300">
          <span className="w-1.5 h-1.5 rounded-full bg-black dark:bg-white animate-pulse" />
          <span>[ SCANNER // ISOLATED FORENSIC SANDBOX ]</span>
        </div>
        <h1 className="text-3xl sm:text-4xl font-serif text-black dark:text-white">
          URL Threat Scanner
        </h1>
        <p className="text-xs sm:text-sm font-mono text-neutral-500 max-w-lg mx-auto">
          Passive multi-vector inspection. Evaluates target endpoints without client exposure.
        </p>
      </div>

      {/* Main Scanner Box */}
      <div className="card-floating p-6 sm:p-8 space-y-6">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-mono font-semibold uppercase text-neutral-700 dark:text-neutral-300">
                // 01. TARGET URL OR DOMAIN
              </label>
              <span className="text-[10px] font-mono text-neutral-400">
                HTTP & HTTPS supported
              </span>
            </div>

            {/* Normal Rounded Search Bar */}
            <div className="relative">
              <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400" />
              <input
                type="text"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter URL to inspect (e.g. https://chase-security-verify.net/login)..."
                className="w-full pl-11 pr-4 py-3 text-xs sm:text-sm font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white focus:bg-white dark:focus:bg-[#18181b] transition-all"
              />
            </div>
          </div>

          {/* Deep Scan Checkbox */}
          <div className="flex items-center justify-between pt-1">
            <label className="flex items-center gap-2 cursor-pointer text-xs font-mono text-neutral-600 dark:text-neutral-400">
              <input
                type="checkbox"
                checked={deepScan}
                onChange={(e) => setDeepScan(e.target.checked)}
                className="rounded border-neutral-300 dark:border-[#27272a] text-black dark:text-white focus:ring-0"
              />
              <span>Full Deep Inspection (5-hop redirect validation & DOM form harvest audit)</span>
            </label>
          </div>

          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            disabled={loading}
            className="w-full btn-industrial py-3 rounded-full text-xs font-semibold cursor-pointer disabled:opacity-50 mt-2"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <span className="w-3.5 h-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />
                Analyzing Target in Sandbox...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-white" />
                <span>Initiate Forensic Threat Scan</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </span>
            )}
          </button>
        </form>

        {error && (
          <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs font-mono text-red-700 dark:text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
            <span>{error}</span>
          </div>
        )}

        {/* 1-Click Test URLs */}
        <div className="pt-2 border-t border-neutral-100 dark:border-[#1f1f23]">
          <span className="text-[10px] font-mono uppercase text-neutral-400 block mb-2">
            Quick demo targets:
          </span>
          <div className="flex flex-wrap gap-2">
            {sampleUrls.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => setUrl(s.url)}
                className="text-xs font-mono px-3 py-1 rounded-full border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-neutral-700 dark:text-neutral-300 hover:text-black dark:hover:text-white hover:border-black dark:hover:border-white transition-colors cursor-pointer"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Execution Pipeline Stage Indicator */}
      <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 shadow-xs space-y-3 font-mono text-xs">
        <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-[#1f1f23]">
          <span className="font-bold uppercase tracking-wider text-black dark:text-white">
            // 02. SCANNER PIPELINE ARCHITECTURE
          </span>
          <span className="text-[10px] text-neutral-500">6 VERIFICATION STAGES</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
          {stages.map((stg, idx) => {
            const isCompleted = loading && activeStage > idx;
            const isCurrent = loading && activeStage === idx;
            return (
              <div
                key={stg.title}
                className={`p-3 rounded-lg border transition-all ${
                  isCurrent
                    ? 'border-black dark:border-white bg-neutral-100 dark:bg-[#18181b]'
                    : isCompleted
                    ? 'border-emerald-300 dark:border-emerald-900 bg-emerald-50/30 dark:bg-emerald-950/20 text-neutral-500'
                    : 'border-neutral-200 dark:border-[#1f1f23] bg-neutral-50/50 dark:bg-[#121214]/50'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[10px] text-neutral-400">0{idx + 1}</span>
                  <span
                    className={`text-[9px] font-pixel px-1.5 py-0.5 rounded ${
                      isCurrent
                        ? 'bg-black text-white dark:bg-white dark:text-black animate-pulse'
                        : isCompleted
                        ? 'bg-emerald-600 text-white'
                        : 'bg-neutral-200 dark:bg-[#1f1f23] text-neutral-500'
                    }`}
                  >
                    {isCurrent ? 'RUNNING' : isCompleted ? 'DONE' : 'STANDBY'}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-black dark:text-white truncate">
                  {stg.title}
                </h4>
                <p className="text-[10px] text-neutral-500 mt-1 leading-snug">
                  {stg.desc}
                </p>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export default function ScannerPage() {
  return (
    <Suspense fallback={<div className="p-8 text-center font-mono text-xs text-neutral-500">Loading scanner module...</div>}>
      <ScannerContent />
    </Suspense>
  );
}
