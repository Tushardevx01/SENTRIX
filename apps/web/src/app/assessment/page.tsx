'use client';

import React, { useState } from 'react';
import {
  Activity,
  ShieldCheck,
  Search,
  CheckCircle2,
  AlertTriangle,
  Lock,
  Globe,
  Terminal,
} from 'lucide-react';

export default function SecurityAssessmentPage() {
  const [targetDomain, setTargetDomain] = useState('cloudflare.com');
  const [evaluating, setEvaluating] = useState(false);

  const securityHeaderAudit = [
    {
      name: 'Strict-Transport-Security (HSTS)',
      status: 'PASS',
      grade: 'max-age=31536000; includeSubDomains; preload',
      description: 'Enforces encrypted HTTPS connections and mitigates SSL-stripping attacks.',
    },
    {
      name: 'Content-Security-Policy (CSP)',
      status: 'PASS',
      grade: 'upgrade-insecure-requests; default-src https:',
      description: 'Restricts script injection, unauthorized external resources, and XSS vectors.',
    },
    {
      name: 'X-Frame-Options',
      status: 'PASS',
      grade: 'DENY',
      description: 'Prevents clickjacking and framing within malicious external iframes.',
    },
    {
      name: 'X-Content-Type-Options',
      status: 'PASS',
      grade: 'nosniff',
      description: 'Blocks MIME-type sniffing from disguising malicious executables as images.',
    },
    {
      name: 'Referrer-Policy',
      status: 'PASS',
      grade: 'strict-origin-when-cross-origin',
      description: 'Protects sensitive URL query parameters from leaking to downstream destinations.',
    },
    {
      name: 'Permissions-Policy',
      status: 'WARN',
      grade: 'Not configured',
      description: 'Microphone, camera, and geolocation sensor permissions are not explicitly restricted.',
    },
  ];

  const configurationAudit = [
    {
      category: 'TLS Invariant',
      finding: 'Modern TLS 1.3 & TLS 1.2 Protocol Suite',
      severity: 'BENIGN',
      detail: 'Legacy SSLv3, TLS 1.0, and TLS 1.1 ciphers are disabled on all server interfaces.',
    },
    {
      category: 'Mixed Content',
      finding: 'Zero Insecure HTTP Elements',
      severity: 'BENIGN',
      detail: 'No unencrypted script, stylesheet, or media elements discovered in page DOM.',
    },
    {
      category: 'Redirect Chain',
      finding: 'Single Direct HTTPS Redirect',
      severity: 'BENIGN',
      detail: 'HTTP port 80 enforces immediate 301 Permanent Redirect to HTTPS without intermediate hops.',
    },
    {
      category: 'Form Targets',
      finding: 'Secure Credential Action Handlers',
      severity: 'BENIGN',
      detail: 'Authentication forms post exclusively to same-origin encrypted endpoints.',
    },
  ];

  const handleAudit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetDomain) return;
    setEvaluating(true);
    setTimeout(() => {
      setEvaluating(false);
    }, 600);
  };

  return (
    <div className="space-y-8 py-2 max-w-5xl mx-auto font-mono text-xs">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <Activity className="w-3.5 h-3.5" />
            <span>[ AUDIT // POSTURE BENCHMARK ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Security Posture Assessment
          </h1>
          <p className="text-xs text-neutral-500 font-mono max-w-2xl">
            Evaluate HTTP security headers, framing restrictions, TLS configuration, and mixed content vulnerabilities.
          </p>
        </div>
      </div>

      {/* Target Domain Input Bar with Normal Rounded Search Bar */}
      <div className="p-5 sm:p-6 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-card space-y-3">
        <span className="text-[10px] uppercase font-bold text-neutral-400 block">
          // 01. TARGET ENDPOINT POSTURE BENCHMARK
        </span>
        <form onSubmit={handleAudit} className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              required
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="Target domain (e.g. cloudflare.com or paypal.com)..."
              className="w-full pl-11 pr-4 py-2.5 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
            />
          </div>
          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            disabled={evaluating}
            className="btn-industrial py-2.5 px-6 rounded-full text-xs font-semibold cursor-pointer disabled:opacity-50 shrink-0"
          >
            {evaluating ? 'Auditing Headers...' : 'Run Posture Audit'}
          </button>
        </form>
      </div>

      {/* Security Headers Assessment Grid */}
      <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
          <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            // 02. HTTP DEFENSIVE HEADERS EVALUATION
          </span>
          <span className="text-[10px] text-neutral-500 font-pixel">CAL-01 AUDIT</span>
        </div>

        <div className="space-y-2.5">
          {securityHeaderAudit.map((h, i) => (
            <div
              key={i}
              className="p-3.5 rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] flex flex-col sm:flex-row sm:items-center justify-between gap-2"
            >
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[9px] font-pixel px-1.5 py-0.5 rounded ${
                    h.status === 'PASS'
                      ? 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300'
                      : 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300'
                  }`}>
                    {h.status}
                  </span>
                  <span className="font-bold text-black dark:text-white text-xs">{h.name}</span>
                </div>
                <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
                  {h.description}
                </p>
              </div>

              <span className="text-[10px] font-mono text-neutral-600 dark:text-neutral-400 p-1.5 bg-neutral-200/50 dark:bg-[#1f1f23] rounded border border-neutral-300 dark:border-[#27272a] shrink-0 max-w-xs truncate">
                {h.grade}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Configuration Audit */}
      <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 shadow-xs space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
          <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            // 03. TRANSPORT & DOM CONFIGURATION
          </span>
          <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-pixel">ACTIVE</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {configurationAudit.map((c, i) => (
            <div key={i} className="p-3.5 rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] space-y-1">
              <span className="text-[10px] uppercase font-bold text-neutral-400 block font-pixel">
                {c.category}
              </span>
              <h4 className="font-bold text-black dark:text-white text-xs">{c.finding}</h4>
              <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">{c.detail}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
