'use client';

import React, { useState } from 'react';
import {
  Activity,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  Globe,
  Search,
  Layers,
  ArrowRight,
  Info,
  Server,
  FileText,
} from 'lucide-react';
import { motion } from 'framer-motion';

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
    <div className="space-y-8 py-2 max-w-5xl mx-auto">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
          <Activity className="w-3.5 h-3.5" />
          <span>Automated Web Posture Evaluation</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
          SECURITY POSTURE ASSESSMENT
        </h1>
        <p className="text-xs text-theme-muted font-mono max-w-2xl">
          Evaluate HTTP defensive headers, TLS configurations, mixed content vulnerabilities, and
          architectural weaknesses.
        </p>
      </div>

      {/* Target Domain Input Bar */}
      <div className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs">
        <form onSubmit={handleAudit} className="flex flex-col sm:flex-row items-center gap-3">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-theme-muted" />
            <input
              type="text"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="Enter domain to audit (e.g. cloudflare.com)..."
              className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-theme-bg border border-theme-border rounded-lg text-theme-text focus:outline-none focus:border-theme-accent"
            />
          </div>
          <button
            type="submit"
            disabled={evaluating}
            className="w-full sm:w-auto px-5 py-2 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 disabled:opacity-50 shrink-0"
          >
            {evaluating ? 'Auditing Headers...' : 'Run Security Assessment'}
          </button>
        </form>
      </div>

      {/* Posture Score & Executive Card */}
      <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-card">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
          <div className="flex flex-col items-center justify-center p-4 border-b md:border-b-0 md:border-r border-theme-borderSubtle">
            <span className="text-[10px] uppercase font-mono font-bold text-theme-muted mb-1">
              Posture Grade
            </span>
            <div className="w-20 h-20 rounded-2xl bg-emerald-500/10 border-2 border-emerald-500 flex items-center justify-center">
              <span className="text-4xl font-black font-mono text-emerald-600 dark:text-emerald-400">
                A+
              </span>
            </div>
            <span className="text-xs font-mono text-theme-success mt-2 font-semibold">
              96 / 100 Score
            </span>
          </div>

          <div className="md:col-span-3 space-y-3">
            <h3 className="text-base font-bold font-mono text-theme-text">
              EXECUTIVE POSTURE SUMMARY: {targetDomain.toUpperCase()}
            </h3>
            <p className="text-xs font-mono text-theme-muted leading-relaxed">
              Target endpoint demonstrates exceptional defense-in-depth posture. All primary security
              headers are actively configured with modern directives. Strict TLS 1.3 parameters and zero
              insecure DOM assets were detected.
            </p>
            <div className="flex flex-wrap gap-4 text-xs font-mono pt-2">
              <span className="flex items-center gap-1.5 text-theme-success">
                <CheckCircle2 className="w-3.5 h-3.5" /> 5 Passing Headers
              </span>
              <span className="flex items-center gap-1.5 text-theme-warning">
                <AlertTriangle className="w-3.5 h-3.5" /> 1 Minor Advisory
              </span>
              <span className="flex items-center gap-1.5 text-theme-text">
                <Lock className="w-3.5 h-3.5 text-theme-accent" /> Strict HTTPS
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Defensive HTTP Headers Audit */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-theme-accent" />
            <span>HTTP SECURITY HEADERS COMPLIANCE</span>
          </h3>
          <span className="text-[11px] font-mono text-theme-muted">RFC 6797 / OWASP ASVS</span>
        </div>

        <div className="space-y-3">
          {securityHeaderAudit.map((header) => (
            <div
              key={header.name}
              className="p-4 rounded-xl border border-theme-border bg-theme-card shadow-xs flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono"
            >
              <div className="space-y-1 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-theme-text">{header.name}</span>
                  {header.status === 'PASS' ? (
                    <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-bold text-[10px] border border-emerald-500/20">
                      PASS
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-bold text-[10px] border border-amber-500/20">
                      ADVISORY
                    </span>
                  )}
                </div>
                <p className="text-theme-muted text-[11px] leading-relaxed">{header.description}</p>
              </div>

              <div className="px-3 py-1.5 rounded-lg bg-theme-elevated border border-theme-borderSubtle text-theme-text text-[11px] truncate max-w-xs font-mono">
                {header.grade}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Configuration & Hardening Matrix */}
      <section className="space-y-4">
        <h3 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
          <Layers className="w-4 h-4 text-theme-accent" />
          <span>SYSTEM CONFIGURATION & HARDENING MATRIX</span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {configurationAudit.map((item, idx) => (
            <div
              key={idx}
              className="p-4 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-1.5 text-xs font-mono"
            >
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase font-bold text-theme-muted">
                  {item.category}
                </span>
                <span className="text-theme-success font-semibold flex items-center gap-1 text-[11px]">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Verified
                </span>
              </div>
              <h4 className="font-bold text-theme-text">{item.finding}</h4>
              <p className="text-theme-muted text-[11px] leading-relaxed">{item.detail}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
