'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Shield,
  Search,
  Lock,
  Radio,
  ArrowRight,
  AlertTriangle,
  Zap,
  CheckCircle2,
  Activity,
  Layers,
  Server,
  Terminal,
  Globe,
  ExternalLink,
  ChevronRight,
  Users,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { submitUrlScan } from '@/lib/api';

export default function LandingPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await submitUrlScan(url.trim());
      if (res?.scanId) {
        router.push(`/reports/${res.scanId}`);
      }
    } catch (err: any) {
      setError(err.message || 'Scan initialization failed. Please check the target URL.');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = [
    'https://login-paypal-verify.xyz/account',
    'https://appleid-security-recovery.com',
    'https://accounts.google.com',
  ];

  const pillars = [
    {
      icon: Shield,
      title: 'SSRF Perimeter Defense',
      description:
        'Pre-flight DNS validation rejects loopback, RFC 1918 private subnets, and cloud instance metadata (169.254.169.254) before initiating TCP sockets.',
      tag: 'Network Layer',
    },
    {
      icon: Lock,
      title: 'Cryptographic & TLS Audit',
      description:
        'Performs raw socket TLS handshakes, inspecting X.509 chains, expiration timestamps, SHA-256 fingerprints, and SAN hostname match validity.',
      tag: 'Transport Layer',
    },
    {
      icon: Terminal,
      title: 'Heuristic Phishing Detection',
      description:
        'Detects homoglyphs, punycode (xn--), suspicious subdomain stacking, credential form action targets, and deceptive brand token spoofing.',
      tag: 'Application Layer',
    },
    {
      icon: Activity,
      title: 'Explainable Scoring & MITRE ATT&CK',
      description:
        'Generates deterministic 0–100 threat scores mapped to BENIGN, SUSPICIOUS, MALICIOUS, or INCONCLUSIVE with MITRE tactic citations.',
      tag: 'Analytics Engine',
    },
  ];

  const workflowSteps = [
    {
      step: '01',
      title: 'Submission & Normalization',
      detail: 'Parses URLs, standardizes schemas, extracts domains, and generates tracking telemetry in MongoDB.',
    },
    {
      step: '02',
      title: 'Perimeter Verification & IP Pinning',
      detail: 'Validates target IP against SSRF blacklists and pins TCP socket connections to eliminate DNS rebinding.',
    },
    {
      step: '03',
      title: 'Multi-Vector Sandbox Inspection',
      detail: 'Executes parallel analyzers: lexical heuristics, TLS certificates, DOM form exfiltration, and threat feeds.',
    },
    {
      step: '04',
      title: 'Forensic Report & Consensus',
      detail: 'Compiles radial risk gauges, evidence trees, redirect chains, and shares verified IOCs with the community.',
    },
  ];

  return (
    <div className="space-y-24 py-10 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
      {/* Hero Section */}
      <section className="text-center space-y-6 pt-6 sm:pt-12 max-w-4xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-theme-accent/10 border border-theme-accent/25 text-theme-accent text-xs font-mono font-medium"
        >
          <Zap className="w-3.5 h-3.5" />
          <span>SENTRIX v1.1 — Zero-Trust Link Intelligence Engine</span>
        </motion.div>

        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="text-4xl sm:text-6xl font-black tracking-tight text-theme-text leading-tight"
        >
          Don&apos;t trust the link.{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-[#5278E8] via-[#7457D5] to-[#16B8B0]">
            Verify the threat.
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.15 }}
          className="text-base sm:text-lg text-theme-muted max-w-2xl mx-auto leading-relaxed"
        >
          Automated multi-layered link verification evaluating untrusted URLs, domain impersonation,
          and TLS vulnerabilities in a hardened sandbox before users interact with them.
        </motion.p>

        {/* Primary URL Inspection Input */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.2 }}
          className="max-w-2xl mx-auto mt-8"
        >
          <form
            onSubmit={handleQuickScan}
            className="flex flex-col sm:flex-row items-center gap-2 p-2 rounded-xl bg-theme-card border border-theme-border shadow-elevated focus-within:border-theme-accent transition-all"
          >
            <div className="flex items-center gap-3 px-3 flex-1 w-full">
              <Search className="w-5 h-5 text-theme-muted shrink-0" />
              <input
                type="text"
                placeholder="Enter URL or domain (e.g. https://login-paypal-security.xyz)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-transparent text-theme-text placeholder:text-theme-muted text-sm font-mono focus:outline-none py-2"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-sm transition-all hover:opacity-90 disabled:opacity-50 shadow-sm"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 rounded-full border-2 border-white dark:border-slate-950 border-t-transparent animate-spin" />
                  <span>Inspecting...</span>
                </>
              ) : (
                <>
                  <span>Inspect Threat</span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {/* Sample quick target buttons */}
          <div className="flex flex-wrap items-center justify-center gap-2 mt-3 text-[11px] font-mono text-theme-muted">
            <span>Quick test:</span>
            {sampleTargets.map((target) => (
              <button
                key={target}
                type="button"
                onClick={() => setUrl(target)}
                className="px-2 py-0.5 rounded border border-theme-borderSubtle bg-theme-elevated hover:border-theme-accent hover:text-theme-text transition-colors"
              >
                {target.replace('https://', '')}
              </button>
            ))}
          </div>

          {error && (
            <div className="mt-4 flex items-center gap-2 text-xs font-mono text-theme-danger bg-theme-danger/10 border border-theme-danger/20 rounded-lg p-3 text-left">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </motion.div>

        {/* Telemetry Highlights */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto pt-6 text-center">
          <div className="p-3 rounded-lg border border-theme-border bg-theme-card">
            <span className="block text-xl font-bold font-mono text-theme-text">&lt; 1.5s</span>
            <span className="text-[11px] font-mono text-theme-muted">Median Audit Time</span>
          </div>
          <div className="p-3 rounded-lg border border-theme-border bg-theme-card">
            <span className="block text-xl font-bold font-mono text-theme-accent">5-Vector</span>
            <span className="text-[11px] font-mono text-theme-muted">Sandbox Pipeline</span>
          </div>
          <div className="p-3 rounded-lg border border-theme-border bg-theme-card">
            <span className="block text-xl font-bold font-mono text-theme-success">100% Zero-Trust</span>
            <span className="text-[11px] font-mono text-theme-muted">Strict Inconclusive State</span>
          </div>
          <div className="p-3 rounded-lg border border-theme-border bg-theme-card">
            <span className="block text-xl font-bold font-mono text-theme-text">TOCTOU Pinning</span>
            <span className="text-[11px] font-mono text-theme-muted">Anti-DNS Rebinding</span>
          </div>
        </div>
      </section>

      {/* Four Security Pillars */}
      <section className="space-y-10">
        <div className="text-center space-y-2 max-w-xl mx-auto">
          <span className="text-xs font-mono uppercase tracking-wider text-theme-accent font-semibold">
            Security Architecture
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-theme-text tracking-tight">
            Comprehensive Four-Pillar Inspection
          </h2>
          <p className="text-xs font-mono text-theme-muted">
            Engineered from ground up with defensive depth and least-privilege sandbox isolation.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {pillars.map((pillar, idx) => {
            const Icon = pillar.icon;
            return (
              <div
                key={idx}
                className="p-6 rounded-xl border border-theme-border bg-theme-card hover:border-theme-accent/40 transition-all space-y-3 group"
              >
                <div className="flex items-center justify-between">
                  <div className="w-10 h-10 rounded-lg bg-theme-elevated border border-theme-border flex items-center justify-center text-theme-accent group-hover:bg-theme-accent/10 transition-colors">
                    <Icon className="w-5 h-5" />
                  </div>
                  <span className="text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded bg-theme-elevated text-theme-muted border border-theme-border">
                    {pillar.tag}
                  </span>
                </div>
                <h3 className="text-base font-bold text-theme-text">{pillar.title}</h3>
                <p className="text-xs text-theme-muted font-mono leading-relaxed">{pillar.description}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* How SENTRIX Works (Workflow Sequence) */}
      <section className="space-y-10">
        <div className="text-center space-y-2 max-w-xl mx-auto">
          <span className="text-xs font-mono uppercase tracking-wider text-theme-accent font-semibold">
            Execution Lifecycle
          </span>
          <h2 className="text-2xl sm:text-3xl font-extrabold text-theme-text tracking-tight">
            How SENTRIX Audits a Link
          </h2>
          <p className="text-xs font-mono text-theme-muted">
            From pre-flight perimeter checks to explainable MITRE ATT&CK risk verdicts.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {workflowSteps.map((wf) => (
            <div
              key={wf.step}
              className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-2 relative"
            >
              <span className="text-2xl font-black font-mono text-theme-accent/40">{wf.step}</span>
              <h4 className="text-sm font-bold text-theme-text">{wf.title}</h4>
              <p className="text-xs font-mono text-theme-muted leading-relaxed">{wf.detail}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Fast Navigation Suite */}
      <section className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-bold font-mono text-theme-text">Platform Modules</h3>
          <Link
            href="/dashboard"
            className="text-xs font-mono text-theme-accent hover:underline flex items-center gap-1"
          >
            Open Command Center <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <Link
            href="/scanner"
            className="p-4 rounded-xl border border-theme-border bg-theme-card hover:bg-theme-elevated transition-all flex flex-col justify-between"
          >
            <div className="space-y-1">
              <div className="w-8 h-8 rounded-lg bg-theme-accent/10 flex items-center justify-center text-theme-accent mb-2">
                <Shield className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-semibold text-theme-text">URL Threat Scanner</h4>
              <p className="text-xs text-theme-muted font-mono">Dedicated deep sandbox analysis console.</p>
            </div>
            <div className="pt-3 text-[11px] font-mono text-theme-accent flex items-center gap-1">
              Launch Scanner <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </Link>

          <Link
            href="/intelligence"
            className="p-4 rounded-xl border border-theme-border bg-theme-card hover:bg-theme-elevated transition-all flex flex-col justify-between"
          >
            <div className="space-y-1">
              <div className="w-8 h-8 rounded-lg bg-theme-accent/10 flex items-center justify-center text-theme-accent mb-2">
                <Radio className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-semibold text-theme-text">Threat Intelligence</h4>
              <p className="text-xs text-theme-muted font-mono">Global index of active phishing & malware IOCs.</p>
            </div>
            <div className="pt-3 text-[11px] font-mono text-theme-accent flex items-center gap-1">
              Search Feeds <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </Link>

          <Link
            href="/certificates"
            className="p-4 rounded-xl border border-theme-border bg-theme-card hover:bg-theme-elevated transition-all flex flex-col justify-between"
          >
            <div className="space-y-1">
              <div className="w-8 h-8 rounded-lg bg-theme-accent/10 flex items-center justify-center text-theme-accent mb-2">
                <Lock className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-semibold text-theme-text">Certificate Intel</h4>
              <p className="text-xs text-theme-muted font-mono">X.509 cryptographic chains and SAN validation.</p>
            </div>
            <div className="pt-3 text-[11px] font-mono text-theme-accent flex items-center gap-1">
              Audit Certs <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </Link>

          <Link
            href="/community"
            className="p-4 rounded-xl border border-theme-border bg-theme-card hover:bg-theme-elevated transition-all flex flex-col justify-between"
          >
            <div className="space-y-1">
              <div className="w-8 h-8 rounded-lg bg-theme-accent/10 flex items-center justify-center text-theme-accent mb-2">
                <Users className="w-4 h-4" />
              </div>
              <h4 className="text-sm font-semibold text-theme-text">Community Feed</h4>
              <p className="text-xs text-theme-muted font-mono">Crowdsourced consensus and peer-reviewed voting.</p>
            </div>
            <div className="pt-3 text-[11px] font-mono text-theme-accent flex items-center gap-1">
              View Feed <ChevronRight className="w-3.5 h-3.5" />
            </div>
          </Link>
        </div>
      </section>

      {/* Professional Footer */}
      <footer className="pt-12 border-t border-theme-border text-xs font-mono text-theme-muted">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="w-5 h-5 rounded bg-gradient-to-tr from-[#5278E8] to-[#16B8B0] flex items-center justify-center text-white text-[10px] font-bold">
              S
            </div>
            <span className="font-semibold text-theme-text">SENTRIX Trust Intelligence Platform</span>
          </div>
          <div className="flex items-center gap-6">
            <Link href="/dashboard" className="hover:text-theme-text transition-colors">
              Command Center
            </Link>
            <Link href="/scanner" className="hover:text-theme-text transition-colors">
              Scanner
            </Link>
            <Link href="/history" className="hover:text-theme-text transition-colors">
              History
            </Link>
            <Link href="/community" className="hover:text-theme-text transition-colors">
              Community
            </Link>
          </div>
          <p>© 2026 SENTRIX Security Inc. Zero-Trust Architecture.</p>
        </div>
      </footer>
    </div>
  );
}
