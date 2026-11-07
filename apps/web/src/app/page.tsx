'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import {
  Shield,
  Search,
  Lock,
  Globe,
  Radio,
  Users,
  CheckCircle2,
  ArrowRight,
  AlertTriangle,
  Zap,
} from 'lucide-react';
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
      setError(err.message || 'Scan initialization failed. Please check the URL.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-20 py-8">
      {/* Hero Section */}
      <section className="text-center space-y-6 max-w-4xl mx-auto pt-6">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-electric-500/10 border border-electric-500/30 text-electric-400 text-xs font-mono font-medium">
          <Zap className="w-3.5 h-3.5" />
          Zero-Trust Link Intelligence Engine
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight">
          Don&apos;t trust the link.{' '}
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-electric-400 via-cyan-300 to-cyber-violet">
            Verify the threat.
          </span>
        </h1>

        <p className="text-lg sm:text-xl text-slate-300 max-w-2xl mx-auto leading-relaxed">
          SENTRIX inspects URLs, detects credential harvesting, audits SSL/TLS configurations, and aggregates global threat feeds in under 2 seconds.
        </p>

        {/* Quick Scan Input */}
        <div className="max-w-2xl mx-auto mt-8">
          <form
            onSubmit={handleQuickScan}
            className="flex flex-col sm:flex-row items-center gap-2 p-2 rounded-xl bg-slate-900/90 border border-slate-700 shadow-2xl focus-within:border-electric-400 transition-all"
          >
            <div className="flex items-center gap-2 px-3 flex-1 w-full">
              <Search className="w-5 h-5 text-slate-400 shrink-0" />
              <input
                type="text"
                placeholder="Enter URL or domain (e.g. login-secure-verification.xyz)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-transparent text-white placeholder-slate-500 text-sm font-mono focus:outline-none py-2"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-sm transition-all shadow-glow hover:shadow-cyan-400/50 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 rounded-full border-2 border-slate-950 border-t-transparent animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  Inspect Threat
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          {error && (
            <div className="mt-3 flex items-center gap-2 text-xs font-mono text-red-400 bg-red-950/40 border border-red-800 rounded-lg p-2.5 text-left">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>
      </section>

      {/* Feature Capabilities Grid */}
      <section className="space-y-8">
        <div className="text-center space-y-2">
          <h2 className="text-2xl sm:text-3xl font-bold text-white">Multi-Vector Security Architecture</h2>
          <p className="text-sm text-slate-400 max-w-xl mx-auto font-mono">
            Rigorous detection layers analyzing every link before your users click.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="p-6 rounded-xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all">
            <div className="w-10 h-10 rounded-lg bg-electric-500/10 border border-electric-500/20 flex items-center justify-center mb-4">
              <Shield className="w-5 h-5 text-electric-400" />
            </div>
            <h3 className="text-base font-semibold text-white mb-2">Phishing & Impersonation</h3>
            <p className="text-xs text-slate-400 font-mono leading-relaxed">
              Discovers typosquatting, homoglyph punycode attacks, deceptive subdomains, and credential submission forms targeting major brands.
            </p>
          </div>

          <div className="p-6 rounded-xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all">
            <div className="w-10 h-10 rounded-lg bg-cyber-violet/10 border border-cyber-violet/20 flex items-center justify-center mb-4">
              <Lock className="w-5 h-5 text-cyber-violet" />
            </div>
            <h3 className="text-base font-semibold text-white mb-2">TLS/SSL Integrity</h3>
            <p className="text-xs text-slate-400 font-mono leading-relaxed">
              Validates issuer certificates, expiration timestamps, self-signed root authorities, and cryptographic cipher standards.
            </p>
          </div>

          <div className="p-6 rounded-xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-all">
            <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center mb-4">
              <Radio className="w-5 h-5 text-emerald-400" />
            </div>
            <h3 className="text-base font-semibold text-white mb-2">Global Threat Intel</h3>
            <p className="text-xs text-slate-400 font-mono leading-relaxed">
              Cross-references live blacklist registries, URLhaus malware repositories, and crowdsourced community consensus.
            </p>
          </div>
        </div>
      </section>

      {/* Quick Launch Cards */}
      <section className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4">
        <Link
          href="/dashboard"
          className="group p-5 bg-gradient-to-r from-slate-900 to-navy-900 border border-slate-800 rounded-xl hover:border-electric-500/40 transition-all flex items-center justify-between"
        >
          <div>
            <h4 className="text-sm font-bold text-white group-hover:text-electric-400 transition-colors">
              Security Dashboard
            </h4>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Live threat telemetry and scan metrics.
            </p>
          </div>
          <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-electric-400 group-hover:translate-x-1 transition-all" />
        </Link>

        <Link
          href="/community"
          className="group p-5 bg-gradient-to-r from-slate-900 to-navy-900 border border-slate-800 rounded-xl hover:border-electric-500/40 transition-all flex items-center justify-between"
        >
          <div>
            <h4 className="text-sm font-bold text-white group-hover:text-electric-400 transition-colors">
              Community Threat Feed
            </h4>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Report suspicious links and vote on threat alerts.
            </p>
          </div>
          <ArrowRight className="w-5 h-5 text-slate-500 group-hover:text-electric-400 group-hover:translate-x-1 transition-all" />
        </Link>
      </section>
    </div>
  );
}
