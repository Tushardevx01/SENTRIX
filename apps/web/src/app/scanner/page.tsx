'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldCheck, Search, AlertCircle, ArrowRight, Layers, Lock } from 'lucide-react';
import { submitUrlScan } from '@/lib/api';
import { LoadingState } from '@/components/ui/LoadingState';

export default function ScannerPage() {
  const router = useRouter();
  const [url, setUrl] = useState('');
  const [deepScan, setDeepScan] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await submitUrlScan(url.trim(), deepScan);
      if (res?.scanId) {
        router.push(`/reports/${res.scanId}`);
      }
    } catch (err: any) {
      setError(err.message || 'An error occurred during threat analysis.');
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="py-16">
        <LoadingState
          message="Executing SENTRIX Threat Pipeline..."
          subMessage="Performing SSRF safety check, TLS certificate validation, DOM parsing, and threat database queries"
        />
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto space-y-8 py-6">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
          URL Threat Inspection Engine
        </h1>
        <p className="mt-1 text-sm text-slate-400 font-mono">
          Enter any URL, IP address, or hostname to trigger multi-vector security analysis.
        </p>
      </div>

      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-6 sm:p-8 shadow-xl">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-mono uppercase text-slate-400 mb-2">
              Target Destination (URL / Domain)
            </label>
            <div className="flex items-center gap-2 p-3 bg-slate-950 border border-slate-800 rounded-lg focus-within:border-electric-400 transition-all">
              <Search className="w-5 h-5 text-slate-500 shrink-0" />
              <input
                type="text"
                placeholder="https://example-verify-login.xyz/auth"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="w-full bg-transparent text-white placeholder-slate-600 text-sm font-mono focus:outline-none"
                required
              />
            </div>
            <p className="mt-1.5 text-[11px] text-slate-500 font-mono">
              Accepts full URLs (https://...), domains (domain.com), or subdomains.
            </p>
          </div>

          <div className="flex items-center gap-3 p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg">
            <input
              type="checkbox"
              id="deepScan"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
              className="w-4 h-4 rounded border-slate-700 bg-slate-900 text-electric-500 focus:ring-electric-400"
            />
            <label htmlFor="deepScan" className="text-xs font-mono text-slate-300 cursor-pointer flex-1">
              <span className="font-semibold text-white block">Deep Heuristic Inspection</span>
              Extended DOM form parsing, multi-hop redirect tracing, and active blacklist queries.
            </label>
          </div>

          {error && (
            <div className="p-4 bg-red-950/40 border border-red-800/70 rounded-lg flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
              <div className="text-xs font-mono text-red-300 leading-relaxed">
                <span className="font-bold block text-red-200">Scan Rejection / Error:</span>
                {error}
              </div>
            </div>
          )}

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-2 px-6 py-3.5 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-sm transition-all shadow-glow hover:shadow-cyan-400/50"
          >
            Launch Threat Inspection
            <ArrowRight className="w-4 h-4" />
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs font-mono text-slate-400">
        <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/60">
          <span className="text-electric-400 font-bold block mb-1">01 / Heuristic Analysis</span>
          Extracts brand homoglyphs, typosquatting vectors, and lexical entropy.
        </div>
        <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/60">
          <span className="text-electric-400 font-bold block mb-1">02 / TLS Verification</span>
          Verifies certificate chains, expiration dates, and cipher configurations.
        </div>
        <div className="p-4 rounded-lg bg-slate-900/40 border border-slate-800/60">
          <span className="text-electric-400 font-bold block mb-1">03 / SSRF Perimeter Safe</span>
          Strict internal IP and cloud metadata protection safeguards infrastructure.
        </div>
      </div>
    </div>
  );
}
