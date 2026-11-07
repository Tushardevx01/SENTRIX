'use client';

import React, { useEffect, useState, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Radio,
  Search,
  ShieldAlert,
  ArrowUpRight,
  Globe,
  AlertTriangle,
  Filter,
  Layers,
  Database,
  ExternalLink,
  Shield,
  Activity,
  CheckCircle2,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { fetchThreats } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IScan, type IThreatReport } from '@sentrix/shared';

function ThreatIntelligenceContent() {
  const searchParams = useSearchParams();
  const [query, setQuery] = useState('');
  const [threats, setThreats] = useState<IScan[]>([]);
  const [communityThreats, setCommunityThreats] = useState<IThreatReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = (searchTerm?: string) => {
    setLoading(true);
    fetchThreats(searchTerm)
      .then((data) => {
        setThreats(data.threats || []);
        setCommunityThreats(data.communityThreats || []);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to fetch threat intelligence');
        setLoading(false);
      });
  };

  useEffect(() => {
    const q = searchParams?.get('q') || '';
    if (q) {
      setQuery(q);
      loadData(q);
    } else {
      loadData();
    }
  }, [searchParams]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    loadData(query.trim());
  };

  return (
    <div className="space-y-8 py-2">
      {/* Page Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
          <Radio className="w-3.5 h-3.5" />
          <span>Global IOC Telemetry Feed</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
          THREAT INTELLIGENCE REPOSITORY
        </h1>
        <p className="text-xs text-theme-muted font-mono max-w-2xl">
          Verified database of high-threat domains, deceptive hostnames, credential harvesting portals,
          and community peer alerts.
        </p>
      </div>

      {/* Search Input Bar */}
      <form onSubmit={handleSearch} className="max-w-2xl">
        <div className="flex items-center gap-2 p-2 bg-theme-card border border-theme-border rounded-xl shadow-xs focus-within:border-theme-accent transition-all">
          <Search className="w-4 h-4 text-theme-muted ml-2 shrink-0" />
          <input
            type="text"
            placeholder="Search domain, hostname, or threat keyword (e.g. paypal, .xyz, auth)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-theme-text text-xs font-mono placeholder:text-theme-muted focus:outline-none py-1.5"
          />
          {query && (
            <button
              type="button"
              onClick={() => {
                setQuery('');
                loadData('');
              }}
              className="text-xs font-mono text-theme-muted hover:text-theme-text px-2"
            >
              Clear
            </button>
          )}
          <button
            type="submit"
            className="px-4 py-2 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 shrink-0"
          >
            Filter Feed
          </button>
        </div>
      </form>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            Active Threat Indicators
          </span>
          <span className="text-2xl font-black font-mono text-theme-text block">
            {threats.length}
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Verified malicious / suspicious</span>
        </div>
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            Community Alerts
          </span>
          <span className="text-2xl font-black font-mono text-theme-accentSec block">
            {communityThreats.length}
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Confirmed peer submissions</span>
        </div>
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted block mb-1">
            External Feed Ingestion
          </span>
          <span className="text-2xl font-black font-mono text-theme-success block flex items-center gap-1.5">
            <CheckCircle2 className="w-5 h-5 text-theme-success" /> URLhaus Sync
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Continuous feed ingestion</span>
        </div>
      </div>

      {loading ? (
        <LoadingState message="Querying Threat Intelligence Registry..." />
      ) : error ? (
        <ErrorState message={error} onRetry={() => loadData(query)} />
      ) : (
        <div className="space-y-8">
          {/* Flagged Scan Threats Grid */}
          <div className="space-y-4">
            <h2 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-theme-danger" />
              <span>VERIFIED MALICIOUS & SUSPICIOUS ENDPOINTS ({threats.length})</span>
            </h2>

            {threats.length === 0 ? (
              <div className="p-8 rounded-xl border border-dashed border-theme-border text-center text-xs font-mono text-theme-muted">
                No active threat records match your search criteria. Try a broader search term.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {threats.map((threat) => (
                  <div
                    key={threat._id}
                    className="p-5 rounded-xl bg-theme-card border border-theme-border hover:border-theme-accent/40 transition-all flex flex-col justify-between shadow-xs space-y-3"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <RiskBadge verdict={threat.verdict} size="sm" />
                        <span className="text-xs font-mono font-bold text-theme-text px-2 py-0.5 rounded bg-theme-elevated border border-theme-borderSubtle">
                          Risk: {threat.riskScore}
                        </span>
                      </div>
                      <h3 className="font-mono text-sm font-bold text-theme-text break-all mb-1">
                        {threat.submittedUrl}
                      </h3>
                      <p className="text-xs font-mono text-theme-muted flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5 text-theme-accent" />
                        Domain: <strong className="text-theme-text">{threat.normalizedDomain}</strong>
                      </p>
                    </div>

                    <div className="pt-3 border-t border-theme-borderSubtle flex items-center justify-between text-xs font-mono">
                      <span className="text-theme-muted">
                        {new Date(threat.createdAt).toLocaleDateString()}
                      </span>
                      <Link
                        href={`/reports/${threat._id}`}
                        className="text-theme-accent hover:underline inline-flex items-center gap-1 font-semibold"
                      >
                        Inspect Report <ArrowUpRight className="w-3.5 h-3.5" />
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Confirmed Community Threats */}
          {communityThreats.length > 0 && (
            <div className="space-y-4 pt-4 border-t border-theme-border">
              <h2 className="text-sm font-bold font-mono text-theme-text flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-theme-warning" />
                <span>CONFIRMED PEER COMMUNITY THREATS ({communityThreats.length})</span>
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {communityThreats.map((rep) => (
                  <div
                    key={rep._id}
                    className="p-5 rounded-xl bg-theme-card border border-theme-border text-xs font-mono space-y-2 shadow-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-600 dark:text-amber-400 font-bold uppercase border border-amber-500/20 text-[10px]">
                        {rep.category}
                      </span>
                      <span className="text-theme-muted">Verifications: {rep.reportCount}</span>
                    </div>
                    <p className="text-theme-text font-bold break-all">{rep.submittedUrl}</p>
                    <p className="text-theme-muted text-[11px] leading-relaxed">{rep.description}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function ThreatIntelligencePage() {
  return (
    <Suspense fallback={<div className="p-12 text-center text-xs font-mono text-theme-muted">Loading threat intelligence...</div>}>
      <ThreatIntelligenceContent />
    </Suspense>
  );
}
