'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { Radio, Search, ShieldAlert, ArrowUpRight, Globe, AlertTriangle } from 'lucide-react';
import { fetchThreats } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IScan, type IThreatReport } from '@sentrix/shared';

export default function ThreatIntelligencePage() {
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
    loadData();
  }, []);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    loadData(query.trim());
  };

  return (
    <div className="space-y-8 py-4">
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
          <Radio className="w-6 h-6 text-electric-400" />
          Threat Intelligence Database
        </h1>
        <p className="mt-1 text-xs font-mono text-slate-400">
          Global index of flagged malicious URLs, phishing domains, and active threat reports.
        </p>
      </div>

      {/* Search Input */}
      <form onSubmit={handleSearch} className="max-w-2xl">
        <div className="flex items-center gap-2 p-2 bg-slate-900 border border-slate-800 rounded-xl focus-within:border-electric-400 transition-all">
          <Search className="w-5 h-5 text-slate-500 ml-2" />
          <input
            type="text"
            placeholder="Search domain, host, or keyword (e.g., paypal, .xyz, bank)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-transparent text-white text-xs font-mono placeholder-slate-500 focus:outline-none py-1.5"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-xs font-mono transition-colors"
          >
            Filter
          </button>
        </div>
      </form>

      {loading ? (
        <LoadingState message="Querying Threat Registry..." />
      ) : error ? (
        <ErrorState message={error} onRetry={() => loadData(query)} />
      ) : (
        <div className="space-y-8">
          {/* Flagged Scan Threats */}
          <div className="space-y-4">
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              Verified Malicious & Suspicious Endpoints ({threats.length})
            </h2>

            {threats.length === 0 ? (
              <div className="p-6 rounded-xl bg-slate-900/40 border border-slate-800 text-center text-xs font-mono text-slate-400">
                No active threat records match your search criteria.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {threats.map((threat) => (
                  <div
                    key={threat._id}
                    className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <RiskBadge verdict={threat.verdict} size="sm" />
                        <span className="text-xs font-mono font-bold text-white px-2 py-0.5 rounded bg-slate-800">
                          Risk: {threat.riskScore}
                        </span>
                      </div>
                      <h3 className="font-mono text-sm font-bold text-white break-all mb-1">
                        {threat.submittedUrl}
                      </h3>
                      <p className="text-xs font-mono text-slate-400 flex items-center gap-1">
                        <Globe className="w-3 h-3 text-electric-400" />
                        Domain: {threat.normalizedDomain}
                      </p>
                    </div>

                    <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-500">
                        {new Date(threat.createdAt).toLocaleDateString()}
                      </span>
                      <Link
                        href={`/reports/${threat._id}`}
                        className="text-electric-400 hover:text-electric-300 inline-flex items-center gap-1 font-semibold"
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
            <div className="space-y-4 pt-4 border-t border-slate-800">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Crowdsourced Threat Alerts ({communityThreats.length})
              </h2>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {communityThreats.map((rep) => (
                  <div
                    key={rep._id}
                    className="p-5 rounded-xl bg-slate-900/40 border border-amber-900/30 text-xs font-mono space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-amber-400 font-bold uppercase">{rep.category}</span>
                      <span className="text-slate-500">Reports: {rep.reportCount}</span>
                    </div>
                    <p className="text-white font-bold break-all">{rep.submittedUrl}</p>
                    <p className="text-slate-400 text-[11px] leading-relaxed">{rep.description}</p>
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
