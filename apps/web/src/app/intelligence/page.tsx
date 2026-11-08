'use client';

import React, { useEffect, useState, Suspense } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import {
  Radio,
  Search,
  ShieldAlert,
  ArrowRight,
  Globe,
  AlertTriangle,
  ExternalLink,
  Terminal,
} from 'lucide-react';
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
    <div className="space-y-8 py-2 max-w-6xl mx-auto font-mono text-xs">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <Radio className="w-3.5 h-3.5" />
            <span>[ INTEL // GLOBAL IOC FEED ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Threat Intelligence Repository
          </h1>
          <p className="text-xs text-neutral-500 font-mono max-w-2xl">
            Verified database of high-threat domains, deceptive hostnames, credential harvesting portals, and community alerts.
          </p>
        </div>
      </div>

      {/* Normal Rounded Search Bar */}
      <form onSubmit={handleSearch} className="max-w-2xl">
        <div className="relative flex items-center">
          <Search className="w-4 h-4 absolute left-4 text-neutral-400" />
          <input
            type="text"
            placeholder="Search domain, hostname, or threat keyword (e.g. paypal, .xyz, auth)..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full pl-11 pr-28 py-2.5 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
          />
          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            className="btn-industrial absolute right-1.5 py-1.5 px-4 rounded-full text-xs font-semibold cursor-pointer"
          >
            Search
          </button>
        </div>
      </form>

      {/* Content */}
      {loading ? (
        <LoadingState message="Querying Global Threat Feed..." />
      ) : error ? (
        <ErrorState title="Threat Intel Error" message={error} onRetry={() => loadData(query)} />
      ) : (
        <div className="space-y-8">
          {/* Verified Threats Table */}
          <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl overflow-hidden shadow-xs space-y-3 p-5">
            <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
              <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                // 01. ACTIVE SUSPICIOUS & MALICIOUS HOSTS
              </span>
              <span className="text-[10px] text-neutral-500 font-pixel">
                {threats.length} IDENTIFIED
              </span>
            </div>

            {threats.length === 0 ? (
              <div className="py-8 text-center text-neutral-400">
                No active threats found matching your query.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left font-mono text-xs">
                  <thead>
                    <tr className="border-b border-neutral-200 dark:border-[#1f1f23] text-neutral-400 text-[10px] uppercase bg-neutral-50 dark:bg-[#121214]">
                      <th className="py-2.5 px-3">Target Domain</th>
                      <th className="py-2.5 px-3">Submitted URL</th>
                      <th className="py-2.5 px-3 text-center">Score</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-100 dark:divide-[#18181b]">
                    {threats.map((t) => (
                      <tr key={t._id} className="hover:bg-neutral-50 dark:hover:bg-[#141416]">
                        <td className="py-2.5 px-3 font-bold text-black dark:text-white max-w-[200px] truncate">
                          {t.normalizedDomain}
                        </td>
                        <td className="py-2.5 px-3 text-neutral-500 max-w-[240px] truncate">
                          {t.submittedUrl}
                        </td>
                        <td className="py-2.5 px-3 text-center font-bold">
                          {t.riskScore}
                        </td>
                        <td className="py-2.5 px-3">
                          <RiskBadge verdict={t.verdict} />
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <Link
                            href={`/reports/${t._id}`}
                            className="btn-industrial text-[10px] py-1 px-2.5 rounded"
                          >
                            Inspect
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function ThreatIntelligencePage() {
  return (
    <Suspense fallback={<div className="p-8 text-center font-mono text-xs text-neutral-500">Loading intelligence feed...</div>}>
      <ThreatIntelligenceContent />
    </Suspense>
  );
}
