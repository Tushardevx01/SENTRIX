'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { History, Search, ArrowUpRight, Globe, Clock } from 'lucide-react';
import { fetchScanHistory } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IScan } from '@sentrix/shared';

export default function HistoryPage() {
  const [scans, setScans] = useState<IScan[]>([]);
  const [total, setTotal] = useState(0);
  const [domainFilter, setDomainFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = (domain?: string) => {
    setLoading(true);
    fetchScanHistory(50, 0, domain)
      .then((data) => {
        setScans(data.scans || []);
        setTotal(data.total || 0);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load scan history');
        setLoading(false);
      });
  };

  useEffect(() => {
    loadHistory();
  }, []);

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    loadHistory(domainFilter.trim());
  };

  return (
    <div className="space-y-8 py-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight flex items-center gap-3">
            <History className="w-6 h-6 text-electric-400" />
            Security Scan History
          </h1>
          <p className="mt-1 text-xs font-mono text-slate-400">
            Audit trail of all performed link, domain, and certificate investigations ({total} total).
          </p>
        </div>

        <form onSubmit={handleFilter} className="flex items-center gap-2 w-full sm:w-auto">
          <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg focus-within:border-electric-400">
            <Search className="w-4 h-4 text-slate-500" />
            <input
              type="text"
              placeholder="Filter by domain..."
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className="bg-transparent text-xs font-mono text-white placeholder-slate-500 focus:outline-none w-36 sm:w-48"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-xs font-mono text-white rounded-lg transition-colors"
          >
            Filter
          </button>
        </form>
      </div>

      {loading ? (
        <LoadingState message="Retrieving Historical Telemetry..." />
      ) : error ? (
        <ErrorState message={error} onRetry={() => loadHistory(domainFilter)} />
      ) : scans.length === 0 ? (
        <div className="p-12 text-center rounded-xl bg-slate-900/40 border border-slate-800 text-slate-500 font-mono text-xs">
          No security scan records found.
        </div>
      ) : (
        <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/50 text-slate-400">
                  <th className="py-3 px-4">Target Destination</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {scans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-white max-w-xs truncate">
                      {scan.submittedUrl}
                    </td>
                    <td className="py-3.5 px-4 text-slate-300">
                      {scan.normalizedDomain}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-white font-bold">
                        {scan.riskScore}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`text-[11px] ${
                          scan.status === 'COMPLETED'
                            ? 'text-emerald-400'
                            : scan.status === 'FAILED'
                            ? 'text-red-400'
                            : 'text-amber-400'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-400">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        href={`/reports/${scan._id}`}
                        className="text-electric-400 hover:text-electric-300 inline-flex items-center gap-1 font-semibold"
                      >
                        Report <ArrowUpRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
