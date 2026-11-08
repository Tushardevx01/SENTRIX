'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  History,
  Search,
  Clock,
  Download,
  Filter,
  ArrowRight,
  Terminal,
} from 'lucide-react';
import { fetchScanHistory } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IScan, VerdictEnum } from '@sentrix/shared';
import { useAuth } from '@/contexts/AuthContext';
import { AuthRequiredGate } from '@/components/auth/AuthRequiredGate';

export default function HistoryPage() {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const [scans, setScans] = useState<IScan[]>([]);
  const [total, setTotal] = useState(0);
  const [domainFilter, setDomainFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = (domain?: string) => {
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }
    setLoading(true);
    fetchScanHistory(100, 0, domain)
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
    if (isAuthenticated) {
      loadHistory();
    } else {
      setLoading(false);
    }
  }, [isAuthenticated]);

  if (authLoading) {
    return <LoadingState message="Verifying session authorization..." />;
  }

  if (!isAuthenticated) {
    return <AuthRequiredGate pageName="Security Scan History" />;
  }

  const handleFilter = (e: React.FormEvent) => {
    e.preventDefault();
    loadHistory(domainFilter.trim());
  };

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredScans, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sentrix_audit_scans_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredScans = scans.filter((scan) => {
    if (verdictFilter === 'ALL') return true;
    return scan.verdict === verdictFilter;
  });

  return (
    <div className="space-y-8 py-2 max-w-6xl mx-auto font-mono text-xs">
      {/* Top Header & Normal Rounded Search Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <History className="w-3.5 h-3.5" />
            <span>[ AUDIT // FORENSIC LOGS ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Security Scan History
          </h1>
          <p className="text-xs text-neutral-500 font-mono">
            Immutable log of all performed link, domain, and certificate investigations ({total} total records).
          </p>
        </div>

        {/* Export & Normal Rounded Search Bar */}
        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <button
            onClick={handleExportJson}
            disabled={filteredScans.length === 0}
            className="px-3 py-2 rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-100 dark:bg-[#121214] text-black dark:text-white hover:bg-neutral-200 dark:hover:bg-[#1c1c20] transition-colors disabled:opacity-50 inline-flex items-center gap-1.5 cursor-pointer"
            title="Export filtered records as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          {/* Normal Rounded Search Bar */}
          <form onSubmit={handleFilter} className="flex items-center gap-1.5 relative">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
              <input
                type="text"
                placeholder="Filter by domain..."
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                className="pl-9 pr-3 py-2 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white w-40 sm:w-52 transition-all"
              />
            </div>
            {/* Normal dark gray button with white button text */}
            <button
              type="submit"
              className="btn-industrial py-2 px-3.5 rounded-full text-xs font-semibold cursor-pointer"
            >
              Filter
            </button>
          </form>
        </div>
      </div>

      {/* Filter Tabs by Verdict */}
      <div className="flex flex-wrap items-center gap-2 pb-2 text-xs font-mono">
        <span className="text-neutral-500 flex items-center gap-1 mr-1">
          <Filter className="w-3.5 h-3.5" /> Filter Verdict:
        </span>
        {['ALL', VerdictEnum.MALICIOUS, VerdictEnum.SUSPICIOUS, VerdictEnum.BENIGN, VerdictEnum.INCONCLUSIVE, VerdictEnum.UNVERIFIED_INFRASTRUCTURE].map(
          (tab) => {
            const isSelected = verdictFilter === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setVerdictFilter(tab)}
                className={`px-3 py-1 rounded-full transition-all cursor-pointer ${
                  isSelected
                    ? 'btn-industrial text-white'
                    : 'bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300 hover:text-black dark:hover:text-white'
                }`}
              >
                {tab}
              </button>
            );
          }
        )}
      </div>

      {/* Main Table View */}
      {loading ? (
        <LoadingState message="Retrieving Historical Telemetry..." />
      ) : error ? (
        <ErrorState title="History Load Error" message={error} onRetry={() => loadHistory()} />
      ) : filteredScans.length === 0 ? (
        <div className="p-12 text-center border border-neutral-200 dark:border-[#27272a] rounded-xl bg-white dark:bg-[#0c0c0e] text-neutral-400 space-y-2">
          <p>No historical security investigations match the selected filter criteria.</p>
          <Link href="/scanner" className="btn-industrial py-1.5 px-4 rounded-full mt-2 inline-flex">
            Scan a URL Now
          </Link>
        </div>
      ) : (
        <div className="card-floating overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-neutral-200 dark:border-[#1f1f23] text-neutral-400 text-[10px] uppercase bg-neutral-50 dark:bg-[#121214]">
                  <th className="py-3 px-4">Investigated Domain</th>
                  <th className="py-3 px-4">Submitted URL</th>
                  <th className="py-3 px-4 text-center">Score</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Forensic View</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-neutral-100 dark:divide-[#18181b]">
                {filteredScans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-neutral-50 dark:hover:bg-[#141416] transition-colors">
                    <td className="py-3 px-4 font-bold text-black dark:text-white max-w-[180px] truncate">
                      {scan.normalizedDomain}
                    </td>
                    <td className="py-3 px-4 max-w-[240px] truncate text-neutral-500">
                      {scan.submittedUrl}
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className="font-bold text-xs">{scan.riskScore}</span>
                      <span className="text-[10px] text-neutral-400">/100</span>
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge verdict={scan.verdict} />
                    </td>
                    <td className="py-3 px-4 text-neutral-500 text-[11px] whitespace-nowrap">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {/* Normal dark gray button with white button text */}
                      <Link
                        href={`/reports/${scan._id}`}
                        className="btn-industrial text-[11px] py-1 px-3 rounded"
                      >
                        <span>Report</span>
                        <ArrowRight className="w-3 h-3 text-white" />
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
