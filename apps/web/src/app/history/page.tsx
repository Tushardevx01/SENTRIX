'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  History,
  Search,
  ArrowUpRight,
  Globe,
  Clock,
  Download,
  Filter,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import { motion } from 'framer-motion';
import { fetchScanHistory } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type IScan, VerdictEnum } from '@sentrix/shared';

export default function HistoryPage() {
  const [scans, setScans] = useState<IScan[]>([]);
  const [total, setTotal] = useState(0);
  const [domainFilter, setDomainFilter] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadHistory = (domain?: string) => {
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
    loadHistory();
  }, []);

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
    <div className="space-y-8 py-2 max-w-6xl mx-auto">
      {/* Top Header & Search Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
            <History className="w-3.5 h-3.5" />
            <span>Forensic Audit Trail</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
            SECURITY SCAN AUDIT HISTORY
          </h1>
          <p className="text-xs text-theme-muted font-mono">
            Immutable log of all performed link, domain, and certificate investigations ({total} total records).
          </p>
        </div>

        {/* Export & Domain Filter */}
        <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
          <button
            onClick={handleExportJson}
            disabled={filteredScans.length === 0}
            className="inline-flex items-center gap-1.5 px-3 py-2 bg-theme-elevated hover:bg-theme-border border border-theme-border text-theme-text rounded-lg text-xs font-mono font-medium transition-colors disabled:opacity-50"
            title="Export filtered records as JSON"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          <form onSubmit={handleFilter} className="flex items-center gap-1.5">
            <div className="flex items-center gap-2 px-3 py-1.5 bg-theme-card border border-theme-border rounded-lg focus-within:border-theme-accent">
              <Search className="w-3.5 h-3.5 text-theme-muted" />
              <input
                type="text"
                placeholder="Domain filter..."
                value={domainFilter}
                onChange={(e) => setDomainFilter(e.target.value)}
                className="bg-transparent text-xs font-mono text-theme-text placeholder:text-theme-muted focus:outline-none w-32 sm:w-44"
              />
            </div>
            <button
              type="submit"
              className="px-3 py-1.5 bg-theme-accent text-white dark:text-slate-950 font-bold text-xs font-mono rounded-lg transition-opacity hover:opacity-90 shadow-xs"
            >
              Filter
            </button>
          </form>
        </div>
      </div>

      {/* Filter Tabs by Verdict */}
      <div className="flex flex-wrap items-center gap-2 pb-2 border-b border-theme-borderSubtle text-xs font-mono">
        <span className="text-theme-muted flex items-center gap-1 mr-1">
          <Filter className="w-3.5 h-3.5" /> Verdict:
        </span>
        {['ALL', VerdictEnum.MALICIOUS, VerdictEnum.SUSPICIOUS, VerdictEnum.BENIGN, VerdictEnum.INCONCLUSIVE, VerdictEnum.UNVERIFIED_INFRASTRUCTURE].map(
          (tab) => {
            const isSelected = verdictFilter === tab;
            return (
              <button
                key={tab}
                type="button"
                onClick={() => setVerdictFilter(tab)}
                className={`px-2.5 py-1 rounded-lg transition-all ${
                  isSelected
                    ? 'bg-theme-accent text-white dark:text-slate-950 font-bold'
                    : 'bg-theme-elevated text-theme-muted hover:text-theme-text'
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
        <ErrorState message={error} onRetry={() => loadHistory(domainFilter)} />
      ) : filteredScans.length === 0 ? (
        <div className="p-12 text-center rounded-xl border border-dashed border-theme-border text-theme-muted font-mono text-xs">
          No security scan records found matching your filters.
        </div>
      ) : (
        <div className="bg-theme-card border border-theme-border rounded-xl overflow-hidden shadow-card">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-theme-border bg-theme-elevated/50 text-theme-muted">
                  <th className="py-3 px-4">Target Destination</th>
                  <th className="py-3 px-4">Domain</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">Verdict</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-borderSubtle">
                {filteredScans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-theme-elevated/40 transition-colors">
                    <td className="py-3.5 px-4 font-bold text-theme-text max-w-xs truncate">
                      {scan.submittedUrl}
                    </td>
                    <td className="py-3.5 px-4 text-theme-muted font-medium">
                      {scan.normalizedDomain}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-theme-elevated border border-theme-borderSubtle text-theme-text font-bold">
                        {scan.riskScore}
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`text-[11px] font-semibold ${
                          scan.status === 'COMPLETED'
                            ? 'text-theme-success'
                            : scan.status === 'FAILED'
                            ? 'text-theme-danger'
                            : 'text-theme-warning'
                        }`}
                      >
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-theme-muted">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        href={`/reports/${scan._id}`}
                        className="text-theme-accent hover:underline inline-flex items-center gap-1 font-semibold"
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
