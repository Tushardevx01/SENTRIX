'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  ArrowRight,
  TrendingUp,
  Activity,
  Search,
  Zap,
  Terminal,
  Lock,
  Clock,
  ExternalLink,
  ChevronRight,
  Server,
  Layers,
} from 'lucide-react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell,
} from 'recharts';
import { fetchDashboardStats, submitUrlScan } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type DashboardStats } from '@sentrix/shared';

export default function DashboardPage() {
  const router = useRouter();
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Quick scan bar state
  const [quickUrl, setQuickUrl] = useState('');
  const [quickScanning, setQuickScanning] = useState(false);

  useEffect(() => {
    let isMounted = true;
    fetchDashboardStats()
      .then((data) => {
        if (isMounted) {
          setStats(data);
          setLoading(false);
        }
      })
      .catch((err) => {
        if (isMounted) {
          setError(err.message || 'Failed to load telemetry stats');
          setLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, []);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickUrl.trim()) return;

    setQuickScanning(true);
    try {
      const res = await submitUrlScan(quickUrl.trim());
      if (res?.scanId) {
        router.push(`/reports/${res.scanId}`);
      }
    } catch (err: any) {
      alert(err.message || 'Scan initiation failed');
    } finally {
      setQuickScanning(false);
    }
  };

  if (loading) {
    return <LoadingState message="Loading Command Center Telemetry..." />;
  }

  if (error || !stats) {
    return (
      <ErrorState
        title="Dashboard Telemetry Error"
        message={error || 'Could not load platform metrics'}
        onRetry={() => window.location.reload()}
      />
    );
  }

  const chartData = [
    { name: 'Benign', count: stats.benignCount, fill: '#15803D' },
    { name: 'Suspicious', count: stats.suspiciousCount, fill: '#B45309' },
    { name: 'Malicious', count: stats.maliciousCount, fill: '#B91C1C' },
  ];

  return (
    <div className="space-y-8 py-2">
      {/* Top Banner & Normal Rounded Quick Scan Bar */}
      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-6 sm:p-7 card-floating">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[11px] font-mono font-semibold uppercase text-neutral-500 tracking-wider">
              [ SOC // INCIDENT COMMAND ]
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Command Center Telemetry
          </h1>
          <p className="text-xs text-neutral-500 font-mono">
            Deterministic passive threat metrics computed directly from production database records.
          </p>
        </div>

        {/* Global Normal Rounded Search Bar */}
        <form
          onSubmit={handleQuickScan}
          className="flex items-center gap-2 w-full lg:w-auto min-w-[320px] max-w-md"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="Fast inspect URL or domain..."
              className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
            />
          </div>
          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            disabled={quickScanning}
            className="btn-industrial rounded-full shrink-0 px-4 py-2 text-xs font-semibold cursor-pointer disabled:opacity-50"
          >
            {quickScanning ? (
              <span className="w-3.5 h-3.5 rounded-full border-2 border-white border-t-transparent animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5 text-white" />
            )}
            <span>Scan</span>
          </button>
        </form>
      </div>

      {/* KPI Cards Grid with Instrumental Serif numbers */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5">
        {/* Total Scans */}
        <div className="p-4 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs">
          <div className="flex items-center justify-between text-neutral-500 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">
              Total Audits
            </span>
            <Activity className="w-3.5 h-3.5" />
          </div>
          <span className="text-3xl font-serif font-bold text-black dark:text-white block">
            {stats.totalScans}
          </span>
          <span className="text-[10px] font-mono text-neutral-500 mt-1 block">Live DB scans</span>
        </div>

        {/* Malicious Threats */}
        <div className="p-4 rounded-xl border border-red-200 dark:border-red-900/40 bg-red-50/40 dark:bg-red-950/20 shadow-xs">
          <div className="flex items-center justify-between text-red-600 dark:text-red-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <ShieldAlert className="w-3 h-3" /> Malicious
            </span>
          </div>
          <span className="text-3xl font-serif font-bold text-red-700 dark:text-red-400 block">
            {stats.maliciousCount}
          </span>
          <span className="text-[10px] font-mono text-red-600/70 dark:text-red-400/70 mt-1 block">
            High threat IOCs
          </span>
        </div>

        {/* Suspicious Scans */}
        <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/40 bg-amber-50/40 dark:bg-amber-950/20 shadow-xs">
          <div className="flex items-center justify-between text-amber-600 dark:text-amber-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Suspicious
            </span>
          </div>
          <span className="text-3xl font-serif font-bold text-amber-700 dark:text-amber-400 block">
            {stats.suspiciousCount}
          </span>
          <span className="text-[10px] font-mono text-amber-600/70 dark:text-amber-400/70 mt-1 block">
            Elevated anomalies
          </span>
        </div>

        {/* Benign Scans */}
        <div className="p-4 rounded-xl border border-emerald-200 dark:border-emerald-900/40 bg-emerald-50/40 dark:bg-emerald-950/20 shadow-xs">
          <div className="flex items-center justify-between text-emerald-600 dark:text-emerald-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> Trusted
            </span>
          </div>
          <span className="text-3xl font-serif font-bold text-emerald-700 dark:text-emerald-400 block">
            {stats.benignCount}
          </span>
          <span className="text-[10px] font-mono text-emerald-600/70 dark:text-emerald-400/70 mt-1 block">
            Clean perimeter
          </span>
        </div>

        {/* Average Risk Index */}
        <div className="p-4 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs">
          <div className="flex items-center justify-between text-neutral-500 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">
              Risk Index
            </span>
            <TrendingUp className="w-3.5 h-3.5" />
          </div>
          <div className="flex items-baseline gap-1">
            <span className="text-3xl font-serif font-bold text-black dark:text-white">
              {stats.averageRiskScore}
            </span>
            <span className="text-xs font-mono text-neutral-400">/100</span>
          </div>
          <span className="text-[10px] font-mono text-neutral-500 mt-1 block">Mean severity</span>
        </div>

        {/* Crowdsourced Reports */}
        <div className="p-4 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs">
          <div className="flex items-center justify-between text-neutral-500 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">
              Community
            </span>
            <Radio className="w-3.5 h-3.5" />
          </div>
          <span className="text-3xl font-serif font-bold text-black dark:text-white block">
            {stats.threatsReported}
          </span>
          <span className="text-[10px] font-mono text-neutral-500 mt-1 block">Peer submissions</span>
        </div>
      </div>

      {/* Analytics & Spectrum Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Spectrum Bar Chart */}
        <div className="lg:col-span-1 p-6 card-floating flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-black dark:text-white">
                // 01. VERDICT SPECTRUM
              </span>
              <span className="text-[9px] font-pixel text-neutral-500">DISTRIBUTION</span>
            </div>
            <p className="text-[11px] text-neutral-500 font-mono mt-2">
              Categorization of all analyzed web endpoints by deterministic heuristic threshold.
            </p>
          </div>

          <div className="h-44 w-full my-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" tick={{ fontSize: 10, fill: '#71717A' }} />
                <YAxis tick={{ fontSize: 10, fill: '#71717A' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#18181B',
                    borderColor: '#27272A',
                    color: '#FAFAFA',
                    fontSize: '11px',
                    fontFamily: 'monospace',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-3 border-t border-neutral-100 dark:border-[#1f1f23] grid grid-cols-3 text-center text-xs font-mono">
            <div>
              <span className="text-[10px] text-neutral-500 block">BENIGN</span>
              <span className="font-bold text-emerald-600 dark:text-emerald-400">{stats.benignCount}</span>
            </div>
            <div>
              <span className="text-[10px] text-neutral-500 block">SUSPICIOUS</span>
              <span className="font-bold text-amber-600 dark:text-amber-400">{stats.suspiciousCount}</span>
            </div>
            <div>
              <span className="text-[10px] text-neutral-500 block">MALICIOUS</span>
              <span className="font-bold text-red-600 dark:text-red-400">{stats.maliciousCount}</span>
            </div>
          </div>
        </div>

        {/* Live Investigations Table */}
        <div className="lg:col-span-2 p-6 card-floating flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
              <span className="text-xs font-mono font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                // 02. RECENT INVESTIGATION LOGS
              </span>
              <Link
                href="/history"
                className="text-[11px] font-mono text-neutral-500 hover:text-black dark:hover:text-white flex items-center gap-1"
              >
                Full Log <ArrowRight className="w-3 h-3" />
              </Link>
            </div>

            <div className="overflow-x-auto mt-3">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-neutral-100 dark:border-[#1f1f23] text-neutral-400 text-[10px] uppercase">
                    <th className="pb-2">Target Destination</th>
                    <th className="pb-2 text-center">Score</th>
                    <th className="pb-2">Verdict</th>
                    <th className="pb-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-100 dark:divide-[#18181b]">
                  {stats.recentScans.slice(0, 5).map((scan) => (
                    <tr key={scan._id} className="hover:bg-neutral-50 dark:hover:bg-[#141416] transition-colors">
                      <td className="py-2.5 max-w-[200px] truncate">
                        <span className="font-medium text-black dark:text-white block truncate">
                          {scan.normalizedDomain}
                        </span>
                        <span className="text-[10px] text-neutral-400 truncate block">
                          {scan.submittedUrl}
                        </span>
                      </td>
                      <td className="py-2.5 text-center">
                        <span className="font-bold text-xs">{scan.riskScore}</span>
                        <span className="text-[10px] text-neutral-400">/100</span>
                      </td>
                      <td className="py-2.5">
                        <RiskBadge verdict={scan.verdict} />
                      </td>
                      <td className="py-2.5 text-right">
                        <Link
                          href={`/reports/${scan._id}`}
                          className="btn-industrial text-[11px] py-1 px-2.5 rounded"
                        >
                          Forensics
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="pt-3 border-t border-neutral-100 dark:border-[#1f1f23] flex items-center justify-between text-[11px] font-mono text-neutral-500">
            <span>Automated attempt-scoped worker execution</span>
            <span>Real-time polling active</span>
          </div>
        </div>
      </div>
    </div>
  );
}
