'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe,
  Radio,
  ArrowUpRight,
  TrendingUp,
  Activity,
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
import { fetchDashboardStats } from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import { type DashboardStats } from '@sentrix/shared';

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  if (loading) {
    return <LoadingState message="Loading Security Telemetry..." />;
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
    { name: 'Benign', count: stats.benignCount, color: '#10B981' },
    { name: 'Suspicious', count: stats.suspiciousCount, color: '#F59E0B' },
    { name: 'Malicious', count: stats.maliciousCount, color: '#EF4444' },
  ];

  return (
    <div className="space-y-8 py-4">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Security Intelligence Dashboard
          </h1>
          <p className="mt-1 text-xs font-mono text-slate-400">
            Real-time threat telemetry aggregated across verified endpoint inspections.
          </p>
        </div>

        <Link
          href="/scanner"
          className="inline-flex items-center gap-2 px-4 py-2 bg-electric-500 hover:bg-electric-400 text-slate-950 font-bold rounded-lg text-xs font-mono transition-all shadow-glow"
        >
          <Activity className="w-4 h-4" />
          Launch New Scan
        </Link>
      </div>

      {/* KPI Stat Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
            Total Scans
          </span>
          <span className="text-2xl font-black font-mono text-white">{stats.totalScans}</span>
        </div>

        <div className="p-4 rounded-xl bg-red-950/20 border border-red-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-red-400 block mb-1 flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" /> Malicious
          </span>
          <span className="text-2xl font-black font-mono text-red-400">{stats.maliciousCount}</span>
        </div>

        <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-amber-400 block mb-1 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3" /> Suspicious
          </span>
          <span className="text-2xl font-black font-mono text-amber-400">
            {stats.suspiciousCount}
          </span>
        </div>

        <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-900/40">
          <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-400 block mb-1 flex items-center gap-1">
            <ShieldCheck className="w-3 h-3" /> Benign
          </span>
          <span className="text-2xl font-black font-mono text-emerald-400">{stats.benignCount}</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1">
            Avg Risk Index
          </span>
          <span className="text-2xl font-black font-mono text-electric-400">
            {stats.averageRiskScore}
            <span className="text-xs text-slate-500 font-normal"> / 100</span>
          </span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block mb-1 flex items-center gap-1">
            <Radio className="w-3 h-3 text-cyan-400" /> Community Alerts
          </span>
          <span className="text-2xl font-black font-mono text-cyan-300">
            {stats.threatsReported}
          </span>
        </div>
      </div>

      {/* Threat Distribution Chart & Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-6 rounded-xl bg-slate-900/60 border border-slate-800">
          <h3 className="text-sm font-bold text-white mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-electric-400" />
            Threat Severity Distribution
          </h3>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#64748B" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#64748B" fontSize={11} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0F172A',
                    borderColor: '#1E293B',
                    borderRadius: '8px',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white mb-2">Zero-Trust Heuristics</h3>
            <p className="text-xs font-mono text-slate-400 leading-relaxed mb-4">
              Real-time classification engines combine URL lexical anomalies, domain impersonation checks, TLS integrity analysis, and community threat consensus.
            </p>
          </div>

          <div className="p-4 bg-slate-950/70 border border-slate-800/80 rounded-lg space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Scanner Engine</span>
              <span className="text-emerald-400">Active (v1.0.0)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Database Engine</span>
              <span className="text-emerald-400">MongoDB Indexed</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">SSRF Protection</span>
              <span className="text-emerald-400">RFC 1918 Enforced</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white">Recent Security Scans</h3>
          <Link
            href="/history"
            className="text-xs font-mono text-electric-400 hover:text-electric-300 flex items-center gap-1"
          >
            Full History <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {stats.recentScans.length === 0 ? (
          <div className="text-center py-8 text-xs font-mono text-slate-500">
            No scans recorded yet. Submit your first URL via the scanner.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2.5 px-3">Target Domain</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-850">
                {stats.recentScans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3 font-semibold text-slate-200 truncate max-w-xs">
                      {scan.normalizedDomain}
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-white font-bold">
                        {scan.riskScore}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <RiskBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="py-3 px-3 text-slate-400">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <Link
                        href={`/reports/${scan._id}`}
                        className="text-electric-400 hover:text-electric-300 inline-flex items-center gap-1"
                      >
                        Report <ArrowUpRight className="w-3 h-3" />
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
  );
}
