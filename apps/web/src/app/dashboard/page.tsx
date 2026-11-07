'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  ArrowUpRight,
  TrendingUp,
  Activity,
  Search,
  Server,
  Zap,
  CheckCircle2,
  Lock,
  Clock,
  ArrowRight,
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
import { motion } from 'framer-motion';
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
    { name: 'Benign', count: stats.benignCount, color: '#16A36A' },
    { name: 'Suspicious', count: stats.suspiciousCount, color: '#E99A32' },
    { name: 'Malicious', count: stats.maliciousCount, color: '#E34E5B' },
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: { staggerChildren: 0.05 },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 12 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.3 } },
  };

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      className="space-y-8 py-2"
    >
      {/* Top Welcome & Global Quick Scan Action */}
      <motion.div
        variants={itemVariants}
        className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs"
      >
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span className="text-[11px] font-mono font-semibold uppercase text-theme-muted tracking-wider">
              Security Operations Center
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-black text-theme-text tracking-tight font-mono">
            COMMAND CENTER TELEMETRY
          </h1>
          <p className="text-xs text-theme-muted font-mono">
            Real-time multi-vector threat index across automated sandbox executions.
          </p>
        </div>

        {/* Global Quick Scan Action */}
        <form
          onSubmit={handleQuickScan}
          className="flex items-center gap-2 w-full lg:w-auto min-w-[320px]"
        >
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-theme-muted" />
            <input
              type="text"
              value={quickUrl}
              onChange={(e) => setQuickUrl(e.target.value)}
              placeholder="Fast inspect URL or domain..."
              className="w-full pl-9 pr-3 py-2 text-xs font-mono bg-theme-bg border border-theme-border rounded-lg text-theme-text placeholder:text-theme-muted focus:outline-none focus:border-theme-accent transition-all"
            />
          </div>
          <button
            type="submit"
            disabled={quickScanning}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 disabled:opacity-50 shrink-0 shadow-sm"
          >
            {quickScanning ? (
              <span className="w-3.5 h-3.5 rounded-full border-2 border-white dark:border-slate-950 border-t-transparent animate-spin" />
            ) : (
              <Zap className="w-3.5 h-3.5" />
            )}
            <span>Scan</span>
          </button>
        </form>
      </motion.div>

      {/* Six Primary KPI Cards */}
      <motion.div
        variants={itemVariants}
        className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3.5"
      >
        {/* Total Scans */}
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <div className="flex items-center justify-between text-theme-muted mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">
              Total Audits
            </span>
            <Activity className="w-3.5 h-3.5" />
          </div>
          <span className="text-2xl font-black font-mono text-theme-text block">
            {stats.totalScans}
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Live DB records</span>
        </div>

        {/* Malicious Threats */}
        <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/50 dark:bg-rose-950/20">
          <div className="flex items-center justify-between text-rose-600 dark:text-rose-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <ShieldAlert className="w-3 h-3" /> Malicious
            </span>
          </div>
          <span className="text-2xl font-black font-mono text-rose-600 dark:text-rose-400 block">
            {stats.maliciousCount}
          </span>
          <span className="text-[10px] font-mono text-rose-600/70 dark:text-rose-400/70 mt-1 block">
            High-threat IOCs
          </span>
        </div>

        {/* Suspicious Scans */}
        <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20">
          <div className="flex items-center justify-between text-amber-600 dark:text-amber-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> Suspicious
            </span>
          </div>
          <span className="text-2xl font-black font-mono text-amber-600 dark:text-amber-400 block">
            {stats.suspiciousCount}
          </span>
          <span className="text-[10px] font-mono text-amber-600/70 dark:text-amber-400/70 mt-1 block">
            Elevated anomalies
          </span>
        </div>

        {/* Benign Scans */}
        <div className="p-4 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50/50 dark:bg-emerald-950/20">
          <div className="flex items-center justify-between text-emerald-600 dark:text-emerald-400 mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> Trusted
            </span>
          </div>
          <span className="text-2xl font-black font-mono text-emerald-600 dark:text-emerald-400 block">
            {stats.benignCount}
          </span>
          <span className="text-[10px] font-mono text-emerald-600/70 dark:text-emerald-400/70 mt-1 block">
            Valid TLS & clean
          </span>
        </div>

        {/* Average Risk Index */}
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <div className="flex items-center justify-between text-theme-muted mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold">
              Avg Risk Index
            </span>
            <TrendingUp className="w-3.5 h-3.5" />
          </div>
          <div className="flex items-baseline gap-1">
            <span className="text-2xl font-black font-mono text-theme-accent">
              {stats.averageRiskScore}
            </span>
            <span className="text-[11px] font-mono text-theme-muted">/100</span>
          </div>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Platform mean</span>
        </div>

        {/* Community Alerts */}
        <div className="p-4 rounded-xl border border-theme-border bg-theme-card">
          <div className="flex items-center justify-between text-theme-muted mb-2">
            <span className="text-[10px] font-mono uppercase tracking-wider font-semibold flex items-center gap-1">
              <Radio className="w-3 h-3 text-theme-accentSec" /> Community
            </span>
          </div>
          <span className="text-2xl font-black font-mono text-theme-accentSec block">
            {stats.threatsReported}
          </span>
          <span className="text-[10px] font-mono text-theme-muted mt-1 block">Peer submissions</span>
        </div>
      </motion.div>

      {/* Threat Distribution Chart & Architecture Engine Status */}
      <motion.div variants={itemVariants} className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recharts Bar Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-theme-border bg-theme-card">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold text-theme-text font-mono flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-theme-accent" />
                VERDICT SEVERITY DISTRIBUTION
              </h3>
              <p className="text-[11px] font-mono text-theme-muted mt-0.5">
                Aggregated scan results categorized by zero-trust risk score thresholds.
              </p>
            </div>
            <span className="text-[10px] font-mono text-theme-muted px-2 py-0.5 rounded bg-theme-elevated border border-theme-border">
              Live Aggregate
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#94A3B8" fontSize={11} fontFamily="monospace" />
                <YAxis stroke="#94A3B8" fontSize={11} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'var(--bg-card)',
                    borderColor: 'var(--border-color)',
                    borderRadius: '8px',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                    color: 'var(--text-primary)',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
                  }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {chartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Engine Telemetry & Sandbox Guard State */}
        <div className="p-5 rounded-xl border border-theme-border bg-theme-card flex flex-col justify-between space-y-4">
          <div>
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-theme-text mb-2">
              <Server className="w-4 h-4 text-theme-accent" />
              <span>CORE DEFENSE ENGINES</span>
            </div>
            <p className="text-xs font-mono text-theme-muted leading-relaxed">
              Multi-tier verification pipeline enforcing strict SSRF boundaries and zero-trust
              evaluations.
            </p>
          </div>

          <div className="p-3 bg-theme-elevated rounded-lg space-y-2.5 text-xs font-mono border border-theme-borderSubtle">
            <div className="flex justify-between items-center">
              <span className="text-theme-muted">Threat Scanner</span>
              <span className="text-theme-success font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> FastAPI (v1.1)
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-theme-muted">API Gateway</span>
              <span className="text-theme-success font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Fastify 5
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-theme-muted">Database Tier</span>
              <span className="text-theme-success font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> MongoDB 7.0
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-theme-muted">SSRF Protection</span>
              <span className="text-theme-success font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> RFC 1918 Block
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-theme-muted">Anti-DNS Rebinding</span>
              <span className="text-theme-success font-semibold flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" /> Socket Pinned
              </span>
            </div>
          </div>

          <Link
            href="/scanner"
            className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-theme-elevated hover:bg-theme-border border border-theme-border text-xs font-mono font-semibold text-theme-text transition-colors"
          >
            <span>Launch Deep Investigation</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </motion.div>

      {/* Recent Investigations Table */}
      <motion.div variants={itemVariants} className="p-5 rounded-xl border border-theme-border bg-theme-card space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold font-mono text-theme-text">RECENT INVESTIGATIONS</h3>
            <p className="text-[11px] font-mono text-theme-muted mt-0.5">
              Audit log of recently analyzed destinations and computed risk ratings.
            </p>
          </div>
          <Link
            href="/history"
            className="text-xs font-mono text-theme-accent hover:underline inline-flex items-center gap-1 font-semibold"
          >
            Full Audit History <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {stats.recentScans.length === 0 ? (
          <div className="text-center py-10 text-xs font-mono text-theme-muted border border-dashed border-theme-border rounded-lg">
            No security scans recorded yet. Enter a URL above to perform the first analysis.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-theme-border text-theme-muted">
                  <th className="py-2.5 px-3">Target Domain</th>
                  <th className="py-2.5 px-3">Risk Score</th>
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Timestamp</th>
                  <th className="py-2.5 px-3 text-right">Report</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-borderSubtle">
                {stats.recentScans.map((scan) => (
                  <tr key={scan._id} className="hover:bg-theme-elevated/50 transition-colors">
                    <td className="py-3 px-3 font-semibold text-theme-text truncate max-w-xs">
                      {scan.normalizedDomain}
                    </td>
                    <td className="py-3 px-3">
                      <span className="px-2 py-0.5 rounded bg-theme-elevated border border-theme-border text-theme-text font-bold">
                        {scan.riskScore}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <RiskBadge verdict={scan.verdict} size="sm" />
                    </td>
                    <td className="py-3 px-3 text-theme-muted">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-3 text-right">
                      <Link
                        href={`/reports/${scan._id}`}
                        className="text-theme-accent hover:underline inline-flex items-center gap-1 font-semibold"
                      >
                        Inspect <ArrowUpRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </motion.div>
    </motion.div>
  );
}
