'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Network,
  Search,
  Layers,
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  RefreshCw,
  FolderTree,
  Activity,
  Globe,
  Wallet,
  Mail,
  Phone,
  Hash,
} from 'lucide-react';
import {
  fetchThreatCampaigns,
  fetchThreatIndicators,
  fetchRelatedThreats,
} from '@/lib/api';
import { RiskBadge } from '@/components/ui/RiskBadge';
import {
  type IThreatCampaign,
  type IThreatIndicator,
  type IRelatedThreats,
  IndicatorTypeEnum,
} from '@sentrix/shared';

export default function CorrelationPage() {
  const [campaigns, setCampaigns] = useState<IThreatCampaign[]>([]);
  const [indicators, setIndicators] = useState<IThreatIndicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTarget, setSearchTarget] = useState('');
  const [searching, setSearching] = useState(false);
  const [relatedResult, setRelatedResult] = useState<IRelatedThreats | null>(null);
  const [activeTab, setActiveTab] = useState<'campaigns' | 'indicators'>('campaigns');

  useEffect(() => {
    let mounted = true;
    async function loadData() {
      try {
        const [cRes, iRes] = await Promise.all([
          fetchThreatCampaigns().catch(() => ({ total: 0, campaigns: [] })),
          fetchThreatIndicators(undefined, 50).catch(() => ({ total: 0, indicators: [] })),
        ]);
        if (mounted) {
          setCampaigns(cRes.campaigns || []);
          setIndicators(iRes.indicators || []);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    }
    loadData();
    return () => {
      mounted = false;
    };
  }, []);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchTarget.trim() || searching) return;
    setSearching(true);
    try {
      const res = await fetchRelatedThreats(searchTarget.trim());
      setRelatedResult(res);
    } catch {
      setRelatedResult(null);
    } finally {
      setSearching(false);
    }
  };

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case IndicatorTypeEnum.DOMAIN:
      case IndicatorTypeEnum.IP:
        return <Globe className="w-3.5 h-3.5 text-sky-400" />;
      case IndicatorTypeEnum.WALLET:
        return <Wallet className="w-3.5 h-3.5 text-emerald-400" />;
      case IndicatorTypeEnum.EMAIL:
        return <Mail className="w-3.5 h-3.5 text-indigo-400" />;
      case IndicatorTypeEnum.PHONE:
        return <Phone className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return <Hash className="w-3.5 h-3.5 text-theme-muted" />;
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-theme-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-theme-accent/10 border border-theme-accent/20 text-theme-accent shadow-xs">
              <Network className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-theme-text flex items-center gap-2">
                Threat Correlation & Campaign Graph
                <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-theme-accent/10 text-theme-accent border border-theme-accent/20">
                  Cross-Vector IOC Graph
                </span>
              </h1>
              <p className="text-xs text-theme-muted mt-0.5">
                Automatically connects recurring domains, shared IPs, crypto wallet addresses, and social engineering patterns across scans and scam messages.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Target Correlation Search */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
            <Search className="w-4 h-4 text-theme-accent" />
            Query Cross-Vector Threat Graph
          </h2>
          <p className="text-[11px] text-theme-muted mt-0.5">
            Enter a domain, IP address, cryptocurrency wallet, email, or telephone number to uncover linked campaigns and incidents.
          </p>
        </div>

        <form onSubmit={handleSearch} className="flex gap-2">
          <input
            type="text"
            required
            placeholder="e.g. login-secure-auth.com or 0x71C84183... or +1-800-555-0199"
            value={searchTarget}
            onChange={(e) => setSearchTarget(e.target.value)}
            className="flex-1 px-3 py-2 text-xs font-mono rounded-lg border border-theme-border bg-theme-base text-theme-text placeholder:text-theme-muted/50 focus:outline-none focus:ring-1 focus:ring-theme-accent"
          />
          <button
            type="submit"
            disabled={searching || !searchTarget.trim()}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-theme-accent text-white font-mono text-xs font-semibold hover:bg-theme-accent/90 disabled:opacity-50 transition-all shadow-sm"
          >
            {searching ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            Trace IOCs
          </button>
        </form>

        {relatedResult && (
          <div className="p-4 rounded-lg bg-theme-base border border-theme-border space-y-3 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-theme-border pb-2">
              <span className="font-semibold text-theme-text">
                Correlation Results for: <span className="text-theme-accent">{relatedResult.target}</span>
              </span>
              <span className="text-[10px] text-theme-muted">
                {relatedResult.relatedScans.length} Related Scans • {relatedResult.relatedMessages.length} Messages • {relatedResult.campaigns.length} Campaigns
              </span>
            </div>

            {/* Campaign links */}
            {relatedResult.campaigns.length > 0 && (
              <div>
                <span className="text-[10px] uppercase text-rose-400 font-bold block mb-1">
                  Active Campaign Matches:
                </span>
                <div className="space-y-1">
                  {relatedResult.campaigns.map((camp) => (
                    <div
                      key={camp._id}
                      className="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-theme-text text-[11px]"
                    >
                      <span className="font-bold text-rose-300">{camp.name}</span> — {camp.summary}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Related Scans */}
            {relatedResult.relatedScans.length > 0 && (
              <div>
                <span className="text-[10px] uppercase text-theme-muted block mb-1">
                  Correlated URL Scans:
                </span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-1.5">
                  {relatedResult.relatedScans.map((sc) => (
                    <Link
                      key={sc._id}
                      href={`/reports/${sc._id}`}
                      className="p-2 rounded bg-theme-elevated border border-theme-border hover:border-theme-accent flex items-center justify-between"
                    >
                      <span className="truncate max-w-[200px] text-[11px] text-theme-text">
                        {sc.submittedUrl}
                      </span>
                      <RiskBadge verdict={sc.verdict} size="sm" />
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-theme-border pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('campaigns')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === 'campaigns'
              ? 'bg-theme-accent text-white'
              : 'text-theme-muted hover:text-theme-text hover:bg-theme-elevated'
          }`}
        >
          Correlated Campaigns ({campaigns.length})
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('indicators')}
          className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
            activeTab === 'indicators'
              ? 'bg-theme-accent text-white'
              : 'text-theme-muted hover:text-theme-text hover:bg-theme-elevated'
          }`}
        >
          Tracked Threat Indicators ({indicators.length})
        </button>
      </div>

      {loading ? (
        <div className="py-12 flex justify-center">
          <RefreshCw className="w-6 h-6 animate-spin text-theme-accent" />
        </div>
      ) : activeTab === 'campaigns' ? (
        campaigns.length === 0 ? (
          <div className="bg-theme-card border border-theme-border rounded-xl p-8 text-center">
            <FolderTree className="w-8 h-8 text-theme-muted mx-auto mb-2 opacity-50" />
            <p className="text-xs font-mono text-theme-muted">
              No correlated threat campaigns active yet. As repetitive attacks occur across multiple scans and message vectors, the engine will group them here automatically.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {campaigns.map((camp) => (
              <div
                key={camp._id}
                className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4 hover:border-theme-accent/50 transition-all"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 uppercase font-semibold">
                      {camp.threatType}
                    </span>
                    <h3 className="text-sm font-bold text-theme-text mt-1.5">
                      {camp.name}
                    </h3>
                  </div>
                  <span className="text-[11px] font-mono font-semibold text-theme-accent bg-theme-accent/10 px-2 py-0.5 rounded border border-theme-accent/20">
                    Confidence: {camp.confidence}%
                  </span>
                </div>

                <p className="text-xs text-theme-muted font-sans leading-relaxed">
                  {camp.summary}
                </p>

                <div className="space-y-2 pt-2 border-t border-theme-border text-xs font-mono">
                  <span className="text-[10px] uppercase text-theme-muted block">
                    Shared Campaign Indicators:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {camp.indicators?.map((ind, i) => (
                      <span
                        key={i}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-theme-base border border-theme-border text-[11px] text-theme-text"
                      >
                        {getIndicatorIcon(ind.type)}
                        <span className="truncate max-w-[150px]">{ind.value}</span>
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5 pt-2 border-t border-theme-border text-xs font-mono">
                  <span className="text-[10px] uppercase text-theme-muted block">
                    Linked Incidents ({camp.relatedIncidents?.length || 0}):
                  </span>
                  <div className="space-y-1">
                    {camp.relatedIncidents?.slice(0, 3).map((inc, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between p-1.5 rounded bg-theme-base/60 text-[11px]"
                      >
                        <span className="truncate max-w-[200px] text-theme-text">{inc.target}</span>
                        <RiskBadge verdict={inc.verdict} size="sm" />
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )
      ) : (
        /* Indicators Tab */
        <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-theme-border text-theme-muted uppercase text-[10px]">
                  <th className="py-2 px-3">Type</th>
                  <th className="py-2 px-3">Normalized Indicator</th>
                  <th className="py-2 px-3">Severity</th>
                  <th className="py-2 px-3">Occurrences</th>
                  <th className="py-2 px-3">First Seen</th>
                  <th className="py-2 px-3">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-border/50">
                {indicators.map((ind) => (
                  <tr key={ind._id} className="hover:bg-theme-elevated/40 transition-colors">
                    <td className="py-2.5 px-3">
                      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-theme-text">
                        {getIndicatorIcon(ind.type)}
                        {ind.type}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-theme-text font-bold truncate max-w-[260px]">
                      {ind.value}
                    </td>
                    <td className="py-2.5 px-3">
                      <RiskBadge severity={ind.severity} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 text-theme-accent font-bold">
                      {ind.occurrences}x
                    </td>
                    <td className="py-2.5 px-3 text-theme-muted text-[10px]">
                      {new Date(ind.firstSeen).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-3 text-theme-muted text-[10px]">
                      {new Date(ind.lastSeen).toLocaleDateString()}
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
