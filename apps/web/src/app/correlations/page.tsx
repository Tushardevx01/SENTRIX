'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Network,
  Search,
  Globe,
  Wallet,
  Mail,
  Phone,
  Hash,
  ArrowRight,
  Terminal,
  Activity,
  Layers,
  ChevronRight,
  ShieldAlert,
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
        return <Globe className="w-3.5 h-3.5 text-black dark:text-white" />;
      case IndicatorTypeEnum.WALLET:
        return <Wallet className="w-3.5 h-3.5 text-emerald-600 dark:text-emerald-400" />;
      case IndicatorTypeEnum.EMAIL:
        return <Mail className="w-3.5 h-3.5 text-sky-600 dark:text-sky-400" />;
      case IndicatorTypeEnum.PHONE:
        return <Phone className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />;
      default:
        return <Hash className="w-3.5 h-3.5 text-neutral-400" />;
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a] text-black dark:text-white shadow-xs">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white flex items-center gap-2">
                Threat Correlation & Campaign Graph
                <span className="text-[9px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-neutral-100 dark:bg-[#18181b] text-neutral-700 dark:text-neutral-300 border border-neutral-300 dark:border-[#27272a]">
                  MODULE B
                </span>
              </h1>
              <p className="text-xs text-neutral-500 font-mono mt-0.5">
                Automatically links shared hosting IPs, cryptocurrency drainer wallets, and attacker infrastructure.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Target Correlation Search Box with Normal Rounded Search Bar */}
      <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 sm:p-6 shadow-card space-y-3">
        <div>
          <h2 className="text-xs font-mono font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
            <Terminal className="w-4 h-4" />
            // 01. QUERY CROSS-VECTOR THREAT GRAPH
          </h2>
          <p className="text-[11px] text-neutral-500 mt-0.5">
            Enter a domain, IP address, cryptocurrency wallet, email, or telephone number to uncover linked incidents.
          </p>
        </div>

        {/* Normal Rounded Search Bar Form */}
        <form onSubmit={handleSearch} className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              required
              placeholder="e.g. login-secure-auth.com or 0x71C84183... or +1-800-555-0199"
              value={searchTarget}
              onChange={(e) => setSearchTarget(e.target.value)}
              className="w-full pl-11 pr-4 py-2.5 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
            />
          </div>
          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            disabled={searching}
            className="btn-industrial py-2.5 px-6 rounded-full text-xs font-semibold cursor-pointer disabled:opacity-50 shrink-0"
          >
            {searching ? 'Querying Graph...' : 'Trace Target IOC'}
          </button>
        </form>
      </div>

      {/* Related Threats Search Result */}
      {relatedResult && (
        <div className="p-5 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-card space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
            <span className="font-bold text-black dark:text-white uppercase tracking-wider">
              // CORRELATION RESULT FOR &quot;{relatedResult.target}&quot;
            </span>
            <span className="text-[10px] text-neutral-500">
              {relatedResult.campaigns.length} Campaigns Linked
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                Linked Scan Incidents ({relatedResult.relatedScans.length})
              </span>
              {relatedResult.relatedScans.length === 0 ? (
                <div className="text-neutral-400 p-2">No linked web scans found.</div>
              ) : (
                <div className="space-y-1">
                  {relatedResult.relatedScans.map((s) => (
                    <div key={s._id} className="p-2 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] flex items-center justify-between">
                      <span className="truncate max-w-[200px] text-black dark:text-white">{s.submittedUrl}</span>
                      <RiskBadge verdict={s.verdict} />
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div>
              <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                Linked Scam Messages ({relatedResult.relatedMessages.length})
              </span>
              {relatedResult.relatedMessages.length === 0 ? (
                <div className="text-neutral-400 p-2">No linked messages found.</div>
              ) : (
                <div className="space-y-1">
                  {relatedResult.relatedMessages.map((m) => (
                    <div key={m._id} className="p-2 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] flex items-center justify-between">
                      <span className="truncate max-w-[200px] text-black dark:text-white">{m.preview}</span>
                      <RiskBadge verdict={m.classification} />
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tabs: Campaigns vs Tracked Atomic Indicators */}
      <div className="space-y-4">
        <div className="flex items-center gap-2 border-b border-neutral-200 dark:border-[#1f1f23] pb-2">
          <button
            type="button"
            onClick={() => setActiveTab('campaigns')}
            className={`px-4 py-1.5 rounded-full text-xs font-mono transition-colors cursor-pointer ${
              activeTab === 'campaigns'
                ? 'btn-industrial'
                : 'text-neutral-500 hover:text-black dark:hover:text-white'
            }`}
          >
            Active Attack Campaigns ({campaigns.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('indicators')}
            className={`px-4 py-1.5 rounded-full text-xs font-mono transition-colors cursor-pointer ${
              activeTab === 'indicators'
                ? 'btn-industrial'
                : 'text-neutral-500 hover:text-black dark:hover:text-white'
            }`}
          >
            Tracked Atomic IOCs ({indicators.length})
          </button>
        </div>

        {activeTab === 'campaigns' ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {campaigns.length === 0 ? (
              <div className="col-span-full p-8 text-center text-neutral-400 border border-neutral-200 dark:border-[#27272a] rounded-xl bg-white dark:bg-[#0c0c0e]">
                No threat campaigns identified yet. Run scans or message audits to cluster attacker infrastructure.
              </div>
            ) : (
              campaigns.map((camp) => (
                <div
                  key={camp.campaignId}
                  className="card-floating p-5 space-y-3"
                >
                  <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-[#1f1f23]">
                    <span className="font-bold text-black dark:text-white truncate pr-2">
                      {camp.name}
                    </span>
                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-[#18181b] text-neutral-500 uppercase font-pixel shrink-0">
                      {camp.threatType}
                    </span>
                  </div>

                  <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
                    {camp.summary}
                  </p>

                  <div className="pt-2 border-t border-neutral-100 dark:border-[#1f1f23] flex items-center justify-between text-[10px] text-neutral-400">
                    <span>{camp.relatedIncidents?.length || 0} linked events</span>
                    <span>Confidence: {camp.confidence}%</span>
                  </div>
                </div>
              ))
            )}
          </div>
        ) : (
          <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl overflow-hidden shadow-xs">
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-neutral-200 dark:border-[#1f1f23] text-neutral-400 text-[10px] uppercase bg-neutral-50 dark:bg-[#121214]">
                    <th className="py-2.5 px-4">Indicator Type</th>
                    <th className="py-2.5 px-4">Normalized Value</th>
                    <th className="py-2.5 px-4 text-center">Occurrences</th>
                    <th className="py-2.5 px-4">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-neutral-100 dark:divide-[#18181b]">
                  {indicators.map((ind) => (
                    <tr key={ind._id} className="hover:bg-neutral-50 dark:hover:bg-[#141416]">
                      <td className="py-2.5 px-4 flex items-center gap-2">
                        {getIndicatorIcon(ind.type)}
                        <span className="font-semibold text-black dark:text-white">{ind.type}</span>
                      </td>
                      <td className="py-2.5 px-4 max-w-[280px] truncate text-neutral-600 dark:text-neutral-300">
                        {ind.normalizedValue}
                      </td>
                      <td className="py-2.5 px-4 text-center font-bold">
                        {ind.occurrences}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className={`text-[10px] px-2 py-0.5 rounded font-pixel ${
                          ind.severity === 'CRITICAL' ? 'bg-red-100 text-red-700 dark:bg-red-950 dark:text-red-400' :
                          ind.severity === 'HIGH' ? 'bg-amber-100 text-amber-700 dark:bg-amber-950 dark:text-amber-400' :
                          'bg-neutral-200 text-neutral-700 dark:bg-[#27272a] dark:text-neutral-300'
                        }`}>
                          {ind.severity}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
