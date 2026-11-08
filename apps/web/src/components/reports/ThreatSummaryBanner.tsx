'use client';

import React from 'react';
import { RiskBadge } from '../ui/RiskBadge';
import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle } from 'lucide-react';
import type { Verdict } from '@sentrix/shared';

export interface ThreatSummaryBannerProps {
  url: string;
  verdict: Verdict;
  riskScore: number;
  confidence: number;
  completedAt?: string;
  isUnverifiedInfrastructure?: boolean;
}

export const ThreatSummaryBanner: React.FC<ThreatSummaryBannerProps> = ({
  url,
  verdict,
  riskScore,
  confidence,
  completedAt,
  isUnverifiedInfrastructure = false,
}) => {
  const getVerdictIcon = () => {
    switch (verdict) {
      case 'BENIGN':
        return <ShieldCheck className="w-8 h-8 text-emerald-500" />;
      case 'SUSPICIOUS':
        return <AlertTriangle className="w-8 h-8 text-amber-500" />;
      case 'MALICIOUS':
        return <ShieldAlert className="w-8 h-8 text-rose-500" />;
      default:
        return <HelpCircle className="w-8 h-8 text-slate-400" />;
    }
  };

  return (
    <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-6 shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-100 dark:border-slate-800 shrink-0">
            {getVerdictIcon()}
          </div>
          <div>
            <div className="flex items-center gap-2.5 flex-wrap">
              <RiskBadge verdict={verdict} />
              <span className="text-xs font-semibold px-2 py-0.5 rounded-md bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                Score: {riskScore}/100
              </span>
              {isUnverifiedInfrastructure && (
                <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-50 text-purple-700 dark:bg-purple-950/40 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
                  Unverified Infrastructure
                </span>
              )}
              <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
                Confidence: {confidence}%
              </span>
            </div>
            <h2 className="mt-2 text-lg font-bold text-slate-900 dark:text-white break-all">
              {url}
            </h2>
            {completedAt && (
              <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
                Analyzed on {new Date(completedAt).toLocaleString()}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
