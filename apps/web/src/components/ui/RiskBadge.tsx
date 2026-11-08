import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertCircle, HelpCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import {
  VerdictEnum,
  type Verdict,
  FindingSeverityEnum,
  type FindingSeverity,
} from '@sentrix/shared';

interface RiskBadgeProps {
  verdict?: Verdict;
  severity?: FindingSeverity;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ verdict, severity, size = 'md' }) => {
  if (verdict) {
    const config = {
      [VerdictEnum.BENIGN]: {
        label: 'BENIGN / TRUSTED',
        style:
          'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/50 dark:text-emerald-400 dark:border-emerald-800/60',
        icon: ShieldCheck,
      },
      [VerdictEnum.SUSPICIOUS]: {
        label: 'SUSPICIOUS / ELEVATED',
        style:
          'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/50 dark:text-amber-400 dark:border-amber-800/60',
        icon: AlertTriangle,
      },
      [VerdictEnum.MALICIOUS]: {
        label: 'MALICIOUS / HIGH THREAT',
        style:
          'bg-rose-50 text-rose-700 border-rose-200 dark:bg-red-950/50 dark:text-red-400 dark:border-red-800/60',
        icon: ShieldAlert,
      },
      [VerdictEnum.INCONCLUSIVE]: {
        label: 'INCONCLUSIVE / PARTIAL',
        style:
          'bg-slate-100 text-slate-700 border-slate-300 dark:bg-zinc-900/90 dark:text-zinc-300 dark:border-zinc-700',
        icon: HelpCircle,
      },
    }[verdict] || {
      label: verdict,
      style:
        'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
      icon: AlertCircle,
    };

    const Icon = config.icon;
    const sizeClasses = {
      sm: 'px-2 py-0.5 text-[11px] gap-1.5 font-medium',
      md: 'px-2.5 py-1 text-xs gap-2 font-semibold tracking-wide',
      lg: 'px-3.5 py-1.5 text-sm gap-2.5 font-bold',
    }[size];

    return (
      <span
        className={cn(
          'inline-flex items-center rounded-lg border font-mono uppercase transition-colors',
          config.style,
          sizeClasses
        )}
      >
        <Icon className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />
        {config.label}
      </span>
    );
  }

  if (severity) {
    const config = {
      [FindingSeverityEnum.CRITICAL]:
        'bg-rose-50 text-rose-700 border-rose-200 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800',
      [FindingSeverityEnum.HIGH]:
        'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-800',
      [FindingSeverityEnum.MEDIUM]:
        'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-950/50 dark:text-amber-300 dark:border-amber-800',
      [FindingSeverityEnum.LOW]:
        'bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/50 dark:text-sky-300 dark:border-sky-800',
      [FindingSeverityEnum.INFO]:
        'bg-slate-50 text-slate-600 border-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:border-slate-700',
    }[severity];

    return (
      <span
        className={cn(
          'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono uppercase font-semibold border',
          config
        )}
      >
        {severity}
      </span>
    );
  }

  return null;
};
