import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { VerdictEnum, type Verdict, FindingSeverityEnum, type FindingSeverity } from '@sentrix/shared';

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
        bg: 'bg-emerald-950/60 border-emerald-500/40 text-emerald-400',
        icon: ShieldCheck,
      },
      [VerdictEnum.SUSPICIOUS]: {
        label: 'SUSPICIOUS / ELEVATED RISK',
        bg: 'bg-amber-950/60 border-amber-500/40 text-amber-400',
        icon: AlertTriangle,
      },
      [VerdictEnum.MALICIOUS]: {
        label: 'MALICIOUS / HIGH THREAT',
        bg: 'bg-red-950/60 border-red-500/50 text-red-400 shadow-glow-red',
        icon: ShieldAlert,
      },
    }[verdict] || {
      label: verdict,
      bg: 'bg-slate-800 border-slate-700 text-slate-300',
      icon: AlertCircle,
    };

    const Icon = config.icon;
    const sizeClasses = {
      sm: 'px-2 py-0.5 text-xs gap-1.5',
      md: 'px-3 py-1 text-xs gap-2 tracking-wide font-semibold',
      lg: 'px-4 py-1.5 text-sm gap-2.5 font-bold',
    }[size];

    return (
      <span
        className={cn(
          'inline-flex items-center rounded-md border font-mono uppercase transition-all',
          config.bg,
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
      [FindingSeverityEnum.CRITICAL]: 'bg-red-950/70 border-red-500 text-red-300',
      [FindingSeverityEnum.HIGH]: 'bg-rose-950/50 border-rose-500/50 text-rose-400',
      [FindingSeverityEnum.MEDIUM]: 'bg-amber-950/50 border-amber-500/40 text-amber-300',
      [FindingSeverityEnum.LOW]: 'bg-sky-950/40 border-sky-500/30 text-sky-300',
      [FindingSeverityEnum.INFO]: 'bg-slate-800/60 border-slate-700 text-slate-400',
    }[severity];

    return (
      <span
        className={cn(
          'inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono uppercase font-medium border',
          config
        )}
      >
        {severity}
      </span>
    );
  }

  return null;
};
