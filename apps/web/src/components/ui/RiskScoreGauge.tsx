import React from 'react';
import { cn } from '@/lib/utils';
import { VerdictEnum, type Verdict } from '@sentrix/shared';

interface RiskScoreGaugeProps {
  score: number;
  verdict: Verdict;
  confidence?: number;
  size?: number;
}

export const RiskScoreGauge: React.FC<RiskScoreGaugeProps> = ({
  score,
  verdict,
  confidence = 90,
  size = 180,
}) => {
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progressOffset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;

  let strokeColor = '#10B981'; // Green
  let glowColor = 'rgba(16, 185, 129, 0.3)';

  if (verdict === VerdictEnum.INCONCLUSIVE) {
    strokeColor = '#94A3B8'; // Slate/Zinc
    glowColor = 'rgba(148, 163, 184, 0.25)';
  } else if (verdict === VerdictEnum.MALICIOUS || score >= 70) {
    strokeColor = '#EF4444'; // Red
    glowColor = 'rgba(239, 68, 68, 0.4)';
  } else if (verdict === VerdictEnum.SUSPICIOUS || score > 25) {
    strokeColor = '#F59E0B'; // Amber
    glowColor = 'rgba(245, 158, 11, 0.3)';
  }

  return (
    <div className="flex flex-col items-center justify-center p-4">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        {/* Glow backdrop */}
        <div
          className="absolute inset-4 rounded-full blur-xl opacity-50"
          style={{ background: glowColor }}
        />

        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            fill="none"
          />
          {/* Active Meter */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={progressOffset}
            strokeLinecap="round"
            fill="none"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-extrabold font-mono tracking-tight text-white">
            {score}
          </span>
          <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400">
            / 100 Risk
          </span>
        </div>
      </div>

      <div className="mt-3 text-center">
        <p className="text-xs font-mono text-slate-400">
          Confidence Rating: <span className="text-white font-semibold">{confidence}%</span>
        </p>
      </div>
    </div>
  );
};
