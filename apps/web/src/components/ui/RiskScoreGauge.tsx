'use client';

import React from 'react';
import { motion } from 'framer-motion';
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
  const clampedScore = Math.min(100, Math.max(0, score));
  const progressOffset = circumference - (clampedScore / 100) * circumference;

  let strokeColor = '#16A36A'; // Green
  let glowColor = 'rgba(22, 163, 106, 0.25)';

  if (verdict === VerdictEnum.INCONCLUSIVE) {
    strokeColor = '#94A3B8'; // Slate/Zinc
    glowColor = 'rgba(148, 163, 184, 0.2)';
  } else if (verdict === VerdictEnum.UNVERIFIED_INFRASTRUCTURE) {
    strokeColor = '#64748B'; // Slate
    glowColor = 'rgba(100, 116, 139, 0.25)';
  } else if (verdict === VerdictEnum.CONFIRMED_MALICIOUS || score >= 85) {
    strokeColor = '#DC2626'; // Deep Crimson Red
    glowColor = 'rgba(220, 38, 38, 0.4)';
  } else if (verdict === VerdictEnum.MALICIOUS || score >= 70) {
    strokeColor = '#E34E5B'; // Red
    glowColor = 'rgba(227, 78, 91, 0.3)';
  } else if (verdict === VerdictEnum.SUSPICIOUS || score > 25) {
    strokeColor = '#E99A32'; // Amber
    glowColor = 'rgba(233, 154, 50, 0.25)';
  }

  return (
    <div className="flex flex-col items-center justify-center p-2">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        {/* Glow backdrop */}
        <div
          className="absolute inset-4 rounded-full blur-xl opacity-40 transition-all"
          style={{ background: glowColor }}
        />

        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="var(--border-color)"
            strokeWidth={strokeWidth}
            fill="none"
          />
          {/* Active Meter with animated dashoffset */}
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={strokeColor}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: progressOffset }}
            transition={{ duration: 1.2, ease: 'easeOut' }}
            strokeLinecap="round"
            fill="none"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <motion.span
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="text-4xl font-black font-mono tracking-tight text-theme-text"
          >
            {clampedScore}
          </motion.span>
          <span className="text-[10px] uppercase font-mono tracking-widest text-theme-muted">
            / 100 Risk
          </span>
        </div>
      </div>

      <div className="mt-3 text-center">
        <span className="text-[11px] font-mono text-theme-muted block">
          Confidence: <strong className="text-theme-text">{Math.round(confidence)}%</strong>
        </span>
      </div>
    </div>
  );
};
