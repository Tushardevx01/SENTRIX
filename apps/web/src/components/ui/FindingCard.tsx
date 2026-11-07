'use client';

import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Code2 } from 'lucide-react';
import { RiskBadge } from './RiskBadge';
import { type IFinding } from '@sentrix/shared';

interface FindingCardProps {
  finding: IFinding;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding }) => {
  const [showEvidence, setShowEvidence] = useState(false);
  const hasEvidence = finding.evidence && Object.keys(finding.evidence).length > 0;

  return (
    <div className="bg-theme-card border border-theme-border rounded-xl p-4 transition-all hover:border-theme-accent/40 shadow-xs">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <RiskBadge severity={finding.severity} />
          <span className="text-xs font-mono uppercase text-theme-muted bg-theme-elevated px-2 py-0.5 rounded border border-theme-borderSubtle">
            {finding.category.replace(/_/g, ' ')}
          </span>
        </div>
        <span className="text-xs font-mono text-theme-muted">
          Confidence: <strong className="text-theme-text">{Math.round(finding.confidence)}%</strong>
        </span>
      </div>

      <h4 className="mt-2 text-sm font-bold text-theme-text font-mono">{finding.title}</h4>
      <p className="mt-1 text-xs text-theme-muted font-mono leading-relaxed">{finding.description}</p>

      {hasEvidence && (
        <div className="mt-3 pt-3 border-t border-theme-borderSubtle">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex items-center gap-1.5 text-xs font-mono text-theme-accent hover:underline transition-colors font-semibold"
          >
            <Code2 className="w-3.5 h-3.5" />
            <span>{showEvidence ? 'Hide Forensic Evidence' : 'Inspect Forensic Evidence'}</span>
            {showEvidence ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showEvidence && (
            <pre className="mt-2 p-3 bg-theme-elevated border border-theme-border rounded-lg font-mono text-xs text-theme-text overflow-x-auto">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};
