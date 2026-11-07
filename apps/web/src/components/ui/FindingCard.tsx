'use client';

import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Code2, AlertCircle } from 'lucide-react';
import { RiskBadge } from './RiskBadge';
import { type IFinding } from '@sentrix/shared';

interface FindingCardProps {
  finding: IFinding;
}

export const FindingCard: React.FC<FindingCardProps> = ({ finding }) => {
  const [showEvidence, setShowEvidence] = useState(false);
  const hasEvidence = finding.evidence && Object.keys(finding.evidence).length > 0;

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-lg p-4 transition-all hover:border-slate-700">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <RiskBadge severity={finding.severity} />
          <span className="text-xs font-mono uppercase text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
            {finding.category.replace(/_/g, ' ')}
          </span>
        </div>
        <span className="text-xs font-mono text-slate-500">
          Confidence: {Math.round(finding.confidence)}%
        </span>
      </div>

      <h4 className="mt-2 text-base font-semibold text-slate-100">{finding.title}</h4>
      <p className="mt-1 text-sm text-slate-300 leading-relaxed">{finding.description}</p>

      {hasEvidence && (
        <div className="mt-3 pt-3 border-t border-slate-800/60">
          <button
            onClick={() => setShowEvidence(!showEvidence)}
            className="flex items-center gap-1.5 text-xs font-mono text-electric-400 hover:text-electric-300 transition-colors"
          >
            <Code2 className="w-3.5 h-3.5" />
            {showEvidence ? 'Hide Forensic Evidence' : 'Inspect Forensic Evidence'}
            {showEvidence ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>

          {showEvidence && (
            <pre className="mt-2 p-3 bg-slate-950/80 border border-slate-800 rounded font-mono text-xs text-electric-300 overflow-x-auto">
              {JSON.stringify(finding.evidence, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};
