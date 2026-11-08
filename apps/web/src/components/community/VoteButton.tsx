'use client';

import React, { useState } from 'react';
import { ThumbsUp, ThumbsDown, Loader2 } from 'lucide-react';

export interface VoteButtonProps {
  reportId?: string;
  initialUpvotes: number;
  initialDownvotes: number;
  onVote: (vote: 'CONFIRM_PHISHING' | 'LEGITIMATE') => Promise<void> | void;
  disabled?: boolean;
}

export const VoteButton: React.FC<VoteButtonProps> = ({
  initialUpvotes,
  initialDownvotes,
  onVote,
  disabled = false,
}) => {
  const [upvotes, setUpvotes] = useState(initialUpvotes);
  const [downvotes, setDownvotes] = useState(initialDownvotes);
  const [voted, setVoted] = useState<'CONFIRM_PHISHING' | 'LEGITIMATE' | null>(null);
  const [loading, setLoading] = useState(false);

  const handleVote = async (type: 'CONFIRM_PHISHING' | 'LEGITIMATE') => {
    if (voted || loading || disabled) return;
    setLoading(true);
    try {
      await onVote(type);
      setVoted(type);
      if (type === 'CONFIRM_PHISHING') {
        setUpvotes((prev) => prev + 1);
      } else {
        setDownvotes((prev) => prev + 1);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="inline-flex items-center gap-1 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 p-1">
      <button
        onClick={() => handleVote('CONFIRM_PHISHING')}
        disabled={!!voted || loading || disabled}
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
          voted === 'CONFIRM_PHISHING'
            ? 'bg-rose-500 text-white'
            : 'text-slate-600 dark:text-slate-400 hover:text-rose-500 hover:bg-white dark:hover:bg-slate-800'
        } disabled:opacity-50`}
        title="Confirm Threat / Malicious"
      >
        {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ThumbsUp className="w-3.5 h-3.5" />}
        <span>{upvotes}</span>
      </button>
      <div className="w-[1px] h-4 bg-slate-200 dark:bg-slate-800" />
      <button
        onClick={() => handleVote('LEGITIMATE')}
        disabled={!!voted || loading || disabled}
        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
          voted === 'LEGITIMATE'
            ? 'bg-emerald-500 text-white'
            : 'text-slate-600 dark:text-slate-400 hover:text-emerald-500 hover:bg-white dark:hover:bg-slate-800'
        } disabled:opacity-50`}
        title="Mark as Benign / Legitimate"
      >
        <ThumbsDown className="w-3.5 h-3.5" />
        <span>{downvotes}</span>
      </button>
    </div>
  );
};
