'use client';

import React, { useState } from 'react';
import { Search, Loader2, ShieldAlert } from 'lucide-react';

export interface ScanSubmitBarProps {
  onScan: (url: string, deepScan: boolean) => Promise<void> | void;
  isLoading?: boolean;
  placeholder?: string;
}

export const ScanSubmitBar: React.FC<ScanSubmitBarProps> = ({
  onScan,
  isLoading = false,
  placeholder = 'Enter URL to analyze (e.g. https://suspicious-login.com)...',
}) => {
  const [url, setUrl] = useState('');
  const [deepScan, setDeepScan] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please provide a URL to scan.');
      return;
    }
    setError(null);
    onScan(trimmed, deepScan);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center gap-2 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-2 shadow-sm focus-within:ring-2 focus-within:ring-primary-500/20 focus-within:border-primary-500">
        <div className="relative flex-1 flex items-center pl-3">
          <Search className="w-5 h-5 text-slate-400 dark:text-slate-500 shrink-0 mr-2" />
          <input
            type="text"
            value={url}
            onChange={(e) => {
              setUrl(e.target.value);
              if (error) setError(null);
            }}
            placeholder={placeholder}
            disabled={isLoading}
            className="w-full bg-transparent py-2.5 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none disabled:opacity-50"
          />
        </div>
        <div className="flex items-center gap-3 px-3 py-1 sm:py-0 border-t sm:border-t-0 sm:border-l border-slate-100 dark:border-slate-800">
          <label className="flex items-center gap-2 cursor-pointer select-none text-xs font-medium text-slate-600 dark:text-slate-400">
            <input
              type="checkbox"
              checked={deepScan}
              onChange={(e) => setDeepScan(e.target.checked)}
              disabled={isLoading}
              className="rounded border-slate-300 text-primary-600 focus:ring-primary-500 dark:border-slate-700 dark:bg-slate-800"
            />
            Deep Scan
          </label>
          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-primary-600 hover:bg-primary-500 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition disabled:opacity-50 disabled:cursor-not-allowed shrink-0"
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Scanning...
              </>
            ) : (
              'Analyze Target'
            )}
          </button>
        </div>
      </div>
      {error && (
        <div className="mt-2 flex items-center gap-1.5 text-xs text-rose-500 font-medium pl-2">
          <ShieldAlert className="w-4 h-4" />
          {error}
        </div>
      )}
    </form>
  );
};
