import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Security Operation Error',
  message,
  onRetry,
}) => {
  return (
    <div className="card-floating bg-white dark:bg-[#0c0c0e] border border-red-200 dark:border-red-900/50 rounded-panel p-8 text-center max-w-lg mx-auto my-8 space-y-3">
      <div className="w-12 h-12 rounded-2xl bg-red-100 dark:bg-red-950/60 border border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 flex items-center justify-center mx-auto">
        <AlertTriangle className="w-6 h-6" />
      </div>
      <h3 className="text-base sm:text-lg font-bold text-neutral-900 dark:text-neutral-100 font-serif">{title}</h3>
      <p className="text-xs text-neutral-600 dark:text-neutral-400 font-mono leading-relaxed">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn-industrial mt-3 px-5 py-2.5 rounded-full text-xs font-semibold cursor-pointer inline-flex items-center gap-2"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry Request
        </button>
      )}
    </div>
  );
};
