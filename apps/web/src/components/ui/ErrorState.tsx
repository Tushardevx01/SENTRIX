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
    <div className="bg-red-950/30 border border-red-500/40 rounded-xl p-6 text-center max-w-lg mx-auto my-6">
      <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
      <h3 className="text-base font-semibold text-red-200">{title}</h3>
      <p className="mt-1 text-sm text-slate-300 font-mono leading-relaxed">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-red-900/50 hover:bg-red-900/80 border border-red-700 text-red-200 rounded-lg text-sm font-medium transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Retry Request
        </button>
      )}
    </div>
  );
};
