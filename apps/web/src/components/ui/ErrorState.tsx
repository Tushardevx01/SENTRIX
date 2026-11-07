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
    <div className="bg-theme-danger/10 border border-theme-danger/30 rounded-xl p-6 text-center max-w-lg mx-auto my-6">
      <AlertTriangle className="w-9 h-9 text-theme-danger mx-auto mb-3" />
      <h3 className="text-base font-bold text-theme-text font-mono">{title}</h3>
      <p className="mt-1 text-xs text-theme-muted font-mono leading-relaxed">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-4 inline-flex items-center gap-2 px-4 py-2 bg-theme-elevated hover:bg-theme-border border border-theme-border text-theme-text rounded-lg text-xs font-mono font-medium transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Retry Request
        </button>
      )}
    </div>
  );
};
