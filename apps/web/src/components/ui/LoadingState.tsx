import React from 'react';
import { Shield } from 'lucide-react';

interface LoadingStateProps {
  message?: string;
  subMessage?: string;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Scanning target destination...',
  subMessage = 'Executing security analyzers and aggregating threat intelligence',
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center">
      <div className="relative flex items-center justify-center mb-6">
        <div className="w-16 h-16 rounded-full border border-theme-accent/25 animate-ping absolute" />
        <div className="w-14 h-14 rounded-full border-2 border-theme-accent border-t-transparent animate-spin flex items-center justify-center">
          <Shield className="w-6 h-6 text-theme-accent animate-pulse" />
        </div>
      </div>
      <h3 className="text-base font-bold text-theme-text font-mono tracking-tight">{message}</h3>
      <p className="mt-1 text-xs text-theme-muted font-mono max-w-md">{subMessage}</p>
    </div>
  );
};
