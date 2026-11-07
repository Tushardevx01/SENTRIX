import React from 'react';
import { Shield, Radar } from 'lucide-react';

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
        <div className="w-20 h-20 rounded-full border border-electric-500/30 animate-ping absolute" />
        <div className="w-16 h-16 rounded-full border-2 border-electric-400 border-t-transparent animate-spin flex items-center justify-center">
          <Shield className="w-7 h-7 text-electric-400 animate-pulse" />
        </div>
      </div>
      <h3 className="text-lg font-semibold text-white tracking-wide">{message}</h3>
      <p className="mt-1 text-sm text-slate-400 font-mono max-w-md">{subMessage}</p>
    </div>
  );
};
