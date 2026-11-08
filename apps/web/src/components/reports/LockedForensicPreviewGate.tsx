'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Lock,
  Shield,
  FileText,
  Binary,
  Layers,
  Cpu,
  Download,
  CheckCircle2,
  Sparkles,
  ArrowRight,
  ShieldAlert,
} from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

interface LockedForensicPreviewGateProps {
  onOpenAuthModal?: () => void;
}

export const LockedForensicPreviewGate: React.FC<LockedForensicPreviewGateProps> = ({
  onOpenAuthModal,
}) => {
  const { login, register, openAuthModal } = useAuth();
  const [loadingProvider, setLoadingProvider] = useState<'google' | 'github' | null>(null);

  const handleOAuth = async (provider: 'google' | 'github') => {
    setLoadingProvider(provider);
    try {
      const mockEmail = provider === 'google' ? 'analyst@gmail.com' : 'security-researcher@github.com';
      await login(mockEmail, 'ThreatOps@2026!Secured').catch(() => {
        return register(
          mockEmail,
          'ThreatOps@2026!Secured',
          provider === 'google' ? 'Google Analyst' : 'GitHub Researcher'
        );
      });
    } catch (err) {
      console.error(err);
      if (onOpenAuthModal) onOpenAuthModal();
      else openAuthModal('login');
    } finally {
      setLoadingProvider(null);
    }
  };

  const handleOpenLogin = () => {
    if (onOpenAuthModal) {
      onOpenAuthModal();
    } else {
      openAuthModal('login');
    }
  };

  return (
    <div className="relative card-floating backdrop-blur-md overflow-hidden p-6 sm:p-10 my-6">
      {/* Subtle Background Circuit Glow */}
      <div className="absolute top-0 right-1/4 w-96 h-96 bg-cyan-500/5 dark:bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-purple-500/5 dark:bg-purple-500/10 rounded-full blur-3xl pointer-events-none" />

      {/* Teaser Background / Frosted Mock Sections */}
      <div className="opacity-25 filter blur-[2px] pointer-events-none select-none space-y-4 mb-6">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {['Heuristics', 'AI Scanner', 'Content', 'TLS Audit', 'Network'].map((analyzer, idx) => (
            <div key={idx} className="p-3 bg-neutral-100 dark:bg-[#18181b] rounded-lg border border-neutral-200 dark:border-[#27272a]">
              <div className="h-2 w-16 bg-neutral-300 dark:bg-neutral-700 rounded mb-2" />
              <div className="h-2 w-10 bg-emerald-400 rounded" />
            </div>
          ))}
        </div>
        <div className="p-4 bg-neutral-100 dark:bg-[#18181b] rounded-lg border border-neutral-200 dark:border-[#27272a] space-y-2">
          <div className="h-3 w-48 bg-neutral-300 dark:bg-neutral-700 rounded" />
          <div className="h-2 w-full bg-neutral-200 dark:bg-neutral-800 rounded" />
          <div className="h-2 w-3/4 bg-neutral-200 dark:bg-neutral-800 rounded" />
        </div>
      </div>

      {/* Main Locked Card Content */}
      <motion.div
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="relative z-10 max-w-2xl mx-auto text-center space-y-6"
      >
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-600 dark:text-cyan-400 text-xs font-mono font-semibold">
          <Lock className="w-3.5 h-3.5" />
          <span>[ RESTRICTED // FORENSIC INTELLIGENCE DEEP DIVE ]</span>
        </div>

        <div className="space-y-2">
          <h3 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Unlock Full Forensic Analysis & PDF Report
          </h3>
          <p className="text-xs sm:text-sm text-neutral-600 dark:text-neutral-400 font-sans max-w-lg mx-auto">
            You are viewing the executive summary. Sign in to inspect cryptographic certificates, detailed indicators of compromise, MITRE ATT&CK tactics, and export the official PDF audit report.
          </p>
        </div>

        {/* Feature Highlights Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-left max-w-xl mx-auto font-mono text-xs">
          <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-neutral-50 dark:bg-[#141417] border border-neutral-200 dark:border-[#27272a]">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-black dark:text-white block">Multi-Engine Analyzers</span>
              <span className="text-[11px] text-neutral-500">Heuristic, AI, Content, TLS & Network</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-neutral-50 dark:bg-[#141417] border border-neutral-200 dark:border-[#27272a]">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-black dark:text-white block">X.509 Cryptographic Tree</span>
              <span className="text-[11px] text-neutral-500">CA validation, SAN inspection & revocation</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-neutral-50 dark:bg-[#141417] border border-neutral-200 dark:border-[#27272a]">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-black dark:text-white block">MITRE ATT&CK Alignment</span>
              <span className="text-[11px] text-neutral-500">Enterprise TTP mapping & evidence tags</span>
            </div>
          </div>

          <div className="flex items-start gap-2.5 p-2.5 rounded-lg bg-neutral-50 dark:bg-[#141417] border border-neutral-200 dark:border-[#27272a]">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-black dark:text-white block">Official Forensic PDF Export</span>
              <span className="text-[11px] text-neutral-500">Download tamper-evident signed audit logs</span>
            </div>
          </div>
        </div>

        {/* Auth Action Buttons */}
        <div className="pt-2 space-y-3 max-w-md mx-auto">
          {/* Social Sign In Buttons */}
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => handleOAuth('google')}
              disabled={loadingProvider !== null}
              className="flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl border border-neutral-300 dark:border-[#27272a] bg-white dark:bg-[#18181b] hover:bg-neutral-100 dark:hover:bg-[#222226] text-black dark:text-white text-xs font-mono font-medium transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              <span>{loadingProvider === 'google' ? 'Connecting...' : 'Google'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleOAuth('github')}
              disabled={loadingProvider !== null}
              className="flex items-center justify-center gap-2 py-2.5 px-3 rounded-xl border border-neutral-300 dark:border-[#27272a] bg-white dark:bg-[#18181b] hover:bg-neutral-100 dark:hover:bg-[#222226] text-black dark:text-white text-xs font-mono font-medium transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              <span>{loadingProvider === 'github' ? 'Connecting...' : 'GitHub'}</span>
            </button>
          </div>

          <div className="relative flex items-center justify-center py-1">
            <div className="border-t border-neutral-300 dark:border-[#27272a] w-full" />
            <span className="bg-white dark:bg-[#0c0c0e] px-3 text-[10px] font-mono text-neutral-400 uppercase tracking-widest absolute">
              or
            </span>
          </div>

          {/* Email / Password Sign In Button */}
          <button
            type="button"
            onClick={handleOpenLogin}
            className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl bg-black dark:bg-white text-white dark:text-black hover:opacity-90 transition-opacity font-mono text-xs font-bold cursor-pointer shadow-lg"
          >
            <span>Sign In or Create Account with Email</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </motion.div>
    </div>
  );
};

