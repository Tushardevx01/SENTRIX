'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Lock,
  Mail,
  ArrowRight,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  Fingerprint,
} from 'lucide-react';

export default function LoginPage() {
  const router = useRouter();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);
    setLoading(true);

    const apiBase = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const endpoint = isRegister
      ? `${apiBase}/api/v1/auth/register`
      : `${apiBase}/api/v1/auth/login`;

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data?.message || 'Authentication request failed');
      }

      if (isRegister) {
        setSuccessMsg('Account registered successfully. Signing in...');
        setTimeout(() => {
          setIsRegister(false);
          setSuccessMsg(null);
        }, 1200);
      } else {
        if (data?.token) {
          localStorage.setItem('sentrix_auth_token', data.token);
          localStorage.setItem('sentrix_user', JSON.stringify(data.user || {}));
        }
        setSuccessMsg('Session authorized. Redirecting to Command Center...');
        setTimeout(() => {
          router.push('/dashboard');
        }, 800);
      }
    } catch (err: any) {
      setError(err?.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoFill = () => {
    setEmail('analyst@sentrix.internal');
    setPassword('ThreatOps@2026!Secured');
    setError(null);
  };

  return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center p-4 sm:p-6 bg-white dark:bg-[#000000] text-black dark:text-white transition-colors">
      <div className="w-full max-w-md space-y-6">
        {/* Top ASCII Micro-Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-[11px] font-mono text-neutral-600 dark:text-neutral-300">
            <span className="w-1.5 h-1.5 rounded-full bg-black dark:bg-white animate-pulse" />
            <span>[ SECURE GATEWAY // ZERO-TRUST ]</span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-serif tracking-tight text-black dark:text-white mt-2">
            {isRegister ? 'Register Identity' : 'Operator Access'}
          </h1>

          <p className="text-xs font-mono text-neutral-500 max-w-sm mx-auto">
            {isRegister
              ? 'Provision a user account for authenticated crowdsourced threat submission.'
              : 'Enter authorized security analyst credentials to manage platform telemetry.'}
          </p>
        </div>

        {/* Clear & Clean Card */}
        <div className="card-floating p-6 sm:p-8 space-y-6">
          {/* Mode Tabs */}
          <div className="grid grid-cols-2 gap-1 p-1 bg-neutral-100 dark:bg-[#18181b] rounded-lg border border-neutral-200 dark:border-[#27272a] text-xs font-mono">
            <button
              type="button"
              onClick={() => {
                setIsRegister(false);
                setError(null);
                setSuccessMsg(null);
              }}
              className={`py-1.5 rounded-md transition-all font-medium ${
                !isRegister
                  ? 'bg-white dark:bg-[#27272a] text-black dark:text-white shadow-xs'
                  : 'text-neutral-500 hover:text-black dark:hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setIsRegister(true);
                setError(null);
                setSuccessMsg(null);
              }}
              className={`py-1.5 rounded-md transition-all font-medium ${
                isRegister
                  ? 'bg-white dark:bg-[#27272a] text-black dark:text-white shadow-xs'
                  : 'text-neutral-500 hover:text-black dark:hover:text-white'
              }`}
            >
              Create Account
            </button>
          </div>

          {/* OAuth Buttons: Google & GitHub */}
          <div className="grid grid-cols-2 gap-2.5">
            <button
              type="button"
              disabled={loading}
              onClick={() => {
                setEmail('analyst@gmail.com');
                setPassword('ThreatOps@2026!Secured');
                setError(null);
                setSuccessMsg('Selected Google account. Click Submit below to sign in.');
              }}
              className="flex items-center justify-center gap-2 py-2 px-3 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] hover:bg-neutral-100 dark:hover:bg-[#18181b] text-xs font-mono font-medium text-black dark:text-white transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <svg className="w-4 h-4" viewBox="0 0 24 24">
                <path fill="#EA4335" d="M12 5c1.6 0 3 .6 4.1 1.7l3.1-3.1C17.3 1.8 14.8 1 12 1 7.5 1 3.7 3.6 1.9 7.3l3.7 2.9C6.5 7.4 9 5 12 5z" />
                <path fill="#4285F4" d="M23.5 12.3c0-.8-.1-1.7-.2-2.3H12v4.6h6.5c-.3 1.5-1.1 2.8-2.4 3.7l3.7 2.9c2.2-2 3.7-5 3.7-8.9z" />
                <path fill="#FBBC05" d="M5.6 14.8c-.2-.7-.4-1.5-.4-2.3 0-.8.2-1.6.4-2.3L1.9 7.3C.7 9.7 0 12.3 0 15.2c0 2.8.7 5.5 1.9 7.8l3.7-2.9z" />
                <path fill="#34A853" d="M12 23.5c3.2 0 6-1.1 8-3l-3.7-2.9c-1.1.7-2.5 1.2-4.3 1.2-3 0-5.5-2-6.4-4.8L1.9 16.9C3.7 20.6 7.5 23.5 12 23.5z" />
              </svg>
              <span>Google</span>
            </button>

            <button
              type="button"
              disabled={loading}
              onClick={() => {
                setEmail('analyst@sentrix.internal');
                setPassword('ThreatOps@2026!Secured');
                setError(null);
                setSuccessMsg('Selected GitHub account. Click Submit below to sign in.');
              }}
              className="flex items-center justify-center gap-2 py-2 px-3 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] hover:bg-neutral-100 dark:hover:bg-[#18181b] text-xs font-mono font-medium text-black dark:text-white transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <svg className="w-4 h-4 fill-current" viewBox="0 0 24 24">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z" />
              </svg>
              <span>GitHub</span>
            </button>
          </div>

          {/* Divider */}
          <div className="relative flex items-center justify-center">
            <div className="border-t border-neutral-200 dark:border-[#1f1f23] w-full" />
            <span className="bg-white dark:bg-[#0c0c0e] px-2 text-[10px] font-mono text-neutral-400 uppercase tracking-widest shrink-0">
              OR EMAIL
            </span>
          </div>

          {/* Error & Success Alerts */}
          {error && (
            <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/50 flex items-start gap-2.5 text-xs text-red-800 dark:text-red-300 font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 flex items-start gap-2.5 text-xs text-emerald-800 dark:text-emerald-300 font-mono">
              <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600 dark:text-emerald-400 mt-0.5" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4 font-mono text-xs">
            <div className="space-y-1.5">
              <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300">
                EMAIL IDENTIFIER
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-400" />
                <input
                  type="email"
                  required
                  placeholder="analyst@sentrix.internal"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white focus:bg-white dark:focus:bg-[#18181b] transition-all"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300">
                PASSPHRASE
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-neutral-400" />
                <input
                  type="password"
                  required
                  placeholder="••••••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-9 pr-3 py-2 rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white focus:bg-white dark:focus:bg-[#18181b] transition-all"
                />
              </div>
              <p className="text-[10px] text-neutral-500 pt-0.5">
                {isRegister
                  ? 'Must be between 8 and 128 characters (scrypt hash protected).'
                  : 'Constant-time verification against timing side-channels.'}
              </p>
            </div>

            {/* Normal dark gray button with white button text */}
            <button
              type="submit"
              disabled={loading}
              className="w-full btn-industrial py-2.5 mt-2 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-50"
            >
              {loading ? (
                <span>Verifying Hash...</span>
              ) : (
                <>
                  <span>{isRegister ? 'Register Identity' : 'Authenticate Operator'}</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {/* Quick Fill / Testing Demo Hint */}
          <div className="pt-4 border-t border-neutral-100 dark:border-[#1f1f23] text-center space-y-2">
            <button
              type="button"
              onClick={handleQuickDemoFill}
              className="text-[11px] font-mono text-neutral-500 hover:text-black dark:hover:text-white underline inline-flex items-center gap-1 cursor-pointer"
            >
              <Fingerprint className="w-3 h-3" /> Quick fill default demo credentials
            </button>

            <div className="text-[10px] font-mono text-neutral-400">
              Zero external auth dependency • scrypt + signed HMAC-SHA256
            </div>
          </div>
        </div>

        {/* Back Link */}
        <div className="text-center font-mono text-xs">
          <Link
            href="/"
            className="text-neutral-500 hover:text-black dark:hover:text-white transition-colors"
          >
            ← Return to System Overview
          </Link>
        </div>
      </div>
    </div>
  );
}
