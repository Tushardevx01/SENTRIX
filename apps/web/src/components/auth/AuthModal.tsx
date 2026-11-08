'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, Mail, User, X, CheckCircle2, AlertTriangle, ArrowRight, KeyRound, Github } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';

export const AuthModal: React.FC = () => {
  const { isAuthModalOpen, closeAuthModal, authModalMode, login, register } = useAuth();
  const [mode, setMode] = useState<'login' | 'register'>(authModalMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  React.useEffect(() => {
    setMode(authModalMode);
    setError(null);
    setSuccess(null);
  }, [authModalMode, isAuthModalOpen]);

  if (!isAuthModalOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    try {
      if (mode === 'register') {
        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters long');
        }
        await register(email, password, name);
        setSuccess('Account created and authenticated successfully!');
      } else {
        await login(email, password);
        setSuccess('Authentication successful. Welcome back!');
      }
    } catch (err: any) {
      setError(err?.message || 'Authentication failed. Please verify credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthSignIn = async (provider: 'google' | 'github') => {
    setError(null);
    setLoading(true);
    try {
      // Direct mock OAuth federated sign in
      const mockEmail = provider === 'google' ? 'analyst@gmail.com' : 'security-researcher@github.com';
      await login(mockEmail, 'ThreatOps@2026!Secured').catch(() => {
        // If account doesn't exist, register and login
        return register(mockEmail, 'ThreatOps@2026!Secured', provider === 'google' ? 'Google Analyst' : 'GitHub Researcher');
      });
      setSuccess(`Signed in with ${provider === 'google' ? 'Google' : 'GitHub'}!`);
    } catch (err: any) {
      setError(`Failed to sign in with ${provider}`);
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
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 overflow-y-auto">
        {/* Backdrop */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={closeAuthModal}
          className="fixed inset-0 bg-black/70 backdrop-blur-md transition-opacity"
        />

        {/* Modal Dialog */}
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          className="relative w-full max-w-md card-floating p-6 sm:p-8 z-10 space-y-5"
        >
          {/* Close button */}
          <button
            onClick={closeAuthModal}
            type="button"
            className="absolute top-5 right-5 p-1.5 rounded-full text-neutral-400 hover:text-black dark:hover:text-white hover:bg-neutral-100 dark:hover:bg-[#18181b] transition-colors cursor-pointer"
          >
            <X className="w-4 h-4" />
          </button>

          {/* Header */}
          <div className="text-center space-y-1.5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a] text-[11px] font-mono text-neutral-700 dark:text-neutral-300">
              <Shield className="w-3.5 h-3.5 text-cyan-500" />
              <span>SENTRIX IDENTITY GATE</span>
            </div>

            <h2 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
              {mode === 'register' ? 'Create Your Account' : 'Welcome to SENTRIX'}
            </h2>
            <p className="text-xs text-neutral-500 font-sans max-w-xs mx-auto">
              Sign in to unlock full forensic reports, X.509 certificate trust tree, audit history, and PDF exports.
            </p>
          </div>

          {/* Tab Switcher */}
          <div className="flex p-1 rounded-xl bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a]">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`flex-1 py-1.5 text-xs font-mono font-medium rounded-lg transition-all cursor-pointer ${
                mode === 'login'
                  ? 'bg-white dark:bg-[#27272a] text-black dark:text-white shadow-xs font-bold'
                  : 'text-neutral-500 hover:text-black dark:hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`flex-1 py-1.5 text-xs font-mono font-medium rounded-lg transition-all cursor-pointer ${
                mode === 'register'
                  ? 'bg-white dark:bg-[#27272a] text-black dark:text-white shadow-xs font-bold'
                  : 'text-neutral-500 hover:text-black dark:hover:text-white'
              }`}
            >
              Sign Up
            </button>
          </div>

          {/* OAuth Buttons: Google & GitHub */}
          <div className="grid grid-cols-2 gap-2.5 pt-1">
            <button
              type="button"
              disabled={loading}
              onClick={() => handleOAuthSignIn('google')}
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
              onClick={() => handleOAuthSignIn('github')}
              className="flex items-center justify-center gap-2 py-2 px-3 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] hover:bg-neutral-100 dark:hover:bg-[#18181b] text-xs font-mono font-medium text-black dark:text-white transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <Github className="w-4 h-4 text-black dark:text-white" />
              <span>GitHub</span>
            </button>
          </div>

          {/* Divider */}
          <div className="relative flex items-center justify-center">
            <div className="border-t border-neutral-200 dark:border-[#1f1f23] w-full" />
            <span className="bg-white dark:bg-[#0c0c0e] px-2 text-[10px] font-mono text-neutral-400 uppercase tracking-widest shrink-0">
              OR CONTINUE WITH EMAIL
            </span>
          </div>

          {/* Feedback */}
          {error && (
            <div className="flex items-start gap-2 p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-xs font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="flex items-start gap-2 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-600 dark:text-emerald-400 text-xs font-mono">
              <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
              <span>{success}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-3.5">
            {mode === 'register' && (
              <div className="space-y-1">
                <label className="text-[10px] font-mono uppercase tracking-wider text-neutral-500 block">
                  Full Name
                </label>
                <div className="relative">
                  <User className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Analyst Name"
                    className="w-full pl-9 pr-3 py-1.5 text-xs font-mono rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
                  />
                </div>
              </div>
            )}

            <div className="space-y-1">
              <label className="text-[10px] font-mono uppercase tracking-wider text-neutral-500 block">
                Work Email
              </label>
              <div className="relative">
                <Mail className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@domain.com"
                  className="w-full pl-9 pr-3 py-1.5 text-xs font-mono rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-[10px] font-mono uppercase tracking-wider text-neutral-500 block">
                Password
              </label>
              <div className="relative">
                <Lock className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-1.5 text-xs font-mono rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 rounded-lg bg-black dark:bg-white text-white dark:text-black text-xs font-mono font-bold hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors flex items-center justify-center gap-2 disabled:opacity-60 cursor-pointer shadow-md"
            >
              <span>{loading ? 'Authenticating...' : mode === 'register' ? 'Sign Up & Continue' : 'Sign In to SENTRIX'}</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </form>

          {/* Quick Demo Credentials Fill */}
          {mode === 'login' && (
            <div className="pt-2 border-t border-neutral-200 dark:border-[#1f1f23] text-center">
              <button
                type="button"
                onClick={handleQuickDemoFill}
                className="inline-flex items-center gap-1.5 text-[11px] font-mono text-neutral-500 hover:text-black dark:hover:text-white transition-colors underline cursor-pointer"
              >
                <KeyRound className="w-3.5 h-3.5 text-amber-500" />
                <span>Fill Demo Analyst Credentials</span>
              </button>
            </div>
          )}
        </motion.div>
      </div>
    </AnimatePresence>
  );
};
