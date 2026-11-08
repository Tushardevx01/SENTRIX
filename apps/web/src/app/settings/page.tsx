'use client';

import React, { useState } from 'react';
import {
  Settings,
  Sun,
  Moon,
  Shield,
  CheckCircle2,
  Terminal,
  Save,
} from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();

  // Settings State
  const [analystName, setAnalystName] = useState('Senior Security Analyst');
  const [analystEmail, setAnalystEmail] = useState('analyst@sentrix.internal');
  const [strictZeroTrust, setStrictZeroTrust] = useState(true);
  const [sessionTimeout, setSessionTimeout] = useState('30m');
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-8 py-2 max-w-4xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <Settings className="w-3.5 h-3.5" />
            <span>[ CONFIG // PLATFORM SETTINGS ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Platform Configuration
          </h1>
          <p className="text-xs text-neutral-500 font-mono max-w-2xl">
            Manage visual appearance, alert thresholds, security policies, and session controls.
          </p>
        </div>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Appearance & Theme Selector */}
        <div className="p-6 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
            <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
              <Sun className="w-4 h-4" />
              // 01. APPEARANCE & THEME (MINIMAL BLACK & WHITE)
            </span>
            <span className="text-[10px] text-neutral-500 font-pixel">UI_STYLE</span>
          </div>

          <div>
            <label className="block text-xs font-semibold text-neutral-700 dark:text-neutral-300 mb-3">
              Theme Mode
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Light Theme Option */}
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                  theme === 'light'
                    ? 'border-black dark:border-white bg-neutral-100 dark:bg-[#18181b]'
                    : 'border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-neutral-500'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Sun className="w-4 h-4 text-black dark:text-white" />
                    <span className="text-xs font-bold text-black dark:text-white">Minimal Light Theme</span>
                  </div>
                  {theme === 'light' && <CheckCircle2 className="w-4 h-4 text-black dark:text-white" />}
                </div>
                <p className="text-[11px] text-neutral-500 leading-relaxed font-sans">
                  Stark high-contrast clean white and dark gray minimal aesthetic.
                </p>
              </button>

              {/* Dark Theme Option */}
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`p-4 rounded-xl border text-left transition-all cursor-pointer ${
                  theme === 'dark'
                    ? 'border-black dark:border-white bg-neutral-100 dark:bg-[#18181b]'
                    : 'border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-neutral-500'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Moon className="w-4 h-4 text-black dark:text-white" />
                    <span className="text-xs font-bold text-black dark:text-white">Industrial Void Dark</span>
                  </div>
                  {theme === 'dark' && <CheckCircle2 className="w-4 h-4 text-black dark:text-white" />}
                </div>
                <p className="text-[11px] text-neutral-500 leading-relaxed font-sans">
                  Deep pure black industrial cybersecurity console with white typography.
                </p>
              </button>
            </div>
          </div>
        </div>

        {/* Security Policies */}
        <div className="p-6 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-neutral-200 dark:border-[#1f1f23]">
            <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
              <Shield className="w-4 h-4" />
              // 02. ZERO-TRUST PERIMETER INVARIANTS
            </span>
            <span className="text-[10px] text-neutral-500 font-pixel">POLICIES</span>
          </div>

          <div className="space-y-3">
            <label className="flex items-center justify-between p-3 rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] cursor-pointer">
              <div className="space-y-0.5">
                <span className="font-semibold text-black dark:text-white block">
                  Strict Zero-Trust Downgrade (Fail-Safe)
                </span>
                <span className="text-[11px] text-neutral-500 block font-sans">
                  Unreachable analyzers automatically mark candidate scans as INCONCLUSIVE.
                </span>
              </div>
              <input
                type="checkbox"
                checked={strictZeroTrust}
                onChange={(e) => setStrictZeroTrust(e.target.checked)}
                className="w-4 h-4 rounded text-black focus:ring-0 cursor-pointer"
              />
            </label>
          </div>
        </div>

        {/* Save Actions */}
        <div className="flex items-center justify-between pt-2">
          {saved ? (
            <span className="text-emerald-600 dark:text-emerald-400 font-bold flex items-center gap-1.5">
              <CheckCircle2 className="w-4 h-4" /> Configuration changes saved.
            </span>
          ) : (
            <span className="text-neutral-400">Settings persist to browser local storage.</span>
          )}

          {/* Normal dark gray button with white button text */}
          <button
            type="submit"
            className="btn-industrial py-2.5 px-6 rounded-full text-xs font-semibold cursor-pointer"
          >
            <Save className="w-3.5 h-3.5 text-white" />
            <span>Save Settings</span>
          </button>
        </div>
      </form>
    </div>
  );
}
