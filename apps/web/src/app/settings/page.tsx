'use client';

import React, { useState } from 'react';
import {
  Settings,
  User,
  Sun,
  Moon,
  Bell,
  Shield,
  Key,
  Database,
  CheckCircle2,
  Lock,
  Save,
  RotateCcw,
  Sparkles,
  Server,
  Layers,
} from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';
import { motion } from 'framer-motion';

export default function SettingsPage() {
  const { theme, setTheme } = useTheme();

  // Settings State
  const [analystName, setAnalystName] = useState('Senior Security Analyst');
  const [analystEmail, setAnalystEmail] = useState('analyst@sentrix.internal');
  const [alertEmail, setAlertEmail] = useState(true);
  const [slackWebhook, setSlackWebhook] = useState(false);
  const [strictZeroTrust, setStrictZeroTrust] = useState(true);
  const [sessionTimeout, setSessionTimeout] = useState('30m');
  const [saved, setSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setSaved(true);
    setTimeout(() => setSaved(false), 2500);
  };

  return (
    <div className="space-y-8 py-2 max-w-4xl mx-auto">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
          <Settings className="w-3.5 h-3.5" />
          <span>Platform Configuration</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
          PLATFORM & ANALYST SETTINGS
        </h1>
        <p className="text-xs text-theme-muted font-mono max-w-2xl">
          Manage visual appearance, alert thresholds, security policies, and session controls.
        </p>
      </div>

      <form onSubmit={handleSave} className="space-y-6">
        {/* Appearance & Theme Selector */}
        <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-theme-borderSubtle">
            <Sun className="w-4 h-4 text-theme-accent" />
            <h3 className="text-sm font-bold font-mono text-theme-text">APPEARANCE & THEME</h3>
          </div>

          <div>
            <label className="block text-xs font-mono font-semibold text-theme-text mb-3">
              Theme Mode (Light Mode is Default)
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Light Theme Option */}
              <button
                type="button"
                onClick={() => setTheme('light')}
                className={`p-4 rounded-xl border text-left transition-all ${
                  theme === 'light'
                    ? 'border-theme-accent bg-theme-accent/5 ring-2 ring-theme-accent/20'
                    : 'border-theme-border bg-theme-elevated/40 hover:border-theme-muted'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Sun className="w-4 h-4 text-amber-500" />
                    <span className="text-xs font-bold font-mono text-theme-text">Light Theme</span>
                  </div>
                  {theme === 'light' && <CheckCircle2 className="w-4 h-4 text-theme-accent" />}
                </div>
                <p className="text-[11px] font-mono text-theme-muted">
                  Clean, high-contrast white aesthetic optimized for daytime SOC environments.
                </p>
              </button>

              {/* Dark Theme Option */}
              <button
                type="button"
                onClick={() => setTheme('dark')}
                className={`p-4 rounded-xl border text-left transition-all ${
                  theme === 'dark'
                    ? 'border-theme-accent bg-theme-accent/5 ring-2 ring-theme-accent/20'
                    : 'border-theme-border bg-theme-elevated/40 hover:border-theme-muted'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Moon className="w-4 h-4 text-theme-accent" />
                    <span className="text-xs font-bold font-mono text-theme-text">Dark Theme</span>
                  </div>
                  {theme === 'dark' && <CheckCircle2 className="w-4 h-4 text-theme-accent" />}
                </div>
                <p className="text-[11px] font-mono text-theme-muted">
                  Technical, low-fatigue cybersecurity aesthetic with electric accents.
                </p>
              </button>
            </div>
          </div>
        </div>

        {/* Analyst Profile */}
        <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-theme-borderSubtle">
            <User className="w-4 h-4 text-theme-accent" />
            <h3 className="text-sm font-bold font-mono text-theme-text">OPERATOR PROFILE</h3>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
            <div>
              <label className="block text-theme-text font-semibold mb-1">Display Name</label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-theme-text focus:outline-none focus:border-theme-accent"
              />
            </div>
            <div>
              <label className="block text-theme-text font-semibold mb-1">Analyst Email</label>
              <input
                type="email"
                value={analystEmail}
                onChange={(e) => setAnalystEmail(e.target.value)}
                className="w-full bg-theme-bg border border-theme-border rounded-lg p-2.5 text-theme-text focus:outline-none focus:border-theme-accent"
              />
            </div>
          </div>
        </div>

        {/* Alert Notifications */}
        <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-theme-borderSubtle">
            <Bell className="w-4 h-4 text-theme-accent" />
            <h3 className="text-sm font-bold font-mono text-theme-text">ALERTING & NOTIFICATIONS</h3>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <label className="flex items-start gap-3 p-3 bg-theme-elevated rounded-lg cursor-pointer">
              <input
                type="checkbox"
                checked={alertEmail}
                onChange={(e) => setAlertEmail(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-theme-border text-theme-accent focus:ring-theme-accent"
              />
              <div>
                <span className="font-semibold text-theme-text block">
                  Critical Threat Email Notifications
                </span>
                <span className="text-theme-muted text-[11px]">
                  Dispatch automated alerts when a scan triggers MALICIOUS or brand typosquatting.
                </span>
              </div>
            </label>

            <label className="flex items-start gap-3 p-3 bg-theme-elevated rounded-lg cursor-pointer">
              <input
                type="checkbox"
                checked={slackWebhook}
                onChange={(e) => setSlackWebhook(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-theme-border text-theme-accent focus:ring-theme-accent"
              />
              <div>
                <span className="font-semibold text-theme-text block">
                  Collaborative Threat Intel Webhook
                </span>
                <span className="text-theme-muted text-[11px]">
                  Broadcast confirmed peer threat alerts to incident response communication channels.
                </span>
              </div>
            </label>
          </div>
        </div>

        {/* Security Policy & Zero-Trust Invariant */}
        <div className="p-6 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-theme-borderSubtle">
            <Shield className="w-4 h-4 text-theme-accent" />
            <h3 className="text-sm font-bold font-mono text-theme-text">SECURITY POLICY CONTROLS</h3>
          </div>

          <div className="space-y-3 text-xs font-mono">
            <label className="flex items-start gap-3 p-3 bg-theme-elevated rounded-lg cursor-pointer">
              <input
                type="checkbox"
                checked={strictZeroTrust}
                onChange={(e) => setStrictZeroTrust(e.target.checked)}
                className="mt-0.5 w-4 h-4 rounded border-theme-border text-theme-accent focus:ring-theme-accent"
              />
              <div>
                <span className="font-semibold text-theme-text block">
                  Strict Zero-Trust Fail-Safe Mode
                </span>
                <span className="text-theme-muted text-[11px]">
                  Incomplete or unreachable scans are strictly flagged as INCONCLUSIVE and never marked as
                  benign.
                </span>
              </div>
            </label>

            <div className="flex items-center justify-between p-3 bg-theme-elevated rounded-lg">
              <div>
                <span className="font-semibold text-theme-text block">Analyst Session Timeout</span>
                <span className="text-theme-muted text-[11px]">
                  Re-authenticate session after period of inactivity.
                </span>
              </div>
              <select
                value={sessionTimeout}
                onChange={(e) => setSessionTimeout(e.target.value)}
                className="bg-theme-card border border-theme-border rounded-lg p-2 text-xs font-mono text-theme-text focus:outline-none"
              >
                <option value="15m">15 Minutes</option>
                <option value="30m">30 Minutes</option>
                <option value="1h">1 Hour</option>
                <option value="4h">4 Hours</option>
              </select>
            </div>
          </div>
        </div>

        {/* Save Bar */}
        <div className="flex items-center justify-between pt-2">
          {saved ? (
            <span className="text-xs font-mono text-theme-success flex items-center gap-1.5 font-semibold">
              <CheckCircle2 className="w-4 h-4" /> Preferences Saved Successfully
            </span>
          ) : (
            <span className="text-xs font-mono text-theme-muted">Settings persist to local browser storage.</span>
          )}

          <button
            type="submit"
            className="inline-flex items-center gap-2 px-6 py-2.5 bg-theme-accent text-white dark:text-slate-950 font-bold rounded-lg text-xs font-mono transition-opacity hover:opacity-90 shadow-sm"
          >
            <Save className="w-4 h-4" />
            <span>Save Preferences</span>
          </button>
        </div>
      </form>
    </div>
  );
}
