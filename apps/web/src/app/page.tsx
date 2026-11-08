'use client';

import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { motion } from 'framer-motion';
import {
  Shield,
  Search,
  Lock,
  ArrowRight,
  Terminal,
  Activity,
  Layers,
  Radio,
  Network,
  Blocks,
  MessageSquareWarning,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Sparkles,
  Zap,
} from 'lucide-react';
import { submitUrlScan } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';

export default function LandingPage() {
  const router = useRouter();
  const { requireAuth, isAuthenticated } = useAuth();
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await submitUrlScan(url.trim());
      if (res?.scanId) {
        router.push(`/reports/${res.scanId}`);
      }
    } catch (err: any) {
      setError(err.message || 'Scan initialization failed. Please check the target URL.');
    } finally {
      setLoading(false);
    }
  };

  const sampleTargets = [
    { label: 'Phishing Demo', url: 'https://login-chase-security-verify.net/login' },
    { label: 'Web3 Wallet Drainer', url: 'https://metamask-synchronize-node.xyz/wallet' },
    { label: 'Tax Authority Scam', url: 'https://irs-tax-refund-portal.online' },
    { label: 'Authentic Safe Domain', url: 'https://github.com' },
  ];

  const modules = [
    {
      code: '01',
      title: 'Scam Message Analyzer',
      subtitle: 'Multi-Channel AI Detection',
      description:
        'Audits SMS, WhatsApp, Email, Telegram, and Social Media messages for 7 social engineering manipulation tactics and extracts IOCs.',
      href: '/messages',
      icon: MessageSquareWarning,
    },
    {
      code: '02',
      title: 'Campaign Correlation',
      subtitle: 'Cross-Vector Threat Graph',
      description:
        'Automatically clusters recurring domains, shared IPs, crypto wallet addresses, and attacker infrastructure across independent incidents.',
      href: '/correlations',
      icon: Network,
    },
    {
      code: '03',
      title: 'Decentralized Registry',
      subtitle: 'Solidity 0.8.20 EVM Commitments',
      description:
        'Anchors tamper-evident, canonical SHA-256 threat commitments to smart contracts with independent byte-for-byte in-browser verification.',
      href: '/blockchain',
      icon: Blocks,
    },
    {
      code: '04',
      title: 'Deep TLS & Perimeter Guard',
      subtitle: 'Socket-Level IP Pinning',
      description:
        'Pre-flight DNS evaluation, connection-time IP pinning defeating DNS rebinding, and SC-081v3 dynamic certificate validity scheduling.',
      href: '/certificates',
      icon: Lock,
    },
  ];

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.15,
        delayChildren: 0.1,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: 25 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.6, ease: 'easeOut' as const },
    },
  };

  return (
    <div className="space-y-24 py-10 sm:py-20 px-4 sm:px-6 max-w-7xl mx-auto">
      {/* Hero Section with Fluid Motion */}
      <motion.section
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        className="text-center space-y-6 max-w-4xl mx-auto"
      >
        <motion.div variants={itemVariants} className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a] text-[11px] font-mono text-neutral-600 dark:text-neutral-300">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          <span>AUTONOMOUS CYBER DEFENSE PLATFORM</span>
        </motion.div>

        <motion.h1
          variants={itemVariants}
          className="text-4xl sm:text-6xl lg:text-7xl font-serif tracking-tight text-black dark:text-white leading-[1.08]"
        >
          Don't trust the link. <br />
          <span className="italic font-normal text-neutral-500 dark:text-neutral-400">
            Verify the threat.
          </span>
        </motion.h1>

        <motion.p
          variants={itemVariants}
          className="text-sm sm:text-base font-sans text-neutral-600 dark:text-neutral-400 max-w-2xl mx-auto leading-relaxed"
        >
          High-performance threat intelligence combining DOM heuristic inspection, deep X.509 cryptographic validation, eMudhra CA weakness detection, and collaborative crowdsourced telemetry.
        </motion.p>

        {/* URL Quick Scan Bar with Auth Requirement */}
        <motion.div variants={itemVariants} className="pt-2 max-w-2xl mx-auto">
          <form
            onSubmit={handleQuickScan}
            className="flex flex-col sm:flex-row items-stretch sm:items-center p-2 rounded-panel card-floating gap-2"
          >
            <div className="flex-1 flex items-center px-3.5 gap-2.5">
              <Search className="w-4 h-4 text-neutral-400 shrink-0" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter suspicious URL to inspect (e.g. https://target.com)..."
                className="w-full py-2 bg-transparent text-xs sm:text-sm font-mono text-black dark:text-white placeholder:text-neutral-400 focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="py-2.5 px-6 rounded-xl bg-black dark:bg-white text-white dark:text-black text-xs font-mono font-bold hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-all flex items-center justify-center gap-2 cursor-pointer shadow-md disabled:opacity-60"
            >
              {loading ? (
                <>
                  <Activity className="w-3.5 h-3.5 animate-spin" />
                  <span>Scanning...</span>
                </>
              ) : (
                <>
                  <span>Analyze URL</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          {error && (
            <motion.div
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-3 text-left p-3 rounded-xl bg-red-500/10 border border-red-500/30 text-red-600 dark:text-red-400 text-xs font-mono flex items-center gap-2"
            >
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </motion.div>
          )}

          {/* Sample Target Badges */}
          <div className="flex flex-wrap items-center justify-center gap-2 pt-4">
            <span className="text-[10px] font-mono text-neutral-400 uppercase tracking-wider">Quick test:</span>
            {sampleTargets.map((st) => (
              <button
                key={st.label}
                type="button"
                onClick={() => setUrl(st.url)}
                className="px-2.5 py-1 rounded-full text-[11px] font-mono border border-neutral-200 dark:border-[#27272a] bg-neutral-100/60 dark:bg-[#121214]/60 text-neutral-700 dark:text-neutral-300 hover:border-black dark:hover:border-white transition-all cursor-pointer"
              >
                {st.label}
              </button>
            ))}
          </div>
        </motion.div>
      </motion.section>

      {/* Live Heuristic Inspection Stream with Scroll Motion */}
      <motion.section
        initial={{ opacity: 0, y: 35 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: '-80px' }}
        transition={{ duration: 0.7, ease: 'easeOut' }}
        className="card-floating p-6 sm:p-8 space-y-4"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-neutral-200 dark:border-[#1f1f23] gap-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-neutral-600 dark:text-neutral-400" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-black dark:text-white">
              // RECENT HEURISTIC DISCOVERIES &amp; ZERO-TRUST TELEMETRY
            </h3>
          </div>
          <div className="flex items-center gap-2 text-[10px] font-mono text-neutral-500">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>REAL-TIME STREAM ACTIVE</span>
          </div>
        </div>

        <div className="divide-y divide-neutral-200/60 dark:divide-[#18181b] font-mono space-y-3">
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
            className="pt-2 flex flex-col md:flex-row md:items-center justify-between gap-1 text-[11px]"
          >
            <div className="flex items-center gap-2 truncate">
              <span className="text-red-600 dark:text-red-400 font-semibold">[MALICIOUS]</span>
              <span className="text-neutral-400">Score: 94/100</span>
              <span className="truncate text-black dark:text-neutral-200">https://secure-chase-account-verify.com/login</span>
            </div>
            <span className="text-neutral-500 shrink-0 font-pixel text-[10px]">BRAND IMPERSONATION + SUB-2048 RSA</span>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -10 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="pt-2 flex flex-col md:flex-row md:items-center justify-between gap-1 text-[11px]"
          >
            <div className="flex items-center gap-2 truncate">
              <span className="text-amber-600 dark:text-amber-400 font-semibold">[SUSPICIOUS]</span>
              <span className="text-neutral-400">Score: 58/100</span>
              <span className="truncate text-black dark:text-neutral-200">https://temporary-invoice-download.xyz/auth</span>
            </div>
            <span className="text-neutral-500 shrink-0 font-pixel text-[10px]">EXCESSIVE SUBDOMAINS + HIGH-RISK TLD</span>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -10 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="pt-2 flex flex-col md:flex-row md:items-center justify-between gap-1 text-[11px]"
          >
            <div className="flex items-center gap-2 truncate">
              <span className="text-emerald-600 dark:text-emerald-400 font-semibold">[BENIGN]</span>
              <span className="text-neutral-400">Score: 04/100</span>
              <span className="truncate text-black dark:text-neutral-200">https://github.com/security</span>
            </div>
            <span className="text-neutral-500 shrink-0 font-pixel text-[10px]">VERIFIED TRANCO TOP-10K HOST</span>
          </motion.div>
        </div>
      </motion.section>

      {/* 4 Core Pillars with Staggered Scroll Motion */}
      <section className="space-y-8">
        <motion.div
          initial={{ opacity: 0, y: 25 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-60px' }}
          transition={{ duration: 0.6 }}
          className="flex items-center justify-between"
        >
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-500 block">
              // DEFENSE-IN-DEPTH ARCHITECTURE
            </span>
            <h2 className="text-2xl sm:text-4xl font-serif text-black dark:text-white mt-1">
              Multi-Layered Threat Verification
            </h2>
          </div>
          <Link
            href="/dashboard"
            className="hidden sm:inline-flex items-center gap-1.5 text-xs font-mono text-neutral-600 dark:text-neutral-300 hover:text-black dark:hover:text-white"
          >
            Open Command Center <ChevronRight className="w-3.5 h-3.5" />
          </Link>
        </motion.div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {modules.map((m, idx) => {
            const Icon = m.icon;
            return (
              <motion.div
                key={m.code}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, margin: '-40px' }}
                transition={{ duration: 0.6, delay: idx * 0.1 }}
              >
                <Link
                  href={m.href}
                  className="group card-floating p-6 hover:border-black dark:hover:border-white transition-all flex flex-col justify-between h-full"
                >
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="p-2 rounded-lg bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a] text-black dark:text-white">
                        <Icon className="w-4 h-4" />
                      </div>
                      <span className="text-[10px] font-mono text-neutral-400 group-hover:text-black dark:group-hover:text-white transition-colors">
                        [{m.code}]
                      </span>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold font-mono text-black dark:text-white group-hover:underline">
                        {m.title}
                      </h3>
                      <span className="text-[11px] text-neutral-500 font-mono block mt-0.5">
                        {m.subtitle}
                      </span>
                    </div>

                    <p className="text-xs text-neutral-600 dark:text-neutral-400 leading-relaxed font-sans">
                      {m.description}
                    </p>
                  </div>

                  <div className="pt-4 mt-2 border-t border-neutral-100 dark:border-[#18181b] flex items-center justify-between text-xs font-mono text-neutral-500 group-hover:text-black dark:group-hover:text-white">
                    <span>Access Module</span>
                    <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
                  </div>
                </Link>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* Action CTA Banner */}
      <motion.section
        initial={{ opacity: 0, scale: 0.98, y: 25 }}
        whileInView={{ opacity: 1, scale: 1, y: 0 }}
        viewport={{ once: true, margin: '-60px' }}
        transition={{ duration: 0.7 }}
        className="bg-neutral-900 dark:bg-[#0c0c0e] text-white border border-neutral-800 dark:border-[#27272a] rounded-3xl p-8 sm:p-14 text-center space-y-6 shadow-2xl relative overflow-hidden"
      >
        <div className="space-y-2 max-w-xl mx-auto">
          <span className="text-[11px] font-mono uppercase tracking-wider text-neutral-400 block font-pixel">
            [ INDUSTRIAL-GRADE SECURITY PERIMETER ]
          </span>
          <h2 className="text-3xl sm:text-5xl font-serif">
            Verify before compromise.
          </h2>
          <p className="text-xs sm:text-sm font-sans text-neutral-400 leading-relaxed">
            Protect your users and organization with zero-trust automated scanning, verifiable blockchain audit trails, and campaign threat graphs.
          </p>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
          <Link
            href="/scanner"
            className="btn-industrial px-6 py-2.5 rounded-full text-xs font-semibold cursor-pointer"
          >
            Launch URL Threat Scanner
          </Link>
          <Link
            href="/messages"
            className="px-6 py-2.5 rounded-full border border-neutral-700 hover:border-neutral-500 bg-transparent text-white text-xs font-mono transition-colors"
          >
            Analyze Scam Message
          </Link>
          <Link
            href="/blockchain"
            className="px-6 py-2.5 rounded-full border border-neutral-700 hover:border-neutral-500 bg-transparent text-white text-xs font-mono transition-colors"
          >
            Decentralized Registry
          </Link>
        </div>
      </motion.section>
    </div>
  );
}
