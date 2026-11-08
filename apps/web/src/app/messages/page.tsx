'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  MessageSquareWarning,
  Send,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Sparkles,
  Link as LinkIcon,
  Mail,
  Phone,
  Wallet,
  Building2,
  Lock,
  Layers,
  CheckCircle2,
  ExternalLink,
  RefreshCw,
  Blocks,
  Copy,
  ChevronRight,
  Shield,
  Lightbulb,
  Terminal,
} from 'lucide-react';
import {
  analyzeMessage,
  fetchMessageAnalyses,
  registerOnBlockchain,
  verifyOnBlockchain,
} from '@/lib/api';
import { RiskScoreGauge } from '@/components/ui/RiskScoreGauge';
import { RiskBadge } from '@/components/ui/RiskBadge';
import {
  MessageChannelEnum,
  type MessageChannel,
  type IMessageAnalysis,
  type IBlockchainRecord,
  type IBlockchainVerification,
} from '@sentrix/shared';

const DEMO_PRESETS = [
  {
    title: 'Urgent Banking OTP Drainer',
    channel: MessageChannelEnum.SMS,
    sender: 'CHASE-SECURE-ALERT',
    content:
      'CHASE BANK ALERT: Unrecognized login from IP 192.168.1.1. Your account is temporarily locked. Reply with your one-time SMS verification OTP code immediately to verify your identity or your funds will be permanently frozen within 15 minutes. Call support: +1-800-555-0199 or access https://chase-security-verify.net/login',
  },
  {
    title: 'Web3 Wallet Seed-Phrase Phishing',
    channel: MessageChannelEnum.WHATSAPP,
    sender: '+1-888-METAMASK-SUPPORT',
    content:
      'MetaMask Support Notice: Security vulnerability detected on your Ethereum wallet 0x71C84183204738719E43486376822fCDEBE49A70. To protect your ERC20 assets, reply immediately with your 12-word recovery seed phrase or private key to synchronize with our secure node. Urgently verify before token drain occurs.',
  },
  {
    title: 'Technical Support & Remote Access Scam',
    channel: MessageChannelEnum.EMAIL,
    sender: 'billing-refund@geek-squad-desk.com',
    content:
      'Geek Squad Invoice Notice: Your subscription was auto-renewed for $499.00. If you did not authorize this charge, call our toll-free refund desk at +1-888-234-5678 immediately. Our technicians require you to download AnyDesk or TeamViewer to process your full refund to your PayPal or CashApp account.',
  },
  {
    title: 'Legitimate Corporate Advisory',
    channel: MessageChannelEnum.EMAIL,
    sender: 'it-security@sentrix-enterprise.internal',
    content:
      'Quarterly Cybersecurity Notice: We are conducting regular identity posture audits. Remember that SENTRIX IT will never ask for your password, MFA code, or seed phrase over email. Visit the corporate portal at https://portal.internal/wiki to read the latest zero-trust guidelines.',
  },
];

export default function MessageScannerPage() {
  const [content, setContent] = useState('');
  const [channel, setChannel] = useState<MessageChannel>(MessageChannelEnum.SMS);
  const [sender, setSender] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [currentAnalysis, setCurrentAnalysis] = useState<IMessageAnalysis | null>(null);
  const [recentAnalyses, setRecentAnalyses] = useState<IMessageAnalysis[]>([]);
  const [error, setError] = useState<string | null>(null);

  // Blockchain state
  const [registeringChain, setRegisteringChain] = useState(false);
  const [blockchainRecord, setBlockchainRecord] = useState<IBlockchainRecord | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [blockchainVerification, setBlockchainVerification] = useState<IBlockchainVerification | null>(null);

  useEffect(() => {
    let mounted = true;
    fetchMessageAnalyses(10, 0)
      .then((res) => {
        if (mounted && res?.messages) {
          setRecentAnalyses(res.messages);
        }
      })
      .catch(() => {});
    return () => {
      mounted = false;
    };
  }, []);

  const handleAnalyze = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!content.trim() || analyzing) return;

    setAnalyzing(true);
    setError(null);
    setBlockchainRecord(null);
    setBlockchainVerification(null);

    try {
      const result = await analyzeMessage({
        content: content.trim(),
        channel,
        sender: sender.trim() || undefined,
      });
      setCurrentAnalysis(result);
      setRecentAnalyses((prev) => [result, ...prev.filter((m) => m._id !== result._id)]);
    } catch (err: any) {
      setError(err?.message || 'Failed to analyze message content');
    } finally {
      setAnalyzing(false);
    }
  };

  const handlePresetClick = (preset: (typeof DEMO_PRESETS)[0]) => {
    setContent(preset.content);
    setChannel(preset.channel);
    setSender(preset.sender);
    setError(null);
    setBlockchainRecord(null);
    setBlockchainVerification(null);
  };

  const handleRegisterOnChain = async () => {
    if (!currentAnalysis?._id || registeringChain) return;
    setRegisteringChain(true);
    try {
      const record = await registerOnBlockchain(currentAnalysis._id, 'MESSAGE');
      setBlockchainRecord(record);
    } catch (err: any) {
      setError(err?.message || 'Failed to commit report hash to blockchain');
    } finally {
      setRegisteringChain(false);
    }
  };

  const handleVerifyOnChain = async () => {
    if (!currentAnalysis?._id || verifyingChain) return;
    setVerifyingChain(true);
    try {
      const verification = await verifyOnBlockchain(currentAnalysis._id);
      setBlockchainVerification(verification);
    } catch (err: any) {
      setError(err?.message || 'Failed to verify blockchain ledger');
    } finally {
      setVerifyingChain(false);
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16 font-mono text-xs">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-neutral-100 dark:bg-[#18181b] border border-neutral-200 dark:border-[#27272a] text-black dark:text-white shadow-xs">
              <MessageSquareWarning className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white flex items-center gap-2">
                Scam Message Analyzer
                <span className="text-[9px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-neutral-100 dark:bg-[#18181b] text-neutral-700 dark:text-neutral-300 border border-neutral-300 dark:border-[#27272a]">
                  MODULE A
                </span>
              </h1>
              <p className="text-xs text-neutral-500 font-mono mt-0.5">
                Multi-channel inspection across SMS, WhatsApp, Email, Telegram & crypto communication.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Preset Quick Fill Buttons */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium text-neutral-500 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" />
            // ONE-CLICK DEMO INCIDENTS:
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {DEMO_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handlePresetClick(preset)}
              className="text-left p-3 rounded-lg border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] hover:border-black dark:hover:border-white transition-all shadow-xs cursor-pointer"
            >
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold text-black dark:text-white">
                <span className="truncate pr-1">{preset.title}</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-[#18181b] text-neutral-500 uppercase font-pixel shrink-0">
                  {preset.channel}
                </span>
              </div>
              <p className="text-[11px] text-neutral-500 line-clamp-2 mt-1.5 font-sans leading-relaxed">
                {preset.content}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Input Form Box */}
      <div className="card-floating p-6 sm:p-7 space-y-4">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
                Communication Channel
              </label>
              <select
                value={channel}
                onChange={(e) => setChannel(e.target.value as MessageChannel)}
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white focus:outline-none focus:border-black dark:focus:border-white"
              >
                <option value={MessageChannelEnum.SMS}>SMS / Text Message</option>
                <option value={MessageChannelEnum.WHATSAPP}>WhatsApp Messenger</option>
                <option value={MessageChannelEnum.EMAIL}>Email Phishing</option>
                <option value={MessageChannelEnum.TELEGRAM}>Telegram Channel / Bot</option>
                <option value={MessageChannelEnum.SOCIAL_MEDIA}>Social Media Direct Message</option>
                <option value={MessageChannelEnum.OTHER}>Other / Raw Text</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
                Sender ID / Authority Header (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. +1-800-CHASE-ALERT or security-notice@binance-verify.com"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white"
              />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-semibold text-neutral-700 dark:text-neutral-300 uppercase mb-1">
              Raw Message Content
            </label>
            <textarea
              rows={4}
              required
              placeholder="Paste raw SMS, email body, WhatsApp alert, or direct message..."
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="w-full p-3 text-xs font-mono rounded-lg border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white leading-relaxed resize-y"
            />
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] text-neutral-400">
              Evaluates 7 behavioral tactics, crypto drainer wallets, and exfiltration webhooks.
            </span>
            {/* Normal dark gray button with white button text */}
            <button
              type="submit"
              disabled={analyzing || !content.trim()}
              className="btn-industrial py-2.5 px-6 rounded-lg text-xs font-semibold cursor-pointer disabled:opacity-50"
            >
              {analyzing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Inspecting Content...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5 text-white" />
                  <span>Analyze Message Threat</span>
                </>
              )}
            </button>
          </div>
        </form>

        {error && (
          <div className="p-3 rounded-lg bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-xs text-red-700 dark:text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0 text-red-500" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Analysis Results Display */}
      {currentAnalysis && (
        <div className="space-y-6">
          {/* Verdict Card */}
          <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-6 shadow-card">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
              <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-neutral-200 dark:border-[#1f1f23] pb-6 md:pb-0 md:pr-6">
                <RiskScoreGauge
                  score={currentAnalysis.riskScore}
                  verdict={currentAnalysis.classification}
                  confidence={currentAnalysis.confidence}
                  size={150}
                />
                <div className="mt-2 text-center">
                  <RiskBadge verdict={currentAnalysis.classification} size="lg" />
                </div>
              </div>

              <div className="md:col-span-2 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase text-neutral-400 tracking-wider">
                    // AI EXECUTIVE THREAT SUMMARY
                  </span>
                  <span className="text-[10px] text-neutral-400">
                    Confidence: {currentAnalysis.confidence}%
                  </span>
                </div>

                <p className="text-sm font-sans text-black dark:text-white leading-relaxed">
                  {currentAnalysis.aiExplanation?.summary ||
                    'Passive heuristic inspection completed for submitted message payload.'}
                </p>

                {/* Blockchain Action Buttons (Normal dark gray button with white text) */}
                <div className="flex flex-wrap items-center gap-2 pt-2">
                  <button
                    type="button"
                    onClick={handleRegisterOnChain}
                    disabled={registeringChain || Boolean(blockchainRecord)}
                    className="btn-industrial py-1.5 px-3 rounded-md text-xs font-semibold cursor-pointer disabled:opacity-50"
                  >
                    <Blocks className="w-3.5 h-3.5 text-white" />
                    <span>
                      {registeringChain
                        ? 'Anchoring on EVM...'
                        : blockchainRecord
                        ? 'Anchored On-Chain'
                        : 'Commit Hash to Blockchain'}
                    </span>
                  </button>

                  <button
                    type="button"
                    onClick={handleVerifyOnChain}
                    disabled={verifyingChain}
                    className="px-3 py-1.5 rounded-md border border-neutral-300 dark:border-[#27272a] bg-neutral-100 dark:bg-[#121214] text-neutral-800 dark:text-neutral-200 hover:text-black dark:hover:text-white text-xs transition-colors cursor-pointer"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 inline mr-1" />
                    <span>Verify Ledger Byte-for-Byte</span>
                  </button>
                </div>

                {blockchainRecord && (
                  <div className="p-2.5 rounded-lg bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-[11px] space-y-1">
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold block flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Immutable SHA-256 Ledger Record Created
                    </span>
                    <div className="text-neutral-500 font-mono truncate">
                      Commitment: {blockchainRecord.reportHash}
                    </div>
                  </div>
                )}

                {blockchainVerification && (
                  <div className="p-2.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 text-[11px] space-y-0.5 text-emerald-800 dark:text-emerald-300">
                    <span className="font-semibold block flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Cryptographic Integrity Verified (100% Match)
                    </span>
                    <span className="text-[10px] text-neutral-500 block">
                      Local SHA-256 matches ledger state byte-for-byte.
                    </span>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Behavioral Patterns & Extracted IOCs */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* 7 Tactics */}
            <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-neutral-200 dark:border-[#1f1f23] pb-2">
                <span className="font-bold uppercase tracking-wider text-black dark:text-white">
                  // DETECTED MANIPULATION TACTICS
                </span>
                <span className="text-[10px] text-neutral-400">
                  {currentAnalysis.detectedPatterns?.length || 0} Identified
                </span>
              </div>

              {(!currentAnalysis.detectedPatterns || currentAnalysis.detectedPatterns.length === 0) ? (
                <div className="p-4 text-center text-neutral-400">
                  No active social engineering tactics detected.
                </div>
              ) : (
                <div className="space-y-2">
                  {currentAnalysis.detectedPatterns.map((pat, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg border border-neutral-200 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] space-y-1"
                    >
                      <div className="flex items-center justify-between font-bold text-black dark:text-white">
                        <span>{pat.title}</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-red-100 dark:bg-red-950/50 text-red-600 dark:text-red-400">
                          {pat.tactic}
                        </span>
                      </div>
                      <p className="text-[11px] text-neutral-500 font-sans leading-relaxed">
                        {pat.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Extracted IOCs */}
            <div className="bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl p-5 shadow-xs space-y-3">
              <div className="flex items-center justify-between border-b border-neutral-200 dark:border-[#1f1f23] pb-2">
                <span className="font-bold uppercase tracking-wider text-black dark:text-white">
                  // EXTRACTED IOCS & ATTACKER ENTITIES
                </span>
                <span className="text-[10px] text-neutral-400">Cross-Vector Targets</span>
              </div>

              <div className="space-y-3">
                {/* URLs */}
                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    URLs ({currentAnalysis.extractedIndicators.urls.length})
                  </span>
                  {currentAnalysis.extractedIndicators.urls.length === 0 ? (
                    <span className="text-neutral-400 text-[11px]">None extracted</span>
                  ) : (
                    <div className="space-y-1">
                      {currentAnalysis.extractedIndicators.urls.map((u, i) => (
                        <div key={i} className="flex items-center justify-between p-2 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a]">
                          <span className="truncate max-w-[240px] text-black dark:text-white">{u}</span>
                          <Link
                            href={`/scanner?target=${encodeURIComponent(u)}`}
                            className="btn-industrial text-[10px] py-0.5 px-2 rounded"
                          >
                            Inspect URL
                          </Link>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Wallets */}
                <div>
                  <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                    Cryptocurrency Wallets ({currentAnalysis.extractedIndicators.wallets.length})
                  </span>
                  {currentAnalysis.extractedIndicators.wallets.length === 0 ? (
                    <span className="text-neutral-400 text-[11px]">None extracted</span>
                  ) : (
                    <div className="space-y-1">
                      {currentAnalysis.extractedIndicators.wallets.map((w, i) => (
                        <div key={i} className="flex items-center justify-between p-2 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a]">
                          <span className="truncate max-w-[220px] text-emerald-600 dark:text-emerald-400 font-mono">{w.address}</span>
                          <span className="text-[9px] px-1.5 py-0.5 rounded bg-neutral-200 dark:bg-[#27272a] text-neutral-600 dark:text-neutral-300 uppercase font-pixel">{w.network}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Phones & Entities */}
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                      Phones ({currentAnalysis.extractedIndicators.phones.length})
                    </span>
                    {currentAnalysis.extractedIndicators.phones.length === 0 ? (
                      <span className="text-neutral-400 text-[11px]">None</span>
                    ) : (
                      currentAnalysis.extractedIndicators.phones.map((p, i) => (
                        <div key={i} className="p-1.5 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] truncate">{p}</div>
                      ))
                    )}
                  </div>
                  <div>
                    <span className="text-[10px] uppercase text-neutral-400 block mb-1">
                      Targeted Entities ({currentAnalysis.extractedIndicators.entities.length})
                    </span>
                    {currentAnalysis.extractedIndicators.entities.length === 0 ? (
                      <span className="text-neutral-400 text-[11px]">None</span>
                    ) : (
                      currentAnalysis.extractedIndicators.entities.map((e, i) => (
                        <div key={i} className="p-1.5 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] truncate font-semibold">{e}</div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
