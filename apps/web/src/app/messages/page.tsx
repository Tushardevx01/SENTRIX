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
  CreditCard,
  Building2,
  Lock,
  Layers,
  CheckCircle2,
  Clock,
  ExternalLink,
  RefreshCw,
  Blocks,
  Copy,
  ChevronRight,
  Shield,
  Lightbulb,
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  analyzeMessage,
  fetchMessageAnalyses,
  registerOnBlockchain,
  verifyOnBlockchain,
} from '@/lib/api';
import { RiskScoreGauge } from '@/components/ui/RiskScoreGauge';
import { RiskBadge } from '@/components/ui/RiskBadge';
import { LoadingState } from '@/components/ui/LoadingState';
import { ErrorState } from '@/components/ui/ErrorState';
import {
  MessageChannelEnum,
  type MessageChannel,
  type IMessageAnalysis,
  type IBlockchainRecord,
  type IBlockchainVerification,
  VerdictEnum,
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
    title: 'Legitimate Corporate Security Advisory',
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
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Blockchain state
  const [registeringChain, setRegisteringChain] = useState(false);
  const [blockchainRecord, setBlockchainRecord] = useState<IBlockchainRecord | null>(null);
  const [verifyingChain, setVerifyingChain] = useState(false);
  const [blockchainVerification, setBlockchainVerification] = useState<IBlockchainVerification | null>(null);

  // Load recent message analyses
  useEffect(() => {
    let mounted = true;
    setLoadingHistory(true);
    fetchMessageAnalyses(10, 0)
      .then((res) => {
        if (mounted && res?.messages) {
          setRecentAnalyses(res.messages);
        }
      })
      .catch(() => {
        // non-blocking
      })
      .finally(() => {
        if (mounted) setLoadingHistory(false);
      });
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
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-theme-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-theme-accent/10 border border-theme-accent/20 text-theme-accent shadow-xs">
              <MessageSquareWarning className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-theme-text flex items-center gap-2">
                Scam & Social Engineering Detector
                <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-500 border border-emerald-500/20">
                  AI Powered + Web3
                </span>
              </h1>
              <p className="text-xs text-theme-muted mt-0.5">
                Analyze SMS, WhatsApp, Emails, and Direct Messages for credential harvesting, urgent OTP fraud, crypto drainers, and entity impersonation.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Preset Quick Fill Buttons */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-medium text-theme-muted flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-theme-accent" />
            Demo Presets (One-Click Investigation):
          </span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {DEMO_PRESETS.map((preset, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => handlePresetClick(preset)}
              className="text-left p-3 rounded-lg border border-theme-border bg-theme-elevated/40 hover:bg-theme-elevated hover:border-theme-accent/40 transition-all group"
            >
              <div className="flex items-center justify-between text-[11px] font-mono font-semibold text-theme-text group-hover:text-theme-accent">
                <span>{preset.title}</span>
                <span className="text-[9px] px-1.5 py-0.5 rounded bg-theme-border/60 text-theme-muted uppercase">
                  {preset.channel}
                </span>
              </div>
              <p className="text-[11px] text-theme-muted line-clamp-2 mt-1.5 font-sans leading-relaxed">
                {preset.content}
              </p>
            </button>
          ))}
        </div>
      </div>

      {/* Main Analysis Form */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm">
        <form onSubmit={handleAnalyze} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-xs font-mono font-medium text-theme-text mb-1.5">
                Message Channel
              </label>
              <select
                value={channel}
                onChange={(e) => setChannel(e.target.value as MessageChannel)}
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-theme-border bg-theme-base text-theme-text focus:outline-none focus:ring-1 focus:ring-theme-accent"
              >
                <option value={MessageChannelEnum.SMS}>SMS (Text Message)</option>
                <option value={MessageChannelEnum.WHATSAPP}>WhatsApp</option>
                <option value={MessageChannelEnum.EMAIL}>Email</option>
                <option value={MessageChannelEnum.TELEGRAM}>Telegram</option>
                <option value={MessageChannelEnum.SOCIAL_MEDIA}>Social Media (DM)</option>
                <option value={MessageChannelEnum.OTHER}>Other / Web Form</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block text-xs font-mono font-medium text-theme-text mb-1.5">
                Sender Information (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. +1-800-555-0199 or security-notice@service.com"
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-theme-border bg-theme-base text-theme-text placeholder:text-theme-muted/50 focus:outline-none focus:ring-1 focus:ring-theme-accent"
              />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="text-xs font-mono font-medium text-theme-text">
                Suspicious Message Content <span className="text-rose-500">*</span>
              </label>
              <span className="text-[11px] font-mono text-theme-muted">
                {content.length} / 10,000 characters
              </span>
            </div>
            <textarea
              rows={4}
              required
              maxLength={10000}
              placeholder="Paste raw SMS, WhatsApp, or phishing email content here for multi-vector threat extraction..."
              value={content}
              onChange={(e) => setContent(e.target.value)}
              className="w-full p-3 text-xs font-mono rounded-lg border border-theme-border bg-theme-base text-theme-text placeholder:text-theme-muted/50 focus:outline-none focus:ring-1 focus:ring-theme-accent resize-y"
            />
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-500 text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center justify-between pt-2">
            <span className="text-[11px] text-theme-muted flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5" />
              Input sanitization active. Private entities are preserved for indicator hashing.
            </span>
            <button
              type="submit"
              disabled={analyzing || !content.trim()}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-theme-accent text-white font-mono text-xs font-semibold hover:bg-theme-accent/90 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm transition-all"
            >
              {analyzing ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Running AI Threat Engine...
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  Analyze Threat Vectors
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Analysis Results */}
      <AnimatePresence>
        {currentAnalysis && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="space-y-6"
          >
            {/* Verdict Hero Card */}
            <div className="bg-theme-card border border-theme-border rounded-xl p-6 shadow-sm">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
                <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-theme-border pb-6 md:pb-0 md:pr-6">
                  <RiskScoreGauge
                    score={currentAnalysis.riskScore}
                    verdict={currentAnalysis.classification}
                    confidence={currentAnalysis.confidence}
                    size={160}
                  />
                  <div className="mt-2 text-center">
                    <RiskBadge verdict={currentAnalysis.classification} size="lg" />
                    <p className="text-[11px] font-mono text-theme-muted mt-1.5">
                      Confidence Score: {currentAnalysis.confidence}%
                    </p>
                  </div>
                </div>

                <div className="md:col-span-2 space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <span className="text-[10px] font-mono uppercase tracking-wider text-theme-muted">
                        Investigation ID: {currentAnalysis._id}
                      </span>
                      <h2 className="text-base font-bold text-theme-text mt-0.5">
                        {currentAnalysis.classification === VerdictEnum.MALICIOUS
                          ? 'High-Risk Social Engineering & Fraud Detected'
                          : currentAnalysis.classification === VerdictEnum.SUSPICIOUS
                          ? 'Suspicious Message Patterns Requiring Caution'
                          : 'No Fraudulent Tactics Detected'}
                      </h2>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono px-2 py-1 rounded bg-theme-elevated text-theme-text border border-theme-border">
                        {currentAnalysis.channel}
                      </span>
                      <button
                        type="button"
                        onClick={handleRegisterOnChain}
                        disabled={registeringChain || !!blockchainRecord}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-theme-accent/10 border border-theme-accent/30 text-theme-accent text-xs font-mono font-medium hover:bg-theme-accent/20 disabled:opacity-60 transition-colors"
                      >
                        <Blocks className="w-3.5 h-3.5" />
                        {registeringChain
                          ? 'Publishing to EVM...'
                          : blockchainRecord
                          ? 'Anchored on Chain'
                          : 'Register on Blockchain'}
                      </button>
                    </div>
                  </div>

                  <p className="text-xs font-mono text-theme-muted bg-theme-base p-3 rounded-lg border border-theme-border italic line-clamp-3">
                    &quot;{currentAnalysis.preview}&quot;
                  </p>

                  {/* Blockchain On-Chain Receipt Banner if registered */}
                  {blockchainRecord && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold flex items-center gap-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          Cryptographically Anchored to Blockchain
                        </span>
                        <button
                          type="button"
                          onClick={handleVerifyOnChain}
                          disabled={verifyingChain}
                          className="underline hover:text-emerald-300 text-[11px]"
                        >
                          {verifyingChain ? 'Verifying...' : 'Verify Cryptographic State'}
                        </button>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[10px] text-theme-muted">
                        <div>
                          <span className="text-theme-text">SHA-256 Report Hash:</span>{' '}
                          <span className="truncate block font-mono text-emerald-300">
                            {blockchainRecord.reportHash}
                          </span>
                        </div>
                        <div>
                          <span className="text-theme-text">Tx Hash:</span>{' '}
                          <span className="truncate block font-mono text-emerald-300">
                            {blockchainRecord.txHash}
                          </span>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {blockchainVerification && (
                    <div className="p-3 rounded-lg bg-theme-elevated border border-theme-border font-mono text-xs space-y-1">
                      <div className="flex items-center gap-2 text-theme-text font-semibold">
                        <Shield className="w-4 h-4 text-emerald-500" />
                        Verification Status: {blockchainVerification.verified ? 'VALID & UNTAMPERED' : 'INVALID'}
                      </div>
                      <p className="text-[11px] text-theme-muted">
                        Computed local SHA-256 matches on-chain commitment byte-for-byte. Contract address:{' '}
                        <code className="text-theme-accent">{blockchainVerification.contractAddress}</code>
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Grid: Extracted Indicators & Detected Tactics */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Detected Tactics */}
              <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-theme-border pb-3">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-theme-accent" />
                    Detected Social Engineering Tactics ({currentAnalysis.detectedPatterns.length})
                  </h3>
                </div>

                {currentAnalysis.detectedPatterns.length === 0 ? (
                  <p className="text-xs font-mono text-theme-muted py-4 text-center">
                    No deceptive manipulation tactics detected in content.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {currentAnalysis.detectedPatterns.map((pat, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg border border-theme-border bg-theme-base/60 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-mono font-bold text-theme-text">
                            {pat.title}
                          </span>
                          <RiskBadge severity={pat.severity} size="sm" />
                        </div>
                        <p className="text-xs text-theme-muted leading-relaxed font-sans">
                          {pat.description}
                        </p>
                        {pat.matchedPatterns?.length > 0 && (
                          <div className="flex flex-wrap gap-1.5 pt-1">
                            {pat.matchedPatterns.map((match, mIdx) => (
                              <span
                                key={mIdx}
                                className="px-1.5 py-0.5 text-[10px] font-mono rounded bg-theme-elevated text-theme-muted border border-theme-border"
                              >
                                {match}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Extracted Threat Indicators */}
              <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-theme-border pb-3">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
                    <Layers className="w-4 h-4 text-theme-accent" />
                    Extracted IOCs & References
                  </h3>
                </div>

                <div className="space-y-3 text-xs font-mono">
                  {/* Extracted URLs */}
                  <div>
                    <span className="text-[10px] uppercase text-theme-muted block mb-1 flex items-center gap-1.5">
                      <LinkIcon className="w-3 h-3" /> URLs ({currentAnalysis.extractedIndicators.urls.length})
                    </span>
                    {currentAnalysis.extractedIndicators.urls.length === 0 ? (
                      <span className="text-theme-muted text-[11px]">None extracted</span>
                    ) : (
                      <div className="space-y-1">
                        {currentAnalysis.extractedIndicators.urls.map((u, i) => (
                          <div
                            key={i}
                            className="flex items-center justify-between p-2 rounded bg-theme-base border border-theme-border"
                          >
                            <span className="truncate max-w-[280px] text-theme-text text-[11px]">{u}</span>
                            <Link
                              href={`/scanner?url=${encodeURIComponent(u)}`}
                              className="inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded bg-theme-accent/10 text-theme-accent hover:bg-theme-accent/20"
                            >
                              Scan URL <ExternalLink className="w-2.5 h-2.5" />
                            </Link>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Extracted Wallets */}
                  <div>
                    <span className="text-[10px] uppercase text-theme-muted block mb-1 flex items-center gap-1.5">
                      <Wallet className="w-3 h-3" /> Crypto Wallets ({currentAnalysis.extractedIndicators.wallets.length})
                    </span>
                    {currentAnalysis.extractedIndicators.wallets.length === 0 ? (
                      <span className="text-theme-muted text-[11px]">None extracted</span>
                    ) : (
                      <div className="space-y-1">
                        {currentAnalysis.extractedIndicators.wallets.map((w, i) => (
                          <div
                            key={i}
                            className="flex items-center justify-between p-2 rounded bg-theme-base border border-theme-border"
                          >
                            <span className="font-mono text-emerald-400 text-[11px] truncate max-w-[260px]">
                              {w.address}
                            </span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-theme-elevated text-theme-muted">
                              {w.network}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Emails & Phones */}
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <span className="text-[10px] uppercase text-theme-muted block mb-1 flex items-center gap-1.5">
                        <Mail className="w-3 h-3" /> Emails ({currentAnalysis.extractedIndicators.emails.length})
                      </span>
                      {currentAnalysis.extractedIndicators.emails.length === 0 ? (
                        <span className="text-theme-muted text-[11px]">None</span>
                      ) : (
                        currentAnalysis.extractedIndicators.emails.map((e, i) => (
                          <div key={i} className="p-1.5 rounded bg-theme-base text-[11px] truncate border border-theme-border">
                            {e}
                          </div>
                        ))
                      )}
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-theme-muted block mb-1 flex items-center gap-1.5">
                        <Phone className="w-3 h-3" /> Phones ({currentAnalysis.extractedIndicators.phones.length})
                      </span>
                      {currentAnalysis.extractedIndicators.phones.length === 0 ? (
                        <span className="text-theme-muted text-[11px]">None</span>
                      ) : (
                        currentAnalysis.extractedIndicators.phones.map((p, i) => (
                          <div key={i} className="p-1.5 rounded bg-theme-base text-[11px] truncate border border-theme-border">
                            {p}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Impersonated Entities */}
                  <div>
                    <span className="text-[10px] uppercase text-theme-muted block mb-1 flex items-center gap-1.5">
                      <Building2 className="w-3 h-3" /> Impersonated Entities ({currentAnalysis.extractedIndicators.entities.length})
                    </span>
                    {currentAnalysis.extractedIndicators.entities.length === 0 ? (
                      <span className="text-theme-muted text-[11px]">No specific brand identified</span>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {currentAnalysis.extractedIndicators.entities.map((ent, i) => (
                          <span
                            key={i}
                            className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[10px] font-mono font-semibold"
                          >
                            {ent}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* AI Grounded Explanation Card */}
            {currentAnalysis.aiExplanation && (
              <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-theme-border pb-3">
                  <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-theme-accent" />
                    AI Grounded Threat Assessment
                  </h3>
                  <span className="text-[10px] font-mono text-theme-muted">
                    Evidence-Backed • Zero Hallucination
                  </span>
                </div>

                <div className="p-3.5 rounded-lg bg-theme-elevated/40 border border-theme-border text-xs text-theme-text leading-relaxed">
                  {currentAnalysis.aiExplanation.summary}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <span className="text-[11px] font-mono font-semibold text-theme-text flex items-center gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
                      Key Forensic Reasoning
                    </span>
                    <ul className="space-y-1.5 text-xs text-theme-muted font-sans">
                      {currentAnalysis.aiExplanation.reasoning.map((r, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-theme-accent font-bold">•</span>
                          <span>{r}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="space-y-2">
                    <span className="text-[11px] font-mono font-semibold text-theme-text flex items-center gap-1.5">
                      <Lightbulb className="w-3.5 h-3.5 text-emerald-500" />
                      Defensive Precautions
                    </span>
                    <ul className="space-y-1.5 text-xs text-theme-muted font-sans">
                      {currentAnalysis.aiExplanation.precautions.map((p, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0 mt-0.5" />
                          <span>{p}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Historical Message Investigations Feed */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-theme-border pb-3">
          <div>
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
              <Clock className="w-4 h-4 text-theme-muted" />
              Recent Message Investigations ({recentAnalyses.length})
            </h3>
            <p className="text-[11px] text-theme-muted mt-0.5">
              Historical scams inspected by SENTRIX message threat engine.
            </p>
          </div>
        </div>

        {loadingHistory ? (
          <div className="py-6 flex justify-center">
            <RefreshCw className="w-5 h-5 animate-spin text-theme-accent" />
          </div>
        ) : recentAnalyses.length === 0 ? (
          <p className="text-xs font-mono text-theme-muted py-6 text-center">
            No previous message investigations found. Use presets above to run a scan.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-theme-border text-theme-muted uppercase text-[10px]">
                  <th className="py-2 px-3">Verdict</th>
                  <th className="py-2 px-3">Score</th>
                  <th className="py-2 px-3">Channel</th>
                  <th className="py-2 px-3">Message Excerpt</th>
                  <th className="py-2 px-3">Tactics</th>
                  <th className="py-2 px-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-border/50">
                {recentAnalyses.map((item) => (
                  <tr key={item._id} className="hover:bg-theme-elevated/40 transition-colors">
                    <td className="py-2.5 px-3">
                      <RiskBadge verdict={item.classification} size="sm" />
                    </td>
                    <td className="py-2.5 px-3 font-bold text-theme-text">
                      {item.riskScore}
                    </td>
                    <td className="py-2.5 px-3 text-theme-muted text-[11px]">
                      {item.channel}
                    </td>
                    <td className="py-2.5 px-3 max-w-[280px] truncate text-theme-muted font-sans text-[11px]">
                      {item.preview}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-theme-elevated text-theme-muted">
                        {item.detectedPatterns?.length || 0} tactic(s)
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          setCurrentAnalysis(item);
                          window.scrollTo({ top: 300, behavior: 'smooth' });
                        }}
                        className="text-theme-accent hover:underline text-[11px] font-medium"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
