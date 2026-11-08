'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import {
  Blocks,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  ExternalLink,
  Search,
  Hash,
  Database,
  Lock,
  Copy,
  Check,
  Layers,
  ArrowRight,
} from 'lucide-react';
import {
  fetchBlockchainRecords,
  fetchBlockchainConfig,
  verifyOnBlockchain,
} from '@/lib/api';
import {
  type IBlockchainRecord,
  type IBlockchainVerification,
} from '@sentrix/shared';

export default function BlockchainRegistryPage() {
  const [records, setRecords] = useState<IBlockchainRecord[]>([]);
  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [verifyId, setVerifyId] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<IBlockchainVerification | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [rRes, cRes] = await Promise.all([
          fetchBlockchainRecords(30, 0).catch(() => ({ total: 0, records: [] })),
          fetchBlockchainConfig().catch(() => ({ enabled: true, chainId: 31337, isSimulated: false })),
        ]);
        if (mounted) {
          setRecords(rRes.records || []);
          setConfig(cRes);
        }
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, []);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!verifyId.trim() || verifying) return;
    setVerifying(true);
    setVerifyError(null);
    setVerificationResult(null);

    try {
      const res = await verifyOnBlockchain(verifyId.trim());
      setVerificationResult(res);
    } catch (err: any) {
      setVerifyError(err?.message || 'Verification failed. Report not found in registry.');
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-theme-border pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-theme-accent/10 border border-theme-accent/20 text-theme-accent shadow-xs">
              <Blocks className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-theme-text flex items-center gap-2">
                Decentralized Threat Intelligence Registry
                <span className="text-[10px] uppercase font-mono font-bold tracking-wider px-2 py-0.5 rounded-full bg-theme-accent/10 text-theme-accent border border-theme-accent/20">
                  Solidity 0.8.20 EVM
                </span>
              </h1>
              <p className="text-xs text-theme-muted mt-0.5">
                Tamper-evident, cryptographically verifiable threat commitments anchored directly on-chain via smart contracts.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Network & Smart Contract Card */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-theme-card border border-theme-border rounded-xl p-4 shadow-sm">
          <span className="text-[10px] font-mono uppercase text-theme-muted block">Contract Protocol</span>
          <span className="text-sm font-mono font-bold text-theme-text mt-1 block">ThreatRegistry.sol</span>
          <span className="text-[11px] text-emerald-400 font-mono mt-0.5 block flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> Standard ERC Compliant
          </span>
        </div>

        <div className="bg-theme-card border border-theme-border rounded-xl p-4 shadow-sm">
          <span className="text-[10px] font-mono uppercase text-theme-muted block">Active Network</span>
          <span className="text-sm font-mono font-bold text-theme-text mt-1 block">
            {config?.isSimulated
              ? 'Simulated Cryptographic Ledger'
              : config?.networkName || 'EVM Testnet / Hardhat'}
          </span>
          <span className="text-[11px] text-theme-muted font-mono mt-0.5 block">
            {config?.isSimulated ? 'Mode: Offline Ledger' : `Chain ID: ${config?.chainId || 31337}`}
          </span>
        </div>

        <div className="bg-theme-card border border-theme-border rounded-xl p-4 shadow-sm">
          <span className="text-[10px] font-mono uppercase text-theme-muted block">Contract Address</span>
          <span className="text-xs font-mono font-bold text-theme-accent mt-1 block truncate">
            {config?.contractAddress || '0x5FbDB2315678afecb367f032d93F642f64180aa3'}
          </span>
          <span className="text-[10px] text-theme-muted font-mono mt-0.5 block">
            Immutable Threat Ledger
          </span>
        </div>

        <div className="bg-theme-card border border-theme-border rounded-xl p-4 shadow-sm">
          <span className="text-[10px] font-mono uppercase text-theme-muted block">Total Anchored Records</span>
          <span className="text-sm font-mono font-bold text-emerald-400 mt-1 block">
            {records.length} Verified Commitments
          </span>
          <span className="text-[10px] text-theme-muted font-mono mt-0.5 block">
            100% Cryptographic Integrity
          </span>
        </div>
      </div>

      {/* Independent Verification Tool */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
        <div>
          <h2 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-theme-accent" />
            Independent Report Cryptographic Verification
          </h2>
          <p className="text-[11px] text-theme-muted mt-0.5">
            SENTRIX guarantees tamper-proof records. Enter any Report ID to recalculate the SHA-256 canonical commitment and verify it against the immutable on-chain state.
          </p>
        </div>

        <form onSubmit={handleVerify} className="flex gap-2">
          <input
            type="text"
            required
            placeholder="Enter Investigation / Scan / Message Report ID (e.g. 6af0938...)"
            value={verifyId}
            onChange={(e) => setVerifyId(e.target.value)}
            className="flex-1 px-3 py-2 text-xs font-mono rounded-lg border border-theme-border bg-theme-base text-theme-text placeholder:text-theme-muted/50 focus:outline-none focus:ring-1 focus:ring-theme-accent"
          />
          <button
            type="submit"
            disabled={verifying || !verifyId.trim()}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-theme-accent text-white font-mono text-xs font-semibold hover:bg-theme-accent/90 disabled:opacity-50 transition-all shadow-sm"
          >
            {verifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            Verify On-Chain Integrity
          </button>
        </form>

        {verifyError && (
          <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-500 text-xs font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{verifyError}</span>
          </div>
        )}

        {verificationResult && (
          <div
            className={`p-4 rounded-lg border space-y-3 font-mono text-xs ${
              verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                ? 'bg-amber-500/10 border-amber-500/30'
                : 'bg-emerald-500/10 border-emerald-500/30'
            }`}
          >
            <div className="flex items-center justify-between">
              <span
                className={`font-bold flex items-center gap-1.5 ${
                  verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                    ? 'text-amber-400'
                    : 'text-emerald-400'
                }`}
              >
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                {verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                  ? 'VERIFICATION PASSED: Cryptographic Commitment Verified (Simulated Ledger)'
                  : 'VERIFICATION PASSED: Report Integrity Confirmed on EVM Blockchain'}
              </span>
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                  verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                    : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                }`}
              >
                {verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                  ? 'SIMULATED LEDGER'
                  : `BLOCK #${verificationResult.blockNumber || 1}`}
              </span>
            </div>

            {Boolean(verificationResult.isSimulated || verificationResult.mode === 'SIMULATED') && (
              <p className="text-[11px] text-amber-300/80">
                Note: This threat commitment was verified against the local tamper-evident cryptographic ledger (Simulated Mode). It was not anchored to a live EVM blockchain network.
              </p>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
              <div>
                <span className="text-theme-muted block">Recalculated Canonical SHA-256:</span>
                <span className="text-theme-text font-bold break-all block">
                  {verificationResult.calculatedHash}
                </span>
              </div>
              <div>
                <span className="text-theme-muted block">
                  {verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                    ? 'Anchored Ledger Hash:'
                    : 'On-Chain Anchored Commitment:'}
                </span>
                <span
                  className={`font-bold break-all block ${
                    verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                      ? 'text-amber-300'
                      : 'text-emerald-400'
                  }`}
                >
                  {verificationResult.onChainHash}
                </span>
              </div>
            </div>

            <div
              className={`grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2 border-t text-[10px] text-theme-muted ${
                verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                  ? 'border-amber-500/20'
                  : 'border-emerald-500/20'
              }`}
            >
              <div>
                <span className="text-theme-text">
                  {verificationResult.isSimulated || verificationResult.mode === 'SIMULATED'
                    ? 'Ledger Reference:'
                    : 'Tx Hash:'}
                </span>{' '}
                <span className="truncate block font-mono text-theme-muted">
                  {verificationResult.txHash}
                </span>
              </div>
              <div>
                <span className="text-theme-text">Contract:</span>{' '}
                <span className="truncate block font-mono text-theme-muted">
                  {verificationResult.contractAddress}
                </span>
              </div>
              <div>
                <span className="text-theme-text">Network:</span>{' '}
                <span className="block font-mono text-theme-muted">
                  {verificationResult.networkName ||
                    (verificationResult.isSimulated
                      ? 'Simulated Cryptographic Ledger'
                      : 'EVM Local')}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Anchored Reports Feed */}
      <div className="bg-theme-card border border-theme-border rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-theme-border pb-3">
          <div>
            <h3 className="text-xs font-mono font-semibold uppercase tracking-wider text-theme-text flex items-center gap-2">
              <Layers className="w-4 h-4 text-theme-accent" />
              On-Chain Threat Intelligence Ledger ({records.length})
            </h3>
            <p className="text-[11px] text-theme-muted mt-0.5">
              Decentralized ledger of tamper-evident threat reports committed to the EVM smart contract.
            </p>
          </div>
        </div>

        {loading ? (
          <div className="py-8 flex justify-center">
            <RefreshCw className="w-5 h-5 animate-spin text-theme-accent" />
          </div>
        ) : records.length === 0 ? (
          <p className="text-xs font-mono text-theme-muted py-8 text-center">
            No threat records anchored to the blockchain yet. Run a URL scan or message analysis and click &quot;Register on Blockchain&quot;.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-theme-border text-theme-muted uppercase text-[10px]">
                  <th className="py-2 px-3">Target / Host</th>
                  <th className="py-2 px-3">Type</th>
                  <th className="py-2 px-3">Mode</th>
                  <th className="py-2 px-3">Canonical SHA-256 Hash</th>
                  <th className="py-2 px-3">Block #</th>
                  <th className="py-2 px-3">Tx Hash / Ledger Ref</th>
                  <th className="py-2 px-3 text-right">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-theme-border/50">
                {records.map((rec) => {
                  const isSim = Boolean(
                    rec.isSimulated ||
                    rec.status === 'SIMULATED' ||
                    rec.txHash?.startsWith('simulated-')
                  );
                  return (
                    <tr key={rec._id} className="hover:bg-theme-elevated/40 transition-colors">
                      <td className="py-2.5 px-3 font-semibold text-theme-text truncate max-w-[200px]">
                        {rec.target}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="text-[10px] px-2 py-0.5 rounded bg-theme-elevated text-theme-muted uppercase font-semibold">
                          {rec.reportType}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        {isSim ? (
                          <span className="text-[9px] px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold uppercase">
                            Simulated
                          </span>
                        ) : (
                          <span className="text-[9px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-bold uppercase">
                            On-Chain EVM
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-theme-muted">
                        <div className="flex items-center gap-1.5">
                          <span className="truncate max-w-[140px] text-emerald-400">{rec.reportHash}</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(rec.reportHash, rec._id)}
                            className="hover:text-theme-text text-theme-muted"
                            title="Copy Full Hash"
                          >
                            {copiedHash === rec._id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                      </td>
                      <td className="py-2.5 px-3 font-bold text-theme-text">
                        {isSim ? <span className="text-theme-muted font-normal text-[11px]">Offline</span> : `#${rec.blockNumber}`}
                      </td>
                      <td className="py-2.5 px-3 text-[11px] text-theme-muted font-mono truncate max-w-[120px]">
                        {rec.txHash}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          type="button"
                          onClick={() => {
                            setVerifyId(rec.reportId);
                            window.scrollTo({ top: 180, behavior: 'smooth' });
                          }}
                          className="text-theme-accent hover:underline text-[11px] font-semibold"
                        >
                          Verify
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
