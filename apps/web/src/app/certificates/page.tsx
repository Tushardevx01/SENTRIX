'use client';

import React, { useState } from 'react';
import {
  Lock,
  ShieldCheck,
  Calendar,
  Key,
  Globe,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Hash,
  Search,
  Server,
  Layers,
  FileCheck,
  Clock,
  Sparkles,
} from 'lucide-react';
import { motion } from 'framer-motion';

export default function CertificateIntelligencePage() {
  const [domainInput, setDomainInput] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('cloudflare');

  const certificatesData: Record<
    string,
    {
      domain: string;
      subject: string;
      issuer: string;
      rootCA: string;
      intermediateCA: string;
      validFrom: string;
      validUntil: string;
      daysRemaining: number;
      fingerprint: string;
      keyAlgorithm: string;
      signatureAlgorithm: string;
      sanList: string[];
      ctLogging: boolean;
      revocationCheck: string;
      hostnameMatched: boolean;
    }
  > = {
    cloudflare: {
      domain: 'cloudflare.com',
      subject: 'CN = cloudflare.com, O = Cloudflare, Inc.',
      issuer: 'CN = Cloudflare Inc ECC CA-3, O = Cloudflare, Inc., C = US',
      rootCA: 'Baltimore CyberTrust Root',
      intermediateCA: 'Cloudflare Inc ECC CA-3',
      validFrom: '2026-02-14',
      validUntil: '2027-02-14',
      daysRemaining: 98,
      fingerprint: '3B:9A:81:4F:92:D1:6C:EE:81:04:12:F6:AB:44:09:A1:6D:FE:71:04',
      keyAlgorithm: 'ECDSA 256-bit (secp256r1)',
      signatureAlgorithm: 'SHA256withECDSA',
      sanList: ['cloudflare.com', '*.cloudflare.com'],
      ctLogging: true,
      revocationCheck: 'OCSP Stapling Active (Good)',
      hostnameMatched: true,
    },
    google: {
      domain: 'accounts.google.com',
      subject: 'CN = *.google.com, O = Google LLC',
      issuer: 'CN = WR2, O = Google Trust Services LLC, C = US',
      rootCA: 'GTS Root R1',
      intermediateCA: 'Google Trust Services WR2',
      validFrom: '2026-08-01',
      validUntil: '2026-10-24',
      daysRemaining: 14,
      fingerprint: '9E:B1:02:44:8D:11:FE:23:41:09:AA:12:90:BB:72:01:84:16:D2:FF',
      keyAlgorithm: 'ECDSA 256-bit (prime256v1)',
      signatureAlgorithm: 'SHA256withECDSA',
      sanList: ['*.google.com', '*.android.com', 'google.com'],
      ctLogging: true,
      revocationCheck: 'CRLSets / OCSP Must-Staple Validated',
      hostnameMatched: true,
    },
    untrusted: {
      domain: 'paypal-security-update.xyz',
      subject: 'CN = paypal-security-update.xyz',
      issuer: 'CN = Untrusted Self-Signed Root, OU = Hackers, C = XX',
      rootCA: 'Untrusted Self-Signed Root',
      intermediateCA: 'None (Direct Self-Signed)',
      validFrom: '2025-01-01',
      validUntil: '2025-06-01',
      daysRemaining: -524,
      fingerprint: 'E4:10:99:A2:3B:55:01:FE:78:12:90:44:AA:11:00:88:91:DE:33:14',
      keyAlgorithm: 'RSA 1024-bit (Deprecate: Insecure Key Length)',
      signatureAlgorithm: 'SHA1withRSA (Insecure Hash)',
      sanList: ['paypal-security-update.xyz'],
      ctLogging: false,
      revocationCheck: 'Unchecked / No CRL or OCSP responder provided',
      hostnameMatched: false,
    },
  };

  const activeCert =
    domainInput.trim() && domainInput in certificatesData
      ? certificatesData[domainInput]
      : certificatesData[selectedPreset];

  return (
    <div className="space-y-8 py-2 max-w-5xl mx-auto">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-theme-accent/10 border border-theme-accent/20 text-theme-accent text-xs font-mono font-medium">
          <Lock className="w-3.5 h-3.5" />
          <span>X.509 Cryptographic Audit</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-theme-text font-mono tracking-tight">
          CERTIFICATE INTELLIGENCE
        </h1>
        <p className="text-xs text-theme-muted font-mono max-w-2xl">
          Inspect SSL/TLS certificate chains, public key parameters, Certificate Transparency logs,
          and expiration countdowns in real-time.
        </p>
      </div>

      {/* Preset Selector & Domain Quick Lookup */}
      <div className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 w-full sm:w-auto">
            <span className="text-xs font-mono text-theme-muted shrink-0">Sample Targets:</span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('cloudflare');
                  setDomainInput('');
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all ${
                  selectedPreset === 'cloudflare' && !domainInput
                    ? 'bg-theme-accent text-white dark:text-slate-950 font-bold'
                    : 'bg-theme-elevated text-theme-muted hover:text-theme-text'
                }`}
              >
                Cloudflare
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('google');
                  setDomainInput('');
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all ${
                  selectedPreset === 'google' && !domainInput
                    ? 'bg-theme-accent text-white dark:text-slate-950 font-bold'
                    : 'bg-theme-elevated text-theme-muted hover:text-theme-text'
                }`}
              >
                Google Auth
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('untrusted');
                  setDomainInput('');
                }}
                className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all ${
                  selectedPreset === 'untrusted' && !domainInput
                    ? 'bg-theme-danger text-white font-bold'
                    : 'bg-theme-elevated text-theme-muted hover:text-theme-text'
                }`}
              >
                Untrusted Impersonator
              </button>
            </div>
          </div>

          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-theme-muted" />
            <input
              type="text"
              placeholder="Lookup target domain..."
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs font-mono bg-theme-bg border border-theme-border rounded-lg text-theme-text focus:outline-none focus:border-theme-accent"
            />
          </div>
        </div>
      </div>

      {/* Main Certificate Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trust Chain Hierarchy */}
        <div className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-theme-text">
            <Layers className="w-4 h-4 text-theme-accent" />
            <span>CERTIFICATE TRUST CHAIN</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {/* Root CA */}
            <div className="p-3 bg-theme-elevated rounded-lg border border-theme-borderSubtle space-y-1">
              <span className="text-[10px] uppercase font-bold text-theme-muted block">
                01 / Root Authority (Trust Store)
              </span>
              <span className="font-semibold text-theme-text block">{activeCert.rootCA}</span>
              <span className="text-[11px] text-theme-success flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> System Trust Store Validated
              </span>
            </div>

            <div className="w-0.5 h-4 bg-theme-border mx-auto" />

            {/* Intermediate CA */}
            <div className="p-3 bg-theme-elevated rounded-lg border border-theme-borderSubtle space-y-1">
              <span className="text-[10px] uppercase font-bold text-theme-muted block">
                02 / Intermediate Authority
              </span>
              <span className="font-semibold text-theme-text block">{activeCert.intermediateCA}</span>
              <span className="text-[11px] text-theme-muted">Chain verification passed</span>
            </div>

            <div className="w-0.5 h-4 bg-theme-border mx-auto" />

            {/* Leaf Certificate */}
            <div
              className={`p-3 rounded-lg border space-y-1 ${
                activeCert.hostnameMatched
                  ? 'bg-theme-card border-theme-accent/40'
                  : 'bg-theme-danger/10 border-theme-danger/40'
              }`}
            >
              <span className="text-[10px] uppercase font-bold text-theme-muted block">
                03 / End-Entity Leaf Certificate
              </span>
              <span className="font-bold text-theme-text block">{activeCert.domain}</span>
              {activeCert.hostnameMatched ? (
                <span className="text-[11px] text-theme-success flex items-center gap-1 font-semibold">
                  <CheckCircle2 className="w-3 h-3" /> Matching SNI & Hostname
                </span>
              ) : (
                <span className="text-[11px] text-theme-danger flex items-center gap-1 font-semibold">
                  <XCircle className="w-3 h-3" /> Hostname Mismatch Alert
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Cryptographic Parameters & Validity Countdown */}
        <div className="lg:col-span-2 space-y-4">
          {/* Validity & Expiration Card */}
          <div className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-theme-borderSubtle">
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-theme-accent" />
                <h3 className="text-sm font-bold font-mono text-theme-text">VALIDITY & EXPIRATION</h3>
              </div>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-bold ${
                  activeCert.daysRemaining > 30
                    ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border border-emerald-500/20'
                    : activeCert.daysRemaining > 0
                    ? 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-500/20'
                    : 'bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/20'
                }`}
              >
                {activeCert.daysRemaining > 0
                  ? `${activeCert.daysRemaining} Days Remaining`
                  : `Expired (${Math.abs(activeCert.daysRemaining)} Days Ago)`}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <span className="text-theme-muted block mb-1">Issue Timestamp</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle">
                  {activeCert.validFrom}
                </span>
              </div>
              <div>
                <span className="text-theme-muted block mb-1">Expiration Timestamp</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle">
                  {activeCert.validUntil}
                </span>
              </div>
            </div>
          </div>

          {/* Cryptographic Properties Card */}
          <div className="p-5 rounded-xl border border-theme-border bg-theme-card shadow-xs space-y-4">
            <div className="flex items-center gap-2 pb-3 border-b border-theme-borderSubtle">
              <Key className="w-4 h-4 text-theme-accent" />
              <h3 className="text-sm font-bold font-mono text-theme-text">
                CRYPTOGRAPHIC ATTRIBUTES & LOGGING
              </h3>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
              <div>
                <span className="text-theme-muted block mb-1">Public Key Algorithm</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle">
                  {activeCert.keyAlgorithm}
                </span>
              </div>
              <div>
                <span className="text-theme-muted block mb-1">Signature Algorithm</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle">
                  {activeCert.signatureAlgorithm}
                </span>
              </div>
              <div>
                <span className="text-theme-muted block mb-1">Certificate Transparency</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle flex items-center gap-1.5">
                  {activeCert.ctLogging ? (
                    <>
                      <CheckCircle2 className="w-3.5 h-3.5 text-theme-success" />
                      <span>Embedded SCTs Verified</span>
                    </>
                  ) : (
                    <>
                      <XCircle className="w-3.5 h-3.5 text-theme-danger" />
                      <span>Missing SCT Proof</span>
                    </>
                  )}
                </span>
              </div>
              <div>
                <span className="text-theme-muted block mb-1">Revocation Status Check</span>
                <span className="font-semibold text-theme-text bg-theme-elevated p-2 rounded-lg block border border-theme-borderSubtle truncate">
                  {activeCert.revocationCheck}
                </span>
              </div>
            </div>

            <div>
              <span className="text-theme-muted text-xs font-mono block mb-1">
                Subject Alternative Names (SANs)
              </span>
              <div className="flex flex-wrap gap-1.5 font-mono text-xs">
                {activeCert.sanList.map((san) => (
                  <span
                    key={san}
                    className="px-2 py-0.5 rounded bg-theme-elevated text-theme-text border border-theme-borderSubtle"
                  >
                    {san}
                  </span>
                ))}
              </div>
            </div>

            <div>
              <span className="text-theme-muted text-xs font-mono block mb-1">
                SHA-256 Fingerprint
              </span>
              <span className="block p-2 rounded-lg bg-theme-elevated border border-theme-borderSubtle font-mono text-[11px] text-theme-text break-all">
                {activeCert.fingerprint}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
