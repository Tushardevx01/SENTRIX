'use client';

import React, { useState } from 'react';
import {
  Lock,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  Search,
  Layers,
  Terminal,
  Activity,
} from 'lucide-react';

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
    <div className="space-y-8 py-2 max-w-5xl mx-auto font-mono text-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-neutral-200 dark:border-[#1f1f23] pb-6">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-neutral-100 dark:bg-[#121214] border border-neutral-300 dark:border-[#27272a] text-[11px] text-neutral-600 dark:text-neutral-300">
            <Lock className="w-3.5 h-3.5" />
            <span>[ TLS // X.509 CRYPTOGRAPHIC AUDIT ]</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-serif text-black dark:text-white">
            Certificate Intelligence
          </h1>
          <p className="text-xs text-neutral-500 font-mono max-w-2xl">
            Inspect SSL/TLS trust chains, public key parameters, Certificate Transparency logs, and CA/Browser Forum SC-081v3 compliance.
          </p>
        </div>
      </div>

      {/* Preset Selector & Normal Rounded Search Bar */}
      <div className="p-5 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-card space-y-4">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">
            <span className="text-xs text-neutral-400">Sample targets:</span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('cloudflare');
                  setDomainInput('');
                }}
                className={`px-3 py-1 rounded-full transition-all cursor-pointer ${
                  selectedPreset === 'cloudflare' && !domainInput
                    ? 'btn-industrial text-white'
                    : 'bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300'
                }`}
              >
                Cloudflare ECC
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('google');
                  setDomainInput('');
                }}
                className={`px-3 py-1 rounded-full transition-all cursor-pointer ${
                  selectedPreset === 'google' && !domainInput
                    ? 'btn-industrial text-white'
                    : 'bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300'
                }`}
              >
                Google GTS Root
              </button>
              <button
                type="button"
                onClick={() => {
                  setSelectedPreset('untrusted');
                  setDomainInput('');
                }}
                className={`px-3 py-1 rounded-full transition-all cursor-pointer ${
                  selectedPreset === 'untrusted' && !domainInput
                    ? 'bg-red-600 text-white font-bold'
                    : 'bg-neutral-100 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300'
                }`}
              >
                Untrusted Phish
              </button>
            </div>
          </div>

          {/* Normal Rounded Search Bar */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              placeholder="Lookup domain cert..."
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-full border border-neutral-300 dark:border-[#27272a] bg-neutral-50 dark:bg-[#121214] text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
            />
          </div>
        </div>
      </div>

      {/* Main Certificate Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trust Chain Hierarchy */}
        <div className="p-5 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
          <div className="flex items-center gap-2 text-xs font-bold text-black dark:text-white pb-2 border-b border-neutral-200 dark:border-[#1f1f23]">
            <Layers className="w-4 h-4 text-black dark:text-white" />
            <span>// 01. CERTIFICATE TRUST CHAIN</span>
          </div>

          <div className="space-y-3 font-mono text-xs">
            {/* Root CA */}
            <div className="p-3 bg-neutral-50 dark:bg-[#121214] rounded-lg border border-neutral-200 dark:border-[#27272a] space-y-1">
              <span className="text-[10px] uppercase font-bold text-neutral-400 block font-pixel">
                01 / Root Authority (Trust Store)
              </span>
              <p className="text-black dark:text-white font-semibold truncate">{activeCert.rootCA}</p>
              <div className="flex items-center gap-1.5 text-[10px] text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="w-3 h-3" />
                <span>Operating System Anchor</span>
              </div>
            </div>

            {/* Intermediate CA */}
            <div className="p-3 bg-neutral-50 dark:bg-[#121214] rounded-lg border border-neutral-200 dark:border-[#27272a] space-y-1">
              <span className="text-[10px] uppercase font-bold text-neutral-400 block font-pixel">
                02 / Intermediate Signer
              </span>
              <p className="text-black dark:text-white font-semibold truncate">{activeCert.intermediateCA}</p>
              <span className="text-[10px] text-neutral-500">Cross-Signed Authority</span>
            </div>

            {/* Leaf Certificate */}
            <div className="p-3 bg-neutral-50 dark:bg-[#121214] rounded-lg border border-neutral-200 dark:border-[#27272a] space-y-1">
              <span className="text-[10px] uppercase font-bold text-neutral-400 block font-pixel">
                03 / End-Entity Subscriber Leaf
              </span>
              <p className="text-black dark:text-white font-semibold truncate">{activeCert.domain}</p>
              <div className="flex items-center gap-1.5 text-[10px] text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="w-3 h-3" />
                <span>Hostname Matched</span>
              </div>
            </div>
          </div>
        </div>

        {/* Cryptographic Parameters */}
        <div className="lg:col-span-2 p-5 rounded-xl border border-neutral-200 dark:border-[#27272a] bg-white dark:bg-[#0c0c0e] shadow-xs space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-[#1f1f23]">
            <span className="font-bold uppercase tracking-wider text-black dark:text-white flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              // 02. CRYPTOGRAPHIC EVIDENCE & VALIDITY SCHEDULE
            </span>
            <span className="text-[10px] text-neutral-500 font-pixel">X.509 v3</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-neutral-400 block">Public Key Algorithm</span>
              <p className="font-semibold text-black dark:text-white">{activeCert.keyAlgorithm}</p>
            </div>
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-neutral-400 block">Signature Digest Algorithm</span>
              <p className="font-semibold text-black dark:text-white">{activeCert.signatureAlgorithm}</p>
            </div>
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-neutral-400 block">Issuance Date</span>
              <p className="text-neutral-600 dark:text-neutral-300">{activeCert.validFrom}</p>
            </div>
            <div className="space-y-1">
              <span className="text-[10px] uppercase text-neutral-400 block">Expiration Timestamp</span>
              <p className="text-neutral-600 dark:text-neutral-300">{activeCert.validUntil} ({activeCert.daysRemaining} days remaining)</p>
            </div>
            <div className="md:col-span-2 space-y-1">
              <span className="text-[10px] uppercase text-neutral-400 block">SHA-256 Fingerprint</span>
              <p className="p-2 rounded bg-neutral-50 dark:bg-[#121214] border border-neutral-200 dark:border-[#27272a] font-mono text-[11px] truncate text-black dark:text-white">
                {activeCert.fingerprint}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
