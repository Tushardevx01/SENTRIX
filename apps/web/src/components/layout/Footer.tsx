'use client';

import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Sparkles } from 'lucide-react';
import HalftoneWordmarkFooter, { FooterColumn } from '@/components/ui/halftone-wordmark-footer';

const SENTRIX_COLUMNS: FooterColumn[] = [
  {
    title: 'Platform',
    links: [
      { label: 'Threat Scanner', href: '/scanner' },
      { label: 'Command Telemetry', href: '/dashboard' },
      { label: 'Threat Intel Feed', href: '/intelligence' },
      { label: 'Community Feed', href: '/community' },
    ],
  },
  {
    title: 'Security',
    links: [
      { label: 'X.509 Cryptography', href: '/certificates' },
      { label: 'EVM Threat Registry', href: '/blockchain' },
      { label: 'Scam Analyzer', href: '/messages' },
      { label: 'Responsible Disclosure', href: '/settings' },
    ],
  },
  {
    title: 'Community',
    links: [
      { label: 'Star on GitHub', href: 'https://github.com/Tushardevx01/SENTRIX/' },
      { label: 'Audit Logs', href: '/history' },
      { label: 'System Overview', href: '/' },
    ],
  },
];

export const Footer: React.FC = () => {
  return (
    <footer className="relative w-full bg-[#050507] text-[#FAFAFA] overflow-hidden pt-20 transition-colors select-none">
      {/* Smooth Top Gradient Masking Transition */}
      <div className="absolute -top-28 inset-x-0 h-28 bg-gradient-to-b from-transparent via-[#050507]/60 to-[#050507] pointer-events-none" />
      <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-white/20 via-cyan-400/30 to-transparent pointer-events-none" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[700px] h-20 bg-gradient-to-b from-cyan-500/10 via-transparent to-transparent blur-2xl pointer-events-none" />

      {/* Background radial gradient glow */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[300px] bg-gradient-to-b from-white/[0.04] via-transparent to-transparent pointer-events-none rounded-full blur-3xl" />

      {/* Floating Asteroid / Waitlist / Journey Simulation */}
      <div className="relative max-w-7xl mx-auto px-6 sm:px-8 mb-10 text-center">
        <div className="relative py-8 flex flex-col items-center justify-center space-y-5">
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.8 }}
            className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-white/[0.03] border border-white/10 text-[11px] font-mono text-neutral-400"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            <span>THE MODERN WEB TRUST LAYER</span>
          </motion.div>

          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.1 }}
            className="text-4xl sm:text-6xl font-serif tracking-tight text-white max-w-2xl"
          >
            Start your journey
          </motion.h2>

          <motion.p
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.2 }}
            className="text-xs sm:text-sm font-sans text-neutral-400 max-w-md mx-auto"
          >
            Inspect suspicious links, verify TLS certificate validity, and collaborate with real-time cybersecurity intelligence.
          </motion.p>

          <motion.form
            initial={{ opacity: 0, y: 15 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.7, delay: 0.3 }}
            onSubmit={(e) => {
              e.preventDefault();
              window.location.href = '/scanner';
            }}
            className="flex items-center w-full max-w-md p-1.5 rounded-full bg-white/[0.04] border border-white/10 backdrop-blur-md shadow-2xl"
          >
            <input
              type="text"
              placeholder="Enter target URL or email..."
              className="flex-1 bg-transparent px-4 py-2 text-xs font-mono text-white placeholder:text-neutral-500 focus:outline-none"
            />
            <button
              type="submit"
              className="px-5 py-2 rounded-full bg-white text-black hover:bg-neutral-200 text-xs font-mono font-bold transition-all shrink-0 cursor-pointer shadow-md"
            >
              Verify Threat
            </button>
          </motion.form>
        </div>
      </div>

      {/* Animated Halftone Wordmark Footer Component */}
      <HalftoneWordmarkFooter
        wordmark="sentrix"
        label="SENTRIX Defense"
        meta="© 2026 · Autonomous Trust Engine"
        columns={SENTRIX_COLUMNS}
        backToTop={true}
        preset="night"
        palette={{
          background: "#050507",
          ink: "#e9e4da",
          warm: "#00E5FF",
        }}
        dotGap={6}
        radius={85}
        crop={0.18}
        grain={0.4}
        interactive={true}
        height="520px"
      />
    </footer>
  );
};

export default Footer;
