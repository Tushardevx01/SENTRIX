'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Shield, Radio, ArrowUpRight, Search } from 'lucide-react';
import { cn } from '@/lib/utils';

export const Header: React.FC = () => {
  const pathname = usePathname();

  const navLinks = [
    { href: '/dashboard', label: 'Dashboard' },
    { href: '/scanner', label: 'URL Threat Scanner' },
    { href: '/history', label: 'Scan History' },
    { href: '/intelligence', label: 'Threat Intel' },
    { href: '/community', label: 'Community Feed' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800 bg-background/80 backdrop-blur-md">
      <div className="flex h-16 items-center justify-between px-4 sm:px-6">
        {/* Brand */}
        <div className="flex items-center gap-6">
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 rounded-lg bg-electric-500/10 border border-electric-500/40 flex items-center justify-center group-hover:border-electric-400 group-hover:shadow-glow transition-all">
              <Shield className="w-5 h-5 text-electric-400" />
            </div>
            <div>
              <span className="text-lg font-black tracking-wider text-white font-mono group-hover:text-electric-300 transition-colors">
                SENTRIX
              </span>
              <span className="hidden sm:block text-[10px] text-slate-400 font-mono -mt-1 tracking-tight">
                Trust Intelligence Platform
              </span>
            </div>
          </Link>

          {/* Desktop Nav */}
          <nav className="hidden md:flex items-center gap-1">
            {navLinks.map((link) => {
              const isActive = pathname === link.href || (link.href !== '/' && pathname.startsWith(link.href));
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    'px-3 py-1.5 rounded-md text-xs font-medium font-mono transition-colors',
                    isActive
                      ? 'text-electric-400 bg-electric-500/10 border border-electric-500/20'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                  )}
                >
                  {link.label}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Right CTA & System Status */}
        <div className="flex items-center gap-3">
          <div className="hidden lg:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-950/40 border border-emerald-500/30 text-[11px] font-mono text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Engine Online
          </div>

          <Link
            href="/scanner"
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 bg-electric-500 hover:bg-electric-400 text-slate-950 font-semibold rounded-md text-xs transition-all shadow-glow hover:shadow-cyan-400/40"
          >
            <Search className="w-3.5 h-3.5" />
            New Scan
          </Link>
        </div>
      </div>
    </header>
  );
};
