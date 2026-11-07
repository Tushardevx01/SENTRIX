'use client';

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldCheck,
  History,
  Radio,
  Users,
  ExternalLink,
  ShieldAlert,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  const links = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/scanner', label: 'Threat Scanner', icon: ShieldCheck },
    { href: '/history', label: 'Scan History', icon: History },
    { href: '/intelligence', label: 'Threat Intel', icon: Radio },
    { href: '/community', label: 'Community Feed', icon: Users },
  ];

  return (
    <aside className="w-64 border-r border-slate-800 bg-navy-950/60 hidden md:flex flex-col justify-between p-4 min-h-[calc(100vh-4rem)]">
      <div className="space-y-6">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500 px-3">
            Core Security Tools
          </span>
          <nav className="mt-2 space-y-1">
            {links.map((link) => {
              const Icon = link.icon;
              const isActive = pathname === link.href || (link.href !== '/' && pathname.startsWith(link.href));
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={cn(
                    'flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all',
                    isActive
                      ? 'bg-electric-500/10 text-electric-400 border border-electric-500/20 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                  )}
                >
                  <Icon className={cn('w-4 h-4', isActive ? 'text-electric-400' : 'text-slate-500')} />
                  {link.label}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Security Alert Badge */}
        <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-lg">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-200 mb-1">
            <ShieldAlert className="w-4 h-4 text-electric-400" />
            <span>Zero-Trust Protocol</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed font-mono">
            Every inspection undergoes multi-vector SSRF-safe analysis, cryptographic verification, and heuristic evaluation.
          </p>
        </div>
      </div>

      <div className="pt-4 border-t border-slate-800 text-[11px] font-mono text-slate-500 flex justify-between items-center px-2">
        <span>SENTRIX v1.0</span>
        <span className="text-emerald-400">Node/Fastify/Python</span>
      </div>
    </aside>
  );
};
