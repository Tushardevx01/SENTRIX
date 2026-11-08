'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield,
  Search,
  Bell,
  Menu,
  Activity,
  ExternalLink,
  LogIn,
  LogOut,
  User,
} from 'lucide-react';
import { AnimatedThemeToggler } from '@/registry/magicui/animated-theme-toggler';
import { SparkleButton } from '@/components/ui/SparkleButton';
import { useAuth } from '@/contexts/AuthContext';

interface HeaderProps {
  onToggleMobileSidebar?: () => void;
  isLanding?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onToggleMobileSidebar, isLanding = false }) => {
  const pathname = usePathname();
  const router = useRouter();
  const { user, isAuthenticated, logout, openAuthModal } = useAuth();
  const [showNotifications, setShowNotifications] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const getBreadcrumb = () => {
    if (pathname === '/') return 'SYSTEM OVERVIEW';
    if (pathname === '/login') return 'OPERATOR LOGIN';
    if (pathname === '/dashboard') return 'COMMAND CENTER';
    if (pathname === '/scanner') return 'URL THREAT SCANNER';
    if (pathname === '/messages') return 'SCAM MESSAGE ANALYZER';
    if (pathname?.startsWith('/reports')) return 'FORENSIC REPORT';
    if (pathname === '/intelligence') return 'THREAT INTELLIGENCE';
    if (pathname === '/correlations') return 'CAMPAIGN GRAPH';
    if (pathname === '/blockchain') return 'EVM THREAT REGISTRY';
    if (pathname === '/certificates') return 'X.509 CERTIFICATES';
    if (pathname === '/assessment') return 'SECURITY ASSESSMENT';
    if (pathname === '/community') return 'COMMUNITY FEED';
    if (pathname === '/history') return 'AUDIT SCAN HISTORY';
    if (pathname === '/settings') return 'CONFIGURATION';
    return 'SECURITY SUITE';
  };

  const handleGlobalSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;
    const q = searchQuery.trim();
    if (q.startsWith('http://') || q.startsWith('https://') || q.includes('.')) {
      router.push(`/scanner?target=${encodeURIComponent(q)}`);
    } else {
      router.push(`/intelligence?q=${encodeURIComponent(q)}`);
    }
    setSearchQuery('');
  };

  const mockNotifications = [
    {
      id: '1',
      title: 'CRITICAL: Hostile Redirect Blocked',
      detail: 'SSRF & credential harvester detected on suspicious target.',
      time: '04m ago',
    },
    {
      id: '2',
      title: 'X.509 CA Incident Detected',
      detail: 'eMudhra compromised sub-CA certificate detected and flagged.',
      time: '18m ago',
    },
    {
      id: '3',
      title: 'EVM Commitment Confirmed',
      detail: 'Canonical SHA-256 report anchored on Solidity smart contract.',
      time: '42m ago',
    },
  ];

  return (
    <header className="sticky top-0 z-50 w-full border-b border-black/[0.08] dark:border-white/[0.08] bg-white/70 dark:bg-[#050507]/70 backdrop-blur-xl transition-all shadow-xs">
      <div className="flex h-16 items-center justify-between px-4 sm:px-6 max-w-7xl mx-auto">
        {/* Left Section: Logo & Breadcrumbs */}
        <div className="flex items-center gap-3">
          {/* Mobile hamburger */}
          <button
            onClick={onToggleMobileSidebar}
            type="button"
            className="p-2 rounded-md border border-neutral-300 dark:border-[#27272a] text-neutral-600 dark:text-neutral-300 hover:text-black dark:hover:text-white md:hidden cursor-pointer"
            aria-label="Toggle navigation"
          >
            <Menu className="w-4 h-4" />
          </button>

          {/* SENTRIX Minimal Logo */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-7 h-7 rounded-md bg-[#18181b] border border-[#27272a] flex items-center justify-center text-white shadow-xs group-hover:scale-105 transition-transform">
              <Shield className="w-3.5 h-3.5 text-cyan-400" />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-extrabold tracking-tight font-mono text-black dark:text-white group-hover:text-neutral-600 dark:group-hover:text-neutral-300 transition-colors">
                SENTRIX
              </span>
              <span className="hidden sm:inline-block text-[9px] font-pixel px-1.5 py-0.5 rounded bg-neutral-100 dark:bg-[#18181b] text-neutral-700 dark:text-neutral-300 border border-neutral-200 dark:border-[#27272a]">
                v1.0
              </span>
            </div>
          </Link>

          {/* Breadcrumb separator */}
          {!isLanding && (
            <div className="hidden md:flex items-center gap-2 text-[11px] font-mono pl-3 border-l border-neutral-200 dark:border-[#27272a] text-neutral-500">
              <span>//</span>
              <span className="font-semibold text-black dark:text-neutral-200 tracking-wide">
                {getBreadcrumb()}
              </span>
            </div>
          )}
        </div>

        {/* Center: Global Search Bar */}
        <div className="hidden lg:flex items-center flex-1 max-w-xs xl:max-w-sm mx-4">
          <form onSubmit={handleGlobalSearch} className="w-full relative">
            <Search className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-neutral-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search target URL or SHA-256..."
              className="w-full pl-9 pr-10 py-1.5 text-xs font-mono rounded-full border border-neutral-200 dark:border-[#27272a] bg-neutral-100/60 dark:bg-[#121214]/60 text-black dark:text-white placeholder:text-neutral-400 focus:outline-none focus:border-black dark:focus:border-white transition-all"
            />
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[9px] font-mono text-neutral-400">
              ↵
            </span>
          </form>
        </div>

        {/* Right Section: Controls, GitHub Star Badge, Theme Toggle & Auth */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* GitHub Star Badge (Provided component) */}
          <div className="hidden sm:block">
            <SparkleButton />
          </div>

          {/* Animated MagicUI Theme Toggler */}
          <AnimatedThemeToggler />

          {/* Notifications Dropdown */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              type="button"
              aria-label="Alerts"
              className="p-2 rounded-full border border-neutral-200 dark:border-[#27272a] bg-neutral-100/80 dark:bg-[#121214]/80 hover:bg-neutral-200 dark:hover:bg-[#18181b] transition-colors cursor-pointer"
            >
              <Bell className="w-3.5 h-3.5 text-neutral-600 dark:text-neutral-300" />
              <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-cyan-400" />
            </button>

            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-[#0c0c0e] border border-neutral-200 dark:border-[#27272a] rounded-xl shadow-2xl p-3.5 z-50 text-xs font-mono">
                <div className="flex items-center justify-between pb-2 border-b border-neutral-200 dark:border-[#1f1f23]">
                  <span className="font-semibold text-black dark:text-white text-[11px] uppercase tracking-wider">
                    // SYSTEM ALERTS
                  </span>
                  <span className="text-[10px] text-cyan-400 font-pixel">[3]</span>
                </div>
                <div className="divide-y divide-neutral-100 dark:divide-[#18181b] mt-1">
                  {mockNotifications.map((n) => (
                    <div key={n.id} className="py-2.5 hover:bg-neutral-50 dark:hover:bg-[#141416] px-1.5 rounded transition-colors">
                      <div className="flex items-center justify-between font-medium text-black dark:text-neutral-200">
                        <span className="truncate pr-2 text-[11px] font-bold">{n.title}</span>
                        <span className="text-[9px] text-neutral-500 shrink-0">{n.time}</span>
                      </div>
                      <p className="text-[10px] text-neutral-500 mt-0.5 leading-snug">{n.detail}</p>
                    </div>
                  ))}
                </div>
                <div className="pt-2 border-t border-neutral-200 dark:border-[#1f1f23] text-center">
                  <Link
                    href="/history"
                    onClick={() => setShowNotifications(false)}
                    className="text-[10px] text-neutral-700 dark:text-neutral-300 hover:underline inline-flex items-center gap-1"
                  >
                    View All Audit Logs <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            )}
          </div>

          {/* User Sign In / Sign Up Gate Buttons or User Profile */}
          {isAuthenticated ? (
            <div className="flex items-center gap-2">
              <Link
                href="/dashboard"
                className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-full border border-neutral-200 dark:border-[#27272a] bg-neutral-100 dark:bg-[#121214] text-xs font-mono text-black dark:text-white"
              >
                <User className="w-3.5 h-3.5 text-cyan-400" />
                <span className="max-w-[100px] truncate">{user?.name || user?.email?.split('@')[0]}</span>
              </Link>
              <button
                type="button"
                onClick={logout}
                title="Sign Out"
                className="p-2 rounded-full border border-neutral-200 dark:border-[#27272a] bg-neutral-100 dark:bg-[#121214] text-neutral-600 dark:text-neutral-300 hover:text-red-500 hover:border-red-500/40 transition-colors cursor-pointer"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => openAuthModal('login')}
                className="px-3 py-1.5 rounded-full text-xs font-mono font-medium text-neutral-700 dark:text-neutral-300 hover:text-black dark:hover:text-white transition-colors cursor-pointer"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => openAuthModal('register')}
                className="px-3.5 py-1.5 rounded-full bg-black dark:bg-white text-white dark:text-black text-xs font-mono font-bold hover:bg-neutral-800 dark:hover:bg-neutral-200 transition-colors cursor-pointer shadow-xs"
              >
                Sign Up
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
