'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import {
  Shield,
  Search,
  Bell,
  Menu,
  X,
  ChevronRight,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Radio,
  User,
  Settings,
  LogOut,
  ExternalLink,
} from 'lucide-react';
import { ThemeToggle } from './ThemeToggle';
import { cn } from '@/lib/utils';

interface HeaderProps {
  onToggleMobileSidebar?: () => void;
  isLanding?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onToggleMobileSidebar, isLanding = false }) => {
  const pathname = usePathname();
  const router = useRouter();
  const [showNotifications, setShowNotifications] = useState(false);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  // Generate breadcrumb title
  const getBreadcrumb = () => {
    if (pathname === '/') return 'Product Overview';
    if (pathname === '/dashboard') return 'Command Center';
    if (pathname === '/scanner') return 'URL Threat Scanner';
    if (pathname.startsWith('/reports')) return 'Investigation Report';
    if (pathname === '/intelligence') return 'Threat Intelligence';
    if (pathname === '/certificates') return 'Certificate Intelligence';
    if (pathname === '/assessment') return 'Security Assessment';
    if (pathname === '/community') return 'Community Feed';
    if (pathname === '/history') return 'Audit Scan History';
    if (pathname === '/settings') return 'Platform Settings';
    return 'Security Intelligence';
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
      title: 'High-Risk Domain Flagged',
      detail: 'SSRF and brand impersonation detected on submitted URL.',
      type: 'critical',
      time: '12m ago',
    },
    {
      id: '2',
      title: 'Threat Intelligence Sync',
      detail: 'URLhaus malware signature registry updated (+48 new IOCs).',
      type: 'info',
      time: '1h ago',
    },
    {
      id: '3',
      title: 'Community Consensus Verified',
      detail: 'Report #TR-8921 confirmed malicious by 14 peer analysts.',
      type: 'success',
      time: '3h ago',
    },
  ];

  return (
    <header className="sticky top-0 z-40 w-full border-b border-theme-border bg-theme-sidebar/95 backdrop-blur-md transition-colors">
      <div className="flex h-16 items-center justify-between px-4 sm:px-6">
        {/* Left Section: Brand & Breadcrumbs */}
        <div className="flex items-center gap-4">
          {/* Mobile hamburger */}
          <button
            onClick={onToggleMobileSidebar}
            type="button"
            className="p-2 rounded-lg border border-theme-border text-theme-muted hover:text-theme-text md:hidden"
            aria-label="Toggle navigation menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          {/* SENTRIX Brand Logo */}
          <Link href="/" className="flex items-center gap-2.5 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-[#5278E8] via-[#7457D5] to-[#16B8B0] flex items-center justify-center shadow-sm">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div className="hidden sm:block">
              <span className="text-base font-extrabold tracking-tight text-theme-text font-mono group-hover:text-theme-accent transition-colors">
                SENTRIX
              </span>
              <span className="block text-[10px] text-theme-muted font-mono -mt-1 tracking-tight">
                Trust Intelligence
              </span>
            </div>
          </Link>

          {/* Breadcrumb separator */}
          {!isLanding && (
            <div className="hidden md:flex items-center gap-2 text-xs font-mono pl-4 border-l border-theme-border">
              <span className="text-theme-muted">Console</span>
              <ChevronRight className="w-3.5 h-3.5 text-theme-muted/50" />
              <span className="font-semibold text-theme-text">{getBreadcrumb()}</span>
            </div>
          )}
        </div>

        {/* Center: Quick Search Bar */}
        <div className="hidden lg:flex items-center flex-1 max-w-md mx-6">
          <form onSubmit={handleGlobalSearch} className="w-full relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-theme-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search IOCs, scan URL or domain... (Enter to inspect)"
              className="w-full pl-9 pr-12 py-1.5 text-xs font-mono bg-theme-bg border border-theme-border rounded-lg text-theme-text placeholder:text-theme-muted focus:outline-none focus:border-theme-accent focus:ring-1 focus:ring-theme-accent/20 transition-all"
            />
            <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] font-mono text-theme-muted bg-theme-elevated px-1.5 py-0.5 rounded border border-theme-border">
              ⌘K
            </span>
          </form>
        </div>

        {/* Right Section: Engine Status, Theme Toggle, Notifications & User */}
        <div className="flex items-center gap-2.5">
          {/* Engine Status Indicator */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>Engine Ready</span>
          </div>

          {/* Theme Toggle Button */}
          <ThemeToggle />

          {/* Notifications Dropdown */}
          <div className="relative">
            <button
              onClick={() => {
                setShowNotifications(!showNotifications);
                setShowUserMenu(false);
              }}
              type="button"
              aria-label="Notifications"
              className="relative p-2 rounded-lg border border-theme-border bg-theme-card text-theme-text hover:bg-theme-elevated transition-colors"
            >
              <Bell className="w-4 h-4 text-theme-muted hover:text-theme-text" />
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-[#E34E5B]" />
            </button>

            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 bg-theme-card border border-theme-border rounded-xl shadow-elevated p-3 z-50 text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-theme-border">
                  <span className="font-semibold text-theme-text font-mono">System Alerts</span>
                  <span className="text-[10px] text-theme-muted font-mono">3 unread</span>
                </div>
                <div className="divide-y divide-theme-borderSubtle mt-1">
                  {mockNotifications.map((n) => (
                    <div key={n.id} className="py-2.5 hover:bg-theme-elevated/50 px-1 rounded transition-colors">
                      <div className="flex items-center justify-between font-medium text-theme-text">
                        <span className="truncate pr-2">{n.title}</span>
                        <span className="text-[10px] text-theme-muted font-mono">{n.time}</span>
                      </div>
                      <p className="text-[11px] text-theme-muted mt-0.5 leading-snug">{n.detail}</p>
                    </div>
                  ))}
                </div>
                <div className="pt-2 border-t border-theme-border text-center">
                  <Link
                    href="/history"
                    onClick={() => setShowNotifications(false)}
                    className="text-[11px] font-mono text-theme-accent hover:underline inline-flex items-center gap-1"
                  >
                    View Complete Audit Trail <ExternalLink className="w-3 h-3" />
                  </Link>
                </div>
              </div>
            )}
          </div>

          {/* Quick Scanner Action */}
          <Link
            href="/scanner"
            className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-theme-accent text-white dark:text-slate-950 hover:opacity-90 transition-opacity shadow-sm"
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Scan URL</span>
          </Link>

          {/* User Profile */}
          <div className="relative">
            <button
              onClick={() => {
                setShowUserMenu(!showUserMenu);
                setShowNotifications(false);
              }}
              type="button"
              className="flex items-center gap-2 p-1 pl-1.5 rounded-lg border border-theme-border bg-theme-card hover:bg-theme-elevated transition-colors"
            >
              <div className="w-6 h-6 rounded-md bg-gradient-to-tr from-[#5278E8] to-[#16B8B0] flex items-center justify-center text-white text-[11px] font-bold">
                A
              </div>
              <span className="hidden xl:inline text-xs font-mono font-medium text-theme-text">
                Analyst
              </span>
            </button>

            {showUserMenu && (
              <div className="absolute right-0 mt-2 w-56 bg-theme-card border border-theme-border rounded-xl shadow-elevated p-2 z-50 text-xs">
                <div className="p-2 border-b border-theme-border">
                  <p className="font-semibold text-theme-text">Security Analyst</p>
                  <p className="text-[11px] font-mono text-theme-muted">analyst@sentrix.internal</p>
                </div>
                <div className="py-1">
                  <Link
                    href="/settings"
                    onClick={() => setShowUserMenu(false)}
                    className="flex items-center gap-2 px-2 py-1.5 rounded-md text-theme-text hover:bg-theme-elevated transition-colors"
                  >
                    <Settings className="w-3.5 h-3.5 text-theme-muted" />
                    Platform Settings
                  </Link>
                  <Link
                    href="/dashboard"
                    onClick={() => setShowUserMenu(false)}
                    className="flex items-center gap-2 px-2 py-1.5 rounded-md text-theme-text hover:bg-theme-elevated transition-colors"
                  >
                    <Activity className="w-3.5 h-3.5 text-theme-muted" />
                    Command Center
                  </Link>
                </div>
                <div className="pt-1 border-t border-theme-border">
                  <button
                    onClick={() => setShowUserMenu(false)}
                    className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-rose-500 hover:bg-rose-500/10 transition-colors text-left"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Reset Session
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
