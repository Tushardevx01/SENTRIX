'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import {
  LayoutDashboard,
  ShieldCheck,
  Radio,
  Lock,
  Activity,
  Users,
  History,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  MessageSquareWarning,
  Network,
  Blocks,
  Terminal,
  LogIn,
  Layers,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface SidebarProps {
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen = false, onCloseMobile }) => {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  const mainNavigation = [
    { href: '/dashboard', label: 'Command Center', icon: LayoutDashboard, code: '01' },
    { href: '/scanner', label: 'URL Threat Scanner', icon: ShieldCheck, code: '02' },
    { href: '/messages', label: 'Scam Message Analyzer', icon: MessageSquareWarning, code: '03' },
  ];

  const intelligenceNavigation = [
    { href: '/intelligence', label: 'Threat Intelligence', icon: Radio, code: '04' },
    { href: '/correlations', label: 'Campaign Correlation', icon: Network, code: '05' },
    { href: '/blockchain', label: 'Web3 Threat Registry', icon: Blocks, code: '06' },
    { href: '/certificates', label: 'Certificate Intel', icon: Lock, code: '07' },
    { href: '/assessment', label: 'Security Assessment', icon: Activity, code: '08' },
    { href: '/community', label: 'Community Feed', icon: Users, code: '09' },
  ];

  const auditNavigation = [
    { href: '/history', label: 'Scan History', icon: History, code: '10' },
    { href: '/settings', label: 'Settings', icon: Settings, code: '11' },
    { href: '/login', label: 'Operator Login', icon: LogIn, code: '12' },
  ];

  const renderNavGroup = (title: string, items: typeof mainNavigation) => (
    <div className="space-y-1">
      {!collapsed && (
        <div className="flex items-center justify-between px-3 py-1.5 text-[10px] font-mono font-semibold uppercase tracking-wider text-neutral-400">
          <span>// {title}</span>
          <span className="text-[9px] text-neutral-500 font-pixel">ASCII</span>
        </div>
      )}
      {items.map((item) => {
        const Icon = item.icon;
        const isActive =
          pathname === item.href ||
          (item.href !== '/' && item.href !== '/login' && pathname.startsWith(item.href));

        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onCloseMobile}
            title={collapsed ? `${item.code} ${item.label}` : undefined}
            className={cn(
              'group relative flex items-center gap-3 px-3 py-2 rounded-md text-xs font-mono transition-all duration-150',
              isActive
                ? 'bg-[#18181b] text-white font-semibold border border-[#27272a] shadow-xs'
                : 'text-neutral-300 hover:text-white hover:bg-[#121214] border border-transparent'
            )}
          >
            <Icon
              className={cn(
                'w-4 h-4 shrink-0 transition-colors',
                isActive ? 'text-white' : 'text-neutral-400 group-hover:text-white'
              )}
            />
            {!collapsed && (
              <div className="flex items-center justify-between flex-1 truncate">
                <span className="truncate">{item.label}</span>
                <span className="text-[10px] text-neutral-500 font-mono opacity-0 group-hover:opacity-100 transition-opacity">
                  [{item.code}]
                </span>
              </div>
            )}
            {isActive && (
              <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-4 bg-white rounded-r" />
            )}
          </Link>
        );
      })}
    </div>
  );

  return (
    <>
      {/* Mobile Backdrop overlay */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs md:hidden"
        />
      )}

      {/* Sidebar container - PURE BLACK WITH CRISP WHITE TEXT */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 md:sticky md:top-16 flex flex-col justify-between border-r border-[#1f1f23] bg-[#000000] text-white transition-all duration-200 ease-in-out h-screen md:h-[calc(100vh-4rem)]',
          collapsed ? 'w-16' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        )}
      >
        <div className="p-3 space-y-5 overflow-y-auto overflow-x-hidden flex-1">
          {/* Mobile Top Header */}
          <div className="flex md:hidden items-center justify-between pb-3 border-b border-[#1f1f23]">
            <span className="text-xs font-mono font-bold tracking-wider text-white">
              [ SENTRIX // NAV ]
            </span>
            <button
              onClick={onCloseMobile}
              className="p-1 rounded text-neutral-400 hover:text-white"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Groups */}
          {renderNavGroup('OPERATIONS', mainNavigation)}
          {renderNavGroup('INTELLIGENCE & WEB3', intelligenceNavigation)}
          {renderNavGroup('SYSTEM & ACCESS', auditNavigation)}

          {/* ASCII Industrial Protocol Box */}
          {!collapsed && (
            <div className="p-3 bg-[#0a0a0c] border border-[#1f1f23] rounded-md font-mono text-[11px] space-y-1">
              <div className="flex items-center justify-between text-neutral-300">
                <span className="flex items-center gap-1.5 font-semibold text-white">
                  <Terminal className="w-3.5 h-3.5 text-neutral-400" />
                  CORE ENGINE
                </span>
                <span className="text-[9px] px-1 py-0.2 bg-[#18181b] text-neutral-300 border border-[#27272a] rounded">
                  ONLINE
                </span>
              </div>
              <p className="text-[10px] text-neutral-400 leading-relaxed pt-1">
                Zero-trust heuristics, socket IP pinning & EVM hash anchoring active.
              </p>
              <div className="text-[9px] text-neutral-500 pt-1 font-pixel">
                [+]: SHA256 // SC-081v3
              </div>
            </div>
          )}
        </div>

        {/* Footer & Collapse Toggle */}
        <div className="p-3 border-t border-[#1f1f23] bg-[#000000] flex items-center justify-between text-[11px] font-mono text-neutral-400">
          {!collapsed ? (
            <>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse" />
                <span className="text-neutral-300 text-[10px] tracking-wide font-pixel">
                  SENTRIX v1.0
                </span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                type="button"
                className="hidden md:inline-flex p-1 rounded text-neutral-400 hover:text-white hover:bg-[#18181b] transition-colors"
                title="Collapse sidebar"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              type="button"
              className="hidden md:flex mx-auto p-1.5 rounded text-neutral-400 hover:text-white hover:bg-[#18181b] transition-colors"
              title="Expand sidebar"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          )}
        </div>
      </aside>
    </>
  );
};
