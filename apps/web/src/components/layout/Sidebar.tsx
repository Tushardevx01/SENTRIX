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
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Server,
  Zap,
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
    { href: '/dashboard', label: 'Command Center', icon: LayoutDashboard },
    { href: '/scanner', label: 'URL Threat Scanner', icon: ShieldCheck },
  ];

  const intelligenceNavigation = [
    { href: '/intelligence', label: 'Threat Intelligence', icon: Radio },
    { href: '/certificates', label: 'Certificate Intel', icon: Lock },
    { href: '/assessment', label: 'Security Assessment', icon: Activity },
    { href: '/community', label: 'Community Feed', icon: Users },
  ];

  const auditNavigation = [
    { href: '/history', label: 'Scan History', icon: History },
    { href: '/settings', label: 'Settings', icon: Settings },
  ];

  const renderNavGroup = (title: string, items: typeof mainNavigation) => (
    <div className="space-y-1">
      {!collapsed && (
        <span className="block px-3 py-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-theme-muted">
          {title}
        </span>
      )}
      {items.map((item) => {
        const Icon = item.icon;
        const isActive =
          pathname === item.href ||
          (item.href !== '/' && pathname.startsWith(item.href));

        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={onCloseMobile}
            title={collapsed ? item.label : undefined}
            className={cn(
              'group relative flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-mono font-medium transition-all duration-150',
              isActive
                ? 'bg-theme-accent/10 text-theme-accent font-semibold border-l-2 border-theme-accent shadow-xs'
                : 'text-theme-muted hover:text-theme-text hover:bg-theme-elevated/70'
            )}
          >
            <Icon
              className={cn(
                'w-4 h-4 shrink-0 transition-colors',
                isActive ? 'text-theme-accent' : 'text-theme-muted group-hover:text-theme-text'
              )}
            />
            {!collapsed && <span className="truncate">{item.label}</span>}
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
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-xs md:hidden"
        />
      )}

      {/* Sidebar container */}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 md:sticky md:top-16 flex flex-col justify-between border-r border-theme-border bg-theme-sidebar transition-all duration-200 ease-in-out h-screen md:h-[calc(100vh-4rem)]',
          collapsed ? 'w-16' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        )}
      >
        <div className="p-3 space-y-5 overflow-y-auto overflow-x-hidden flex-1">
          {/* Mobile Top Header */}
          <div className="flex md:hidden items-center justify-between pb-3 border-b border-theme-border">
            <span className="text-xs font-mono font-bold text-theme-text">SENTRIX NAV</span>
            <button
              onClick={onCloseMobile}
              className="p-1 rounded text-theme-muted hover:text-theme-text"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
          </div>

          {/* Navigation Groups */}
          {renderNavGroup('Operations', mainNavigation)}
          {renderNavGroup('Intelligence & Audit', intelligenceNavigation)}
          {renderNavGroup('Governance', auditNavigation)}

          {/* Zero-Trust Protocol Info Box (Desktop Only when expanded) */}
          {!collapsed && (
            <div className="p-3 bg-theme-elevated/80 border border-theme-border rounded-xl">
              <div className="flex items-center gap-2 text-xs font-semibold text-theme-text mb-1">
                <ShieldAlert className="w-4 h-4 text-theme-accent shrink-0" />
                <span className="truncate">Zero-Trust Guard</span>
              </div>
              <p className="text-[11px] text-theme-muted font-mono leading-relaxed">
                SSRF-isolated sockets, TLS audit & MITRE ATT&CK heuristics.
              </p>
            </div>
          )}
        </div>

        {/* Footer & Collapse Toggle */}
        <div className="p-3 border-t border-theme-border bg-theme-sidebar flex items-center justify-between text-[11px] font-mono text-theme-muted">
          {!collapsed ? (
            <>
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-theme-success" />
                <span>SENTRIX v1.1</span>
              </div>
              <button
                onClick={() => setCollapsed(true)}
                type="button"
                className="hidden md:inline-flex p-1 rounded-md text-theme-muted hover:text-theme-text hover:bg-theme-elevated transition-colors"
                title="Collapse sidebar"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            </>
          ) : (
            <button
              onClick={() => setCollapsed(false)}
              type="button"
              className="hidden md:flex mx-auto p-1.5 rounded-md text-theme-muted hover:text-theme-text hover:bg-theme-elevated transition-colors"
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
