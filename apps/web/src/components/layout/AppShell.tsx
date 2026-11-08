'use client';

import React, { useState } from 'react';
import { usePathname } from 'next/navigation';
import { Header } from './Header';
import { Sidebar } from './Sidebar';
import { Footer } from './Footer';
import { useAuth } from '@/contexts/AuthContext';
import { AuthRequiredGate } from '../auth/AuthRequiredGate';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const pathname = usePathname();
  const { isAuthenticated, isLoading } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);
  const isLanding = pathname === '/';
  const isAuthPage = pathname === '/login';

  // Publicly accessible for quick scanning and short result inspection
  const isPublicRoute =
    isLanding ||
    isAuthPage ||
    pathname === '/scanner' ||
    Boolean(pathname?.startsWith('/reports'));

  // Any other operational route (like /history, /dashboard, /intelligence) strictly requires authentication
  const isAccessBlocked = !isPublicRoute && !isAuthenticated;

  // If loading session from localStorage, render subtle loading pulse
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-theme-bg text-theme-text font-mono text-xs">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>Verifying security perimeter...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-theme-bg text-theme-text transition-colors">
      <Header
        onToggleMobileSidebar={() => setMobileOpen(!mobileOpen)}
        isLanding={isLanding}
      />
      {isLanding ? (
        <main className="flex-1 w-full">{children}</main>
      ) : (
        <div className="flex flex-1 w-full">
          <Sidebar
            mobileOpen={mobileOpen}
            onCloseMobile={() => setMobileOpen(false)}
          />
          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full overflow-y-auto">
            {isAccessBlocked ? (
              <AuthRequiredGate pageName={pathname || 'Internal Operational Area'} />
            ) : (
              children
            )}
          </main>
        </div>
      )}
      {isLanding && <Footer />}
    </div>
  );
};
