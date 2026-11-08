'use client';

import React, { useState } from 'react';
import { usePathname } from 'next/navigation';
import { Header } from './Header';
import { Sidebar } from './Sidebar';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const pathname = usePathname();
  const [mobileOpen, setMobileOpen] = useState(false);
  const isLanding = pathname === '/';

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
            {children}
          </main>
        </div>
      )}
    </div>
  );
};
