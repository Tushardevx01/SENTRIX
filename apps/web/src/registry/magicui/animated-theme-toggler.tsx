'use client';

import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Sun, Moon } from 'lucide-react';
import { useTheme } from '@/contexts/ThemeContext';

interface AnimatedThemeTogglerProps {
  className?: string;
  size?: number;
}

export function AnimatedThemeToggler({ className = '', size = 18 }: AnimatedThemeTogglerProps) {
  const { theme, toggleTheme, mounted } = useTheme();

  // Until mounted, render a placeholder with fixed sizing to avoid SSR hydration mismatch
  if (!mounted) {
    return (
      <div
        className={`w-9 h-9 rounded-full flex items-center justify-center border border-neutral-200 dark:border-[#27272a] bg-neutral-100/50 dark:bg-[#121214]/50 ${className}`}
      />
    );
  }

  const isDark = theme === 'dark';

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label="Toggle theme"
      className={`relative w-9 h-9 rounded-full flex items-center justify-center border border-neutral-200 dark:border-[#27272a] bg-neutral-100 dark:bg-[#121214] hover:bg-neutral-200 dark:hover:bg-[#18181b] text-neutral-800 dark:text-neutral-200 transition-colors cursor-pointer overflow-hidden ${className}`}
    >
      <AnimatePresence mode="wait" initial={false}>
        {isDark ? (
          <motion.div
            key="moon"
            initial={{ y: -20, opacity: 0, rotate: -45, scale: 0.8 }}
            animate={{ y: 0, opacity: 1, rotate: 0, scale: 1 }}
            exit={{ y: 20, opacity: 0, rotate: 45, scale: 0.8 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            className="flex items-center justify-center"
          >
            <Moon style={{ width: size, height: size }} className="text-cyan-400" />
          </motion.div>
        ) : (
          <motion.div
            key="sun"
            initial={{ y: 20, opacity: 0, rotate: 45, scale: 0.8 }}
            animate={{ y: 0, opacity: 1, rotate: 0, scale: 1 }}
            exit={{ y: -20, opacity: 0, rotate: -45, scale: 0.8 }}
            transition={{ type: 'spring', stiffness: 400, damping: 25 }}
            className="flex items-center justify-center"
          >
            <Sun style={{ width: size, height: size }} className="text-amber-500" />
          </motion.div>
        )}
      </AnimatePresence>
    </button>
  );
}

export function AnimatedThemeTogglerDemo() {
  return (
    <div className="flex justify-center p-6">
      <AnimatedThemeToggler />
    </div>
  );
}

export default AnimatedThemeToggler;

