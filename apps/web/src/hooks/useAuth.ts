'use client';

import { useState, useEffect, useCallback } from 'react';

const AUTH_STORAGE_KEY = 'sentrix_auth_token';

/**
 * Client authentication state hook managing persistent session tokens.
 */
export function useAuth() {
  const [token, setTokenState] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(AUTH_STORAGE_KEY);
      setTokenState(stored);
    } catch {
      // Graceful fallback for SSR or storage restrictions
    }
    setMounted(true);
  }, []);

  const login = useCallback((newToken: string) => {
    try {
      localStorage.setItem(AUTH_STORAGE_KEY, newToken);
    } catch (e) {
      console.warn('Failed to persist auth token', e);
    }
    setTokenState(newToken);
  }, []);

  const logout = useCallback(() => {
    try {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    } catch (e) {
      console.warn('Failed to remove auth token', e);
    }
    setTokenState(null);
  }, []);

  return {
    token,
    isAuthenticated: !!token,
    mounted,
    login,
    logout,
  };
}
