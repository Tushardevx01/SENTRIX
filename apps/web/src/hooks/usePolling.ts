'use client';

import { useEffect, useRef } from 'react';

export interface UsePollingOptions {
  immediate?: boolean;
  pauseOnHidden?: boolean;
}

/**
 * Resilient interval polling hook with document visibility awareness.
 */
export function usePolling(
  callback: () => void | Promise<void>,
  intervalMs: number | null,
  options: UsePollingOptions = {}
): void {
  const { immediate = false, pauseOnHidden = true } = options;
  const savedCallback = useRef(callback);
  savedCallback.current = callback;

  useEffect(() => {
    if (intervalMs === null || intervalMs <= 0) return;

    if (immediate) {
      savedCallback.current();
    }

    const tick = () => {
      if (pauseOnHidden && typeof document !== 'undefined' && document.hidden) {
        return;
      }
      savedCallback.current();
    };

    const id = setInterval(tick, intervalMs);
    return () => clearInterval(id);
  }, [intervalMs, immediate, pauseOnHidden]);
}
