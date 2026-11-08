/**
 * Frontend Type Definitions & Shared Contract Re-Exports
 */
export * from '@sentrix/shared';

export type Theme = 'light' | 'dark';

export interface NavRoute {
  name: string;
  href: string;
  icon: string;
  badge?: string;
}

export interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  trend?: 'up' | 'down' | 'neutral';
  icon?: React.ReactNode;
}
