/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    './src/contexts/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        theme: {
          bg: 'var(--bg-main)',
          sidebar: 'var(--bg-sidebar)',
          card: 'var(--bg-card)',
          elevated: 'var(--bg-elevated)',
          border: 'var(--border-color)',
          borderSubtle: 'var(--border-subtle)',
          text: 'var(--text-primary)',
          muted: 'var(--text-secondary)',
          subtleText: 'var(--text-muted)',
          accent: 'var(--accent-primary)',
          accentSec: 'var(--accent-secondary)',
          accentPurple: 'var(--accent-purple)',
          success: 'var(--status-success)',
          warning: 'var(--status-warning)',
          danger: 'var(--status-danger)',
          info: 'var(--status-info)',
        },
        // Semantic aliases
        background: 'var(--bg-main)',
        foreground: 'var(--text-primary)',
        card: {
          DEFAULT: 'var(--bg-card)',
          foreground: 'var(--text-primary)',
          elevated: 'var(--bg-elevated)',
        },
        border: 'var(--border-color)',
        // Retain brand colors for gradient accents
        sentrix: {
          blue: '#5278E8',
          purple: '#7457D5',
          cyan: '#16B8B0',
          darkBg: '#090B0E',
          darkCard: '#11161C',
          darkBorder: '#252D35',
          lime: '#B6F36B',
        },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
      borderRadius: {
        sm: '6px',
        DEFAULT: '8px',
        md: '10px',
        lg: '12px',
        xl: '14px',
        '2xl': '16px',
      },
      boxShadow: {
        subtle: '0 1px 3px 0 rgba(0, 0, 0, 0.05), 0 1px 2px -1px rgba(0, 0, 0, 0.05)',
        card: '0 2px 6px -1px rgba(0, 0, 0, 0.06), 0 1px 4px -2px rgba(0, 0, 0, 0.04)',
        elevated: '0 10px 15px -3px rgba(0, 0, 0, 0.08), 0 4px 6px -4px rgba(0, 0, 0, 0.04)',
      },
    },
  },
  plugins: [],
};
