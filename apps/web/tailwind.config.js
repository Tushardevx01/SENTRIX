/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: ['class'],
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        background: '#0B0F19',
        foreground: '#F8FAFC',
        card: {
          DEFAULT: '#111827',
          foreground: '#F8FAFC',
          hover: '#1F2937',
        },
        navy: {
          800: '#131B2E',
          900: '#0F172A',
          950: '#080D1A',
        },
        electric: {
          400: '#38BDF8',
          500: '#00E5FF',
          600: '#0284C7',
        },
        cyber: {
          violet: '#8B5CF6',
          indigo: '#6366F1',
          emerald: '#10B981',
          amber: '#F59E0B',
          rose: '#EF4444',
        },
        border: '#1E293B',
        input: '#1E293B',
        ring: '#00E5FF',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      boxShadow: {
        glow: '0 0 20px -5px rgba(0, 229, 255, 0.3)',
        'glow-red': '0 0 20px -5px rgba(239, 68, 68, 0.3)',
        'glow-violet': '0 0 20px -5px rgba(139, 92, 246, 0.3)',
      },
    },
  },
  plugins: [],
};
