FROM node:22-alpine

WORKDIR /app

# Enable pnpm
RUN corepack enable && corepack prepare pnpm@11.21.0 --activate

# Copy workspace configurations
COPY package.json pnpm-workspace.yaml ./
COPY packages/shared ./packages/shared
COPY apps/web ./apps/web

# Install dependencies and build shared and web
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @sentrix/shared build
RUN pnpm --filter @sentrix/web build

WORKDIR /app/apps/web

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node_modules/.bin/next", "start", "-p", "3000"]
