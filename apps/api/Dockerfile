FROM node:22-alpine

WORKDIR /app

# Enable pnpm
RUN corepack enable && corepack prepare pnpm@11.21.0 --activate

# Copy root workspace configurations
COPY package.json pnpm-workspace.yaml ./
COPY packages/shared ./packages/shared
COPY apps/api ./apps/api

# Install dependencies and build shared and api
RUN pnpm install --frozen-lockfile=false
RUN pnpm --filter @sentrix/shared build
RUN pnpm --filter @sentrix/api build

WORKDIR /app/apps/api

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/server.js"]
