FROM node:22-alpine

WORKDIR /app

# Copy workspace configurations
COPY package.json package-lock.json* ./
COPY packages/shared ./packages/shared
COPY apps/web ./apps/web

# Install dependencies using npm and build shared and web
RUN npm ci || npm install
RUN npm --workspace=@sentrix/shared run build
RUN npm --workspace=@sentrix/web run build

WORKDIR /app/apps/web

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3000').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node_modules/.bin/next", "start", "-p", "3000"]
