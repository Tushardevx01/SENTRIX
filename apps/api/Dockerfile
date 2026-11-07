FROM node:22-alpine

WORKDIR /app

# Copy workspace configurations
COPY package.json ./
COPY packages/shared ./packages/shared
COPY apps/api ./apps/api

# Install dependencies using npm and build shared and api
RUN npm install
RUN npm --workspace=@sentrix/shared run build
RUN npm --workspace=@sentrix/api run build

WORKDIR /app/apps/api

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:8000/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

CMD ["node", "dist/server.js"]
