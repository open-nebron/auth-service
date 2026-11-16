# Stage 1: Build & compile TypeScript
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies required for native modules (e.g. argon2)
RUN apk add --no-cache python3 make g++

# Point node-gyp to official nodejs headers for Alpine builds
ENV npm_config_disturl=https://nodejs.org/dist

# Install dependencies
COPY package.json package-lock.json* ./
RUN npm ci

# Copy sources and configuration
COPY tsconfig.json ./
COPY openapi.yaml ./
COPY src ./src

# Build TypeScript to dist
RUN npm run build

# Remove development dependencies and unused native prebuilds to minimize image size
RUN npm prune --omit=dev && \
    rm -rf node_modules/argon2/prebuilds node_modules/argon2/build/Release/obj.target && \
    find node_modules -type f \( -name "*.md" -o -name "*.d.ts" -o -name "*.map" \) -delete 2>/dev/null || true

# Stage 2: Production runner
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4001

# Create secrets directory and ensure proper permissions for non-root 'node' user
RUN mkdir -p /app/secrets/keys && chown -R node:node /app

# Copy production dependencies and compiled artifacts
COPY --chown=node:node package.json ./
COPY --chown=node:node openapi.yaml ./
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist ./dist

# Run as non-root user
USER node

EXPOSE 4001

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4001/health || exit 1

CMD ["node", "dist/server.js"]
