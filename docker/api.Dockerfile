# Stage 1: Base image
FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat python3 make g++

# Stage 2: Dependencies & Builder
FROM base AS builder
WORKDIR /app

# Copy monorepo configuration
COPY package.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/crypto/package.json ./packages/crypto/
COPY apps/api/package.json ./apps/api/

# Install dependencies across workspaces
RUN npm install

# Copy source code
COPY packages/shared ./packages/shared
COPY packages/crypto ./packages/crypto
COPY apps/api ./apps/api

# Build shared packages and API
RUN npm run build -w packages/shared
RUN npm run build -w packages/crypto
RUN npm run build -w apps/api

# Stage 3: Runner
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV API_PORT=4000

# Install runtime dependencies for native bindings if required
RUN apk add --no-cache libc6-compat

# Create non-root user
USER node

# Copy built distribution files and required runtime packages
COPY --chown=node:node --from=builder /app/node_modules ./node_modules
COPY --chown=node:node --from=builder /app/package.json ./package.json
COPY --chown=node:node --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --chown=node:node --from=builder /app/packages/shared/package.json ./packages/shared/package.json
COPY --chown=node:node --from=builder /app/packages/crypto/dist ./packages/crypto/dist
COPY --chown=node:node --from=builder /app/packages/crypto/package.json ./packages/crypto/package.json
COPY --chown=node:node --from=builder /app/apps/api/dist ./apps/api/dist
COPY --chown=node:node --from=builder /app/apps/api/package.json ./apps/api/package.json

EXPOSE 4000

CMD ["node", "apps/api/dist/index.js"]
