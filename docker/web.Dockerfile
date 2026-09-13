# Stage 1: Base image
FROM node:20-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat

# Stage 2: Dependencies & Builder
FROM base AS builder
WORKDIR /app

# Copy monorepo configuration
COPY package.json tsconfig.base.json ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/crypto/package.json ./packages/crypto/
COPY apps/web/package.json ./apps/web/

# Install dependencies across workspaces
RUN npm install

# Copy source code
COPY packages/shared ./packages/shared
COPY packages/crypto ./packages/crypto
COPY apps/web ./apps/web

# Build dependencies and Next.js web application
RUN npm run build -w packages/shared
RUN npm run build -w packages/crypto
RUN npm run build -w apps/web

# Stage 3: Runner
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Configure non-root user for security
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs

# Copy build artifacts and dependencies
COPY --chown=nextjs:nodejs --from=builder /app/node_modules ./node_modules
COPY --chown=nextjs:nodejs --from=builder /app/package.json ./package.json
COPY --chown=nextjs:nodejs --from=builder /app/packages/shared/dist ./packages/shared/dist
COPY --chown=nextjs:nodejs --from=builder /app/packages/shared/package.json ./packages/shared/package.json
COPY --chown=nextjs:nodejs --from=builder /app/packages/crypto/dist ./packages/crypto/dist
COPY --chown=nextjs:nodejs --from=builder /app/packages/crypto/package.json ./packages/crypto/package.json
COPY --chown=nextjs:nodejs --from=builder /app/apps/web ./apps/web

USER nextjs

EXPOSE 3000

CMD ["npm", "run", "start", "-w", "apps/web"]
