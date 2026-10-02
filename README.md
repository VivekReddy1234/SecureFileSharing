# CipherVault — End-to-End Encrypted Cloud File Sharing Platform

> **A production-grade, zero-knowledge cloud file storage and sharing platform where the server never possesses plaintext file contents or the keys needed to decrypt them.**

---

## 1. Project Overview

CipherVault is built under a strict zero-knowledge trust boundary:

1. **Client-Side Cryptography**: Files are encrypted in chunks in the browser using AES-256-GCM before any byte leaves the client.
2. **Direct-to-S3 Multipart Streaming**: Encrypted chunks stream directly to private AWS S3 buckets using short-lived presigned URLs. Raw file content never traverses the application backend.
3. **Multi-Recipient Key Encapsulation**: File Data Encryption Keys (DEKs) are wrapped independently for each grantee using 3072-bit RSA-OAEP public keys.
4. **Zero-Knowledge Share Links**: Ephemeral public share links embed high-entropy 256-bit secrets exclusively within the URL fragment (`#linkSecret`), ensuring they are never sent over HTTP to the server.
5. **Comprehensive Audit Logging**: Tamper-evident logging of security events with absolute redaction of cryptographic secrets.
6. **Zero Plaintext Admin Model**: Administrators can manage accounts and view system logs but possess no cryptographic ability to decrypt user data.

---

## 2. Architecture & Data Flow

```mermaid
graph TD
    subgraph Browser Client [Authenticated Browser Client]
        UI[Next.js 14 Web App]
        WebCrypto[W3C Web Crypto API]
        MemoryKeys[In-Memory Key Ring: MasterKey & PrivateKey]
        WebCrypto --> MemoryKeys
    end

    subgraph API Server [Node.js Express API]
        AuthCtrl[Auth Controller & Argon2id]
        FileCtrl[File & Share Controller]
        AuthzLayer[Mandatory assertFileAccess Middleware]
        AuditSvc[Audit Logging Service]
    end

    subgraph Storage & Persistence [Storage Layer]
        PG[(PostgreSQL 16 via Prisma)]
        Redis[(Redis 7 - Token Family & Rate Limits)]
        S3[(AWS S3 Private Bucket)]
    end

    Browser Client -- "1. TLS Auth (HKDF AuthKey)" --> AuthCtrl
    Browser Client -- "2. Presigned URL Request" --> FileCtrl
    FileCtrl --> AuthzLayer
    AuthzLayer --> PG
    FileCtrl -- "3. Presigned PUT/GET URLs" --> Browser Client
    Browser Client -- "4. Direct Encrypted Chunks (AES-256-GCM)" --> S3
    AuthCtrl --> Redis
    FileCtrl --> AuditSvc
    AuditSvc --> PG
```

### Key Workspaces in Monorepo
- `apps/web`: Next.js 14 App Router, React 18, Tailwind CSS frontend with Web Crypto orchestration.
- `apps/api`: Express + TypeScript backend with Prisma ORM, Argon2id hashing, Redis rate-limiting, and AWS SDK S3 presigner.
- `packages/shared`: Shared TypeScript types, Zod schemas, and architectural constants.
- `packages/crypto`: Thin, strictly-tested wrappers around the native Web Crypto API (`crypto.subtle`).
- `docker/`: Multi-stage Dockerfiles and healthcheck-validated Docker Compose orchestration.

---

## 3. Cryptographic Hierarchy & Invariants

```mermaid
flowchart TD
    Passphrase[User Password] -->|PBKDF2-HMAC-SHA256 >= 600,000 rounds| MasterKey[Master Key: 256 bits]
    MasterKey -->|HKDF: ciphervault-auth-v1| AuthKey[Authentication Key]
    AuthKey -->|TLS POST /auth/login| ServerArgon2[Server Argon2id Hash: User.authHash]
    MasterKey -->|HKDF: ciphervault-privkey-wrap-v1| PrivWrapKey[Private Key Wrapping Key: AES-GCM]
    RecoverySecret[256-bit CSPRNG Secret] -->|HKDF: ciphervault-recovery-wrap-v1| RecWrapKey[Recovery Wrapping Key: AES-GCM]

    RSAIdentity[RSA-OAEP 3072-bit Keypair]
    RSAIdentity -->|Public Key| ServerPub[User.publicKey - Plaintext]
    RSAIdentity -->|Private Key + PrivWrapKey| WrappedPriv[User.wrappedPrivateKey - AES-GCM]
    RSAIdentity -->|Private Key + RecWrapKey| RecWrappedPriv[User.recoveryWrappedPrivateKey]

    FileDEK[File Data Encryption Key: Fresh AES-256 per file]
    FileDEK -->|AES-256-GCM + IV per chunk + AAD: fileId||chunkIndex| EncryptedChunks[S3 Multipart Ciphertext]
    FileDEK -->|RSA-OAEP Wrap with Grantee PublicKey| FileKeyGrant[FileKeyGrant.wrappedKey]
    FileDEK -->|AES-GCM Wrap with Fragment Secret| ShareLink[ShareLink.wrappedKey]
```

### Cryptographic Non-Negotiables:
1. **Never Send Plaintext Secrets**: Passwords, raw master keys, unwrapped RSA private keys, and unwrapped file DEKs never leave client memory.
2. **Fresh 96-bit IV per Encryption**: Nonces are generated using `crypto.getRandomValues(12)` on every operation and are never reused.
3. **Chunk AAD Binding**: Additional Authenticated Data $\text{AAD} = \text{uint32}(\text{chunkIndex})$ is bound into every chunk's GCM tag, preventing ciphertext splicing and reordering attacks.
4. **Encrypted Manifest**: Original filenames, MIME types, and file sizes reside inside `encryptedManifest`, encrypted with the file's DEK and stored in Postgres. The server cannot inspect file contents or metadata names.

---

## 4. Database Schema Overview

The database uses PostgreSQL managed through Prisma:

- **`User`**: Credentials and cryptographic identity (`authHash`, `authSalt`, `kdfIterations`, `publicKey`, `wrappedPrivateKey`, `recoveryWrappedPrivateKey`).
- **`RefreshToken`**: Session management with rotation chains (`tokenHash`, `familyId`, `revokedAt`, `replacedByHash`).
- **`File`**: Storage records (`s3Key`, `encryptedManifest`, `manifestIv`, `sizeBytes`, `status`).
- **`FileKeyGrant`**: Cryptographic key encapsulation rows (`fileId`, `userId`, `wrappedKey`). One row per grantee.
- **`FileShare`**: Logical permission rules (`canView`, `canDownload`, `canReshare`, `expiresAt`, `revokedAt`).
- **`ShareLink`**: Ephemeral public links (`wrappedKey`, `passwordHash`, `maxUses`, `useCount`, `expiresAt`, `revokedAt`).
- **`AuditLog`**: Append-only security audit entries (`userId`, `eventType`, `resourceId`, `success`, `ipAddress`, `metadata`).

---

## 5. Documented File Size Limits

- **Chunk Size**: Fixed at **8 MiB** ($8,388,608$ bytes). Matches S3 multipart upload 5 MiB minimum with headroom.
- **Multipart Limit**: S3 supports a maximum of 10,000 parts per multipart upload.
- **Theoretical Maximum**: $10,000 \times 8\text{ MiB} \approx 78.1\text{ GiB}$.
- **Practical Default Ceiling**: Configured via `MAX_FILE_SIZE_BYTES=5368709120` (**5 GiB**).

---

## 6. Security Limitations & Documented Trade-Offs

Per the architecture specification in `SECURITY.md`, the following trade-offs are explicitly documented:

1. **No Server-Side Malware Scanning**: Scanning plaintext for viruses or executing heuristics is cryptographically impossible without sending plaintext to the server, which breaks the zero-knowledge model.
2. **Metadata Leakage**: The server observes communication graphs (who shares with whom), object sizes rounded to chunk boundaries, IP addresses, and upload/download frequencies.
3. **Web-Delivered Client Vulnerability**: Delivering client cryptographic JS via the web carries the inherent risk that a compromised server could serve malicious code. This is mitigated through strict Content Security Policy (`script-src 'self'`), HTTP Strict Transport Security (HSTS), and subresource integrity.
4. **Revocation Boundaries**: Revoking a share or link deletes cryptographic key grants from the server, preventing future downloads. However, revocation cannot cryptographically erase plaintext data already downloaded and decrypted by a recipient prior to revocation.
5. **Share Link Password Gate**: The server checks passwords against `ShareLink.passwordHash` purely as a rate-limiting convenience to reject invalid attempts early. The true cryptographic gate is client-side key derivation from `#linkSecret` and the passphrase.

---

## 7. Environment Setup & Configuration

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

| Variable | Description | Example |
| :--- | :--- | :--- |
| `DATABASE_URL` | PostgreSQL connection URI | `postgresql://ciphervault:ciphervault@localhost:5432/ciphervault?schema=public` |
| `REDIS_URL` | Redis instance connection URI | `redis://localhost:6379` |
| `JWT_SECRET` | Secret for access tokens (min 32 chars) | `your-secure-access-token-secret-32-chars-min` |
| `JWT_REFRESH_SECRET` | Secret for refresh tokens (different from JWT_SECRET) | `your-secure-refresh-token-secret-32-chars-min` |
| `AWS_REGION` | AWS Region for S3 bucket | `us-east-1` |
| `AWS_ACCESS_KEY_ID` | AWS IAM Access Key ID | `AKIAIOSFODNN7EXAMPLE` |
| `AWS_SECRET_ACCESS_KEY` | AWS IAM Secret Access Key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| `AWS_S3_BUCKET` | Dedicated private S3 bucket name | `ciphervault-secure-vault` |
| `CORS_ORIGIN` | Allowed client origin | `http://localhost:3000` |
| `NEXT_PUBLIC_API_URL` | Frontend API base URL | `http://localhost:4000` |
| `MAX_FILE_SIZE_BYTES` | Maximum upload ceiling in bytes | `5368709120` (5 GiB) |
| `ACCESS_TOKEN_TTL_MINUTES` | Access token lifetime | `15` |
| `REFRESH_TOKEN_TTL_DAYS` | Refresh token lifetime | `30` |

### S3 Bucket CORS Configuration
Configure the bucket CORS policy in the AWS Management Console to allow direct browser multipart uploads:

```json
[
  {
    "AllowedHeaders": ["*"],
    "AllowedMethods": ["GET", "PUT", "POST", "HEAD"],
    "AllowedOrigins": [
      "http://localhost:3000",
      "https://YOUR-CIPHERVAULT-FRONTEND.vercel.app"
    ],
    "ExposeHeaders": ["ETag", "x-amz-server-side-encryption"]
  }
]
```

### Production Deployment Variables

#### Frontend — Vercel

```env
NEXT_PUBLIC_API_URL=https://YOUR-CIPHERVAULT-BACKEND.onrender.com
```

#### Backend — Render

```env
DATABASE_URL=postgresql://<neon-user>:<neon-password>@<neon-host>/<database>?sslmode=require
REDIS_URL=redis://<upstash-username>:<upstash-password>@<upstash-host>:<upstash-port>
JWT_SECRET=<generate-a-random-secret-at-least-32-characters>
JWT_REFRESH_SECRET=<generate-a-different-random-secret-at-least-32-characters>
AWS_REGION=<your-aws-region>
AWS_ACCESS_KEY_ID=<your-aws-access-key-id>
AWS_SECRET_ACCESS_KEY=<your-aws-secret-access-key>
AWS_S3_BUCKET=<your-private-s3-bucket-name>
CORS_ORIGIN=https://YOUR-CIPHERVAULT-FRONTEND.vercel.app
MAX_FILE_SIZE_BYTES=5368709120
ACCESS_TOKEN_TTL_MINUTES=15
REFRESH_TOKEN_TTL_DAYS=30
NODE_ENV=production
API_PORT=4000
```

---

## 8. Development & Docker Orchestration

### Prerequisites
- Node.js >= 20.0.0
- Docker & Docker Compose
- npm >= 10.0.0

### Local Development Setup

1. **Install All Monorepo Dependencies**:
   ```bash
   npm install
   ```

2. **Generate Database Client**:
   ```bash
   npx prisma generate --schema=apps/api/prisma/schema.prisma
   ```

3. **Start Postgres & Redis via Docker**:
   ```bash
   docker compose -f docker/docker-compose.yml up -d postgres redis
   ```

4. **Apply Database Migrations**:
   ```bash
   npm run db:push -w apps/api
   ```

5. **Run in Development Mode**:
   ```bash
   # Terminal 1: Backend API (port 4000)
   npm run dev -w apps/api

   # Terminal 2: Web Frontend (port 3000)
   npm run dev -w apps/web
   ```

### Full Stack Docker Deployment
Run the complete stack (Postgres, Redis, API, and Next.js Web) in isolated containers with healthcheck coordination:

```bash
docker compose -f docker/docker-compose.yml up --build -d
```

Verify service health:
```bash
curl http://localhost:4000/health
curl http://localhost:4000/ready
```

---

## 9. Running Verification & Test Suites

The platform includes comprehensive test suites across unit, cryptographic, and security layers:

```bash
# 1. Typecheck the entire monorepo
npm run typecheck

# 2. Run all cryptographic tests (AES-GCM, RSA-OAEP, PBKDF2, HKDF, AAD, nonces)
npm run test -w packages/crypto

# 3. Run shared schema validation tests
npm run test -w packages/shared

# 4. Run API security & unit tests (IDOR, role escalation, JWT tampering, Argon2id)
npm run test -w apps/api

# 5. Build all packages and applications for production
npm run build
```

---

## 10. License

Apache-2.0. See `LICENSE` for details.
