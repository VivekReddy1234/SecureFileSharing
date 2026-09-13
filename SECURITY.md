# CipherVault Security Architecture & Cryptographic Specification

**Document Version:** 1.0.0  
**Classification:** Public Security Specification  
**Architecture Paradigm:** Zero-Knowledge End-to-End Encryption (E2EE)  
**Target Platform:** Web Client (Web Cryptography API) & Distributed Cloud Backend  

---

## Executive Summary

CipherVault is an enterprise-grade, end-to-end encrypted (E2EE) file storage and sharing platform designed under a strict **Zero-Knowledge Architecture**. The foundational invariant of CipherVault is that the cloud infrastructure (servers, databases, object stores, and administrators) acts purely as an untrusted blind storage and routing bus.

At no point in transit, at rest, or during key exchange does the server possess the mathematical ability to decrypt user files, view filenames, inspect MIME types, or recover user passwords and private keys. All cryptographic operations—including key derivation, payload encryption/decryption, and asymmetric key wrapping—execute exclusively inside the client's execution environment using standard, non-extractable Web Cryptography primitives.

---

## 1. Threat Model

The CipherVault threat model formalizes our security posture against adversaries across different attack surfaces, trust boundaries, and operational layers. We assume the server infrastructure may be observed, intercepted, or compromised by hostile actors.

### Threat Matrix

| Adversary Profile | Attacker Capabilities | Cryptographic Mitigations & System Controls | Residual Risk & Blast Radius |
| :--- | :--- | :--- | :--- |
| **Unauthenticated Network Attacker** | • Passive eavesdropping on transit traffic<br>• Active Man-in-the-Middle (MITM) on transport layer<br>• BGP hijacking, rogue DNS, public Wi-Fi interception | • Mandatory TLS 1.3 with strict cipher suites<br>• HTTP Strict Transport Security (HSTS) with `includeSubDomains` and `preload`<br>• All payload data is ciphertext before entering transport<br>• Auth tokens are high-entropy bearer secrets | • Network metadata leakage (timing, IP endpoints, total byte volume)<br>• Traffic analysis of upload/download intervals |
| **Authenticated Malicious User** | • Valid registered account<br>• Ability to craft arbitrary API requests<br>• Attempts horizontal/vertical privilege escalation<br>• Attempts IDOR against files, chunks, and key grants | • Cryptographic access control: having ciphertext confers zero access without the wrapping key<br>• Strict relational authorization in API (PostgreSQL row-level checks)<br>• Unique per-file DEKs (compromise of one file key does not affect any other file)<br>• Rate limiting on API endpoints | • Storage quota consumption (mitigated by enforced account limits)<br>• DoS via rapid generation of orphaned records (mitigated by transactional quotas) |
| **Compromised User Account** | • Adversary possesses user's authentication credentials or session token<br>• Access to user's web session<br>• Ability to query all accessible files and metadata | • If session token alone is stolen, adversary cannot derive Master Key without the user's password (authKey is a one-way HKDF subkey)<br>• If password is stolen, adversary can derive Master Key and access all user data<br>• Account recovery key allows legitimate user to reset credentials | • Full compromise of all files and shares owned by or granted to that specific user<br>• Zero blast radius to unrelated platform users |
| **Malicious / Compromised Share Recipient** | • Legitimate recipient of a direct share or public share link<br>• Holds valid unwrapped DEK for authorized files<br>• May attempt to access unauthorized files or redistribute data | • Recipients receive *only* the specific DEK for the files shared with them<br>• Revocation removes access to future downloads and rotations<br>• DEK grants are bound to specific `fileId` and recipient identity | • Exfiltration of plaintext once decrypted on recipient's local machine (inherent to any computer system: once read, data can be copied)<br>• Secondary leakage of shared plaintext outside platform |
| **Database Compromise** | • Full read/write access to PostgreSQL database (via SQLi, leaked DB credentials, or compromised DB replica) | • File contents are never stored in DB (stored as chunk ciphertexts in S3)<br>• User passwords are unknown; server only stores Argon2id hashes of `authKey`<br>• Private keys in DB are encrypted under Master Key wrapper<br>• DEKs in `file_key_grants` are RSA-OAEP encrypted<br>• File manifests contain only encrypted metadata | • Exposure of relational graph (who shares with whom)<br>• Exposure of user emails, creation timestamps, and account activity logs<br>• Zero plaintext file or key exposure |
| **S3 Bucket Compromise** | • Full read/write/delete access to AWS S3 / MinIO object storage<br>• Ability to download raw chunk objects or tamper with stored blobs | • All chunk blobs are AES-256-GCM ciphertexts<br>• Fresh 96-bit IV per chunk; 128-bit authentication tag verified before decryption<br>• AAD (`fileId \|\| chunkIndex`) binds chunks cryptographically to manifest<br>• Tampered chunks fail GCM tag verification and are rejected | • Deletion or ransomware destruction of chunk blobs (mitigated by S3 Object Lock / Versioning and offline backups)<br>• Zero plaintext data exposure |
| **Compromised / Malicious Server** | • Remote Code Execution (RCE) on backend API nodes<br>• Rogue backend engineer or host compromise<br>• Full control over API responses and database state | • Server never receives user passwords, Master Keys, unwrapped RSA private keys, or plaintext DEKs<br>• Backend cannot decrypt any stored chunk or manifest<br>• Cannot forge valid RSA signatures or decrypt RSA-OAEP payloads | • Server can serve malicious JavaScript to client (see Residual Risk: Web-Delivered Client Risk)<br>• Denial of Service by dropping or corrupting files<br>• Access to transport-layer metadata and IP addresses |
| **XSS on Frontend** | • Cross-Site Scripting vulnerability in client web application<br>• Execution of arbitrary JavaScript in the user's browser context | • Strict Content Security Policy (CSP) blocking inline scripts and untrusted domains<br>• Contextual escaping and sanitization of UI elements<br>• Web Crypto keys marked `extractable: false` where supported to impede raw key extraction | • **Highest severity residual risk in web cryptography**<br>• Adversary can invoke Web Crypto APIs to decrypt files or exfiltrate session data during active user session |
| **Malicious Administrator** | • Cloud infrastructure provider root access (AWS/GCP/Azure admins, hypervisor root, DBA) | • Zero-knowledge boundary ensures admins have no access to encryption keys<br>• Infrastructure access yields only Argon2id auth hashes, RSA public keys, and AES-GCM ciphertexts | • Destruction of infrastructure (mitigated by multi-cloud disaster recovery)<br>• Metadata surveillance (traffic volume, sharing topology) |

---

## 2. Key Hierarchy & Derivation Architecture

CipherVault implements a multi-tier cryptographic key hierarchy. Keys are separated strictly by operational domain using deterministic derivation with cryptographically distinct domain strings.

```
                         +-----------------------------------+
                         |           User Password           |
                         +-----------------------------------+
                                           |
                                           |  PBKDF2-HMAC-SHA256
                                           |  (salt = userSalt, min 600k rounds)
                                           v
                         +-----------------------------------+
                         |            Master Key             |
                         |        (256-bit, Memory Only)     |
                         +-----------------------------------+
                                           |
                   +-----------------------+-----------------------+
                   | HKDF-SHA256                                   | HKDF-SHA256
                   | info: "ciphervault-auth-v1"                   | info: "ciphervault-privkey-wrap-v1"
                   v                                               v
+------------------------------------+           +------------------------------------+
|         Authentication Key         |           |       Private Key Wrap Key         |
|             (256-bit)              |           |             (256-bit)              |
+------------------------------------+           +------------------------------------+
                   |                                               |
                   | Sent over TLS at Login                        | AES-256-GCM Encrypt
                   v                                               v
+------------------------------------+           +------------------------------------+
|    Server-Side Storage Only:       |           |     Encrypted User Private Key     |
|   Argon2id(authKey, serverSalt)    |           |       (Stored in PostgreSQL)       |
+------------------------------------+           +------------------------------------+

                                                 +------------------------------------+
                                                 |        User Asymmetric Pair        |
                                                 |        RSA-OAEP 3072-bit           |
                                                 +------------------------------------+
                                                        /                      \
                                                       /                        \
                       +----------------------------------+   +----------------------------------+
                       |          RSA Public Key          |   |         RSA Private Key          |
                       |       (Cleartext in DB)          |   |  (Wrapped in DB, Decrypted in Mem|
                       +----------------------------------+   +----------------------------------+
                                        ^                                      |
                                        | RSA-OAEP Wrap                        | RSA-OAEP Unwrap
                                        |                                      v
+------------------------------------------------------------------------------------------------+
|                                    File Data Encryption Key (DEK)                              |
|                                    (Fresh AES-256 per File)                                    |
+------------------------------------------------------------------------------------------------+
                                        |
                 +----------------------+----------------------+
                 | AES-256-GCM                                 | AES-256-GCM
                 | AAD: fileId || chunkIndex                   | AAD: fileId || chunkIndex
                 v                                             v
+------------------------------------+        +------------------------------------+
|       Chunk 0 Ciphertext           |        |       Chunk N Ciphertext           |
|     (8 MiB + IV + GCM Tag)         |        |     (8 MiB + IV + GCM Tag)         |
+------------------------------------+        +------------------------------------+
```

### Detailed Component Specifications

#### 1. Master Key (MK)
- **Source:** User password input.
- **Salt:** 16-byte (128-bit) cryptographically secure random salt (`userSalt`), generated on registration via `crypto.getRandomValues()` and stored in cleartext on the server.
- **Derivation Function:** PBKDF2-HMAC-SHA256.
- **Iterations:** $\ge 600,000$ iterations (in compliance with OWASP recommendations).
- **Output:** 256 bits (32 bytes).
- **Lifecycle & Storage:** Calculated dynamically in client memory upon authentication. **Never transmitted over the network; never written to `localStorage`, `sessionStorage`, `IndexedDB`, or cookies.** Purged from memory on logout or tab closure.

#### 2. Authentication Key (`authKey`)
- **Source:** Derived from Master Key.
- **Derivation Function:** HKDF-SHA256 (RFC 5869).
  $$\text{authKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{userSalt}, \text{MK}), \text{"ciphervault-auth-v1"}, 32)$$
- **Role:** Transmitted over TLS to the backend API during authentication. It authenticates the client without ever exposing the Master Key or the user's password.

#### 3. Server-Side Authentication Key Storage
- **Algorithm:** Argon2id (RFC 9106).
- **Server Action:** The server never stores `authKey` directly. Upon receipt, the server computes:
  $$\text{StoredHash} = \text{Argon2id}(\text{authKey}, \text{salt}=\text{authSalt}, m=65536, t=3, p=4, \text{len}=32)$$
- **Verification:** Constant-time verification using `crypto.timingSafeEqual` prevents timing side-channel attacks during authentication.

#### 4. User Asymmetric Keypair
- **Algorithm:** RSA-OAEP 3072-bit with SHA-256 digest and MGF1-SHA256 mask generation function.
- **Public Key:** Exported as SPKI SubjectPublicKeyInfo, stored in cleartext in PostgreSQL, and made publicly queryable to authenticated users to facilitate peer-to-peer file sharing.
- **Private Key:** Exported as PKCS#8 DER, then encrypted client-side using AES-256-GCM.
  - **Wrapping Key:** $\text{KeyWrapKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{userSalt}, \text{MK}), \text{"ciphervault-privkey-wrap-v1"}, 32)$.
  - **IV:** Fresh 96-bit CSPRNG IV per encryption.
  - **Storage:** Stored in PostgreSQL as `encrypted_private_key` alongside its 12-byte IV and 16-byte GCM authentication tag.

#### 5. Account Recovery Key (RK)
- **Generation:** 256 bits of cryptographically secure random entropy (`crypto.getRandomValues(32)`), displayed to the user once during registration as a 64-character hexadecimal string or formatted 24-word phrase.
- **Recovery Wrapping Key:**
  $$\text{RecoveryWrapKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{userSalt}, \text{RK}), \text{"ciphervault-recovery-wrap-v1"}, 32)$$
- **Storage:** The user's RSA-OAEP private key is encrypted a second time under `RecoveryWrapKey` using AES-256-GCM and stored in PostgreSQL as `recovery_encrypted_private_key`.
- **Zero-Knowledge Property:** The server never receives `RK`. If the user forgets their password, providing `RK` allows client-side recovery of the RSA private key, enabling password resets without losing access to historical files.

#### 6. File Data Encryption Key (DEK)
- **Algorithm:** AES-256 (symmetric).
- **Generation:** Generated freshly on the client for each file upload using `crypto.getRandomValues(32)`.
- **Purpose:** Encrypts file chunks and the file's metadata manifest. A DEK is never reused across different files.

#### 7. Per-Grantee Key Wrapping (`FileKeyGrant`)
- **Mechanism:** For every user authorized to access a file (including the owner), the file's DEK is encrypted using that specific user's RSA-OAEP 3072-bit public key.
- **Storage:** Stored in the `file_key_grants` table:
  $$\text{wrappedDEK} = \text{RSA-OAEP-Encrypt}(\text{RecipientPublicKey}, \text{DEK})$$
- The server stores only the wrapped blob. Only the recipient holding the corresponding private key can unwrap the DEK in browser memory.

---

## 3. Cryptographic Primitives and Parameter Specifications

CipherVault adheres exclusively to standardized, high-assurance cryptographic primitives recommended by NIST, OWASP, and the cryptographic research community.

```
+-----------------------------------+---------------------------------------------------------+
| Cryptographic Primitive           | Parameter Specification                                 |
+-----------------------------------+---------------------------------------------------------+
| Symmetric Payload Cipher          | AES-256-GCM (NIST SP 800-38D)                           |
|   - Key Length                    | 256 bits (32 bytes)                                     |
|   - Nonce / IV                    | 96 bits (12 bytes), fresh CSPRNG per chunk              |
|   - Authentication Tag            | 128 bits (16 bytes), verified prior to plaintext emit   |
+-----------------------------------+---------------------------------------------------------+
| Asymmetric Key Wrapping           | RSA-OAEP (RFC 8017 / PKCS #1 v2.2)                      |
|   - Modulus Length                | 3072 bits (e = 65537 / 0x10001)                         |
|   - Hash Function                 | SHA-256                                                 |
|   - Mask Generation Function      | MGF1 with SHA-256                                       |
+-----------------------------------+---------------------------------------------------------+
| Client-Side KDF (Master Key)      | PBKDF2-HMAC-SHA256 (RFC 8018)                           |
|   - Minimum Iterations            | 600,000 iterations                                      |
|   - Salt Length                   | 128 bits (16 bytes) CSPRNG per user                     |
|   - Derived Key Length            | 256 bits (32 bytes)                                     |
+-----------------------------------+---------------------------------------------------------+
| Subkey Derivation                 | HKDF-SHA256 (RFC 5869)                                  |
|   - Extract Step                  | HMAC-SHA256 with userSalt                               |
|   - Expand Step                   | Domain-separated info tags                              |
+-----------------------------------+---------------------------------------------------------+
| Server-Side Password Hashing      | Argon2id (RFC 9106)                                     |
|   - Memory Cost (m)               | 65,536 KiB (64 MiB)                                     |
|   - Time Cost (t)                 | 3 iterations                                            |
|   - Parallelism (p)               | 4 threads                                               |
|   - Salt Length                   | 128 bits (16 bytes) CSPRNG per hash                     |
|   - Hash Output Length            | 256 bits (32 bytes)                                     |
+-----------------------------------+---------------------------------------------------------+
| Digest & Integrity Checking       | SHA-256 (FIPS 180-4)                                    |
+-----------------------------------+---------------------------------------------------------+
| String / Token Comparison         | Constant-time comparison (crypto.timingSafeEqual)       |
+-----------------------------------+---------------------------------------------------------+
```

---

## 4. File Encryption Format & Storage Architecture

Files are not encrypted as single monolithic blobs. To support streaming uploads, high throughput, and bounded client-side memory utilization, CipherVault employs an **authenticated chunking format**.

```
+------------------------------------------------------------------------------------+
|                                 Logical File Stream                                |
+------------------------------------------------------------------------------------+
        |                                   |                                   |
        v                                   v                                   v
+------------------+                +------------------+                +------------------+
| Chunk 0 (8 MiB)  |                | Chunk 1 (8 MiB)  |                | Chunk N (<=8MiB) |
+------------------+                +------------------+                +------------------+
        |                                   |                                   |
        | AES-256-GCM                       | AES-256-GCM                       | AES-256-GCM
        | IV_0 (12 bytes)                   | IV_1 (12 bytes)                   | IV_N (12 bytes)
        | AAD = fileId || 0                 | AAD = fileId || 1                 | AAD = fileId || N
        v                                   v                                   v
+------------------------------------------------------------------------------------+
| Physical Chunk Blob Structure (Stored in S3 / MinIO):                              |
| [ 12-byte IV ] [ Ciphertext Payload (up to 8 MiB) ] [ 16-byte GCM Tag ]            |
+------------------------------------------------------------------------------------+
```

### 1. Chunk Specifications
- **Chunk Size:** Fixed at 8 MiB (8,388,608 bytes) for chunks $0$ to $N-1$. The final chunk $N$ contains remaining bytes ($1 \le \text{size} \le 8\text{ MiB}$).
- **Per-Chunk IV:** Each chunk uses an independently generated 96-bit (12-byte) IV from `crypto.getRandomValues(12)`.
- **Authenticated Additional Data (AAD):**
  To defeat chunk-reordering, chunk-deletion, and chunk-transplant attacks (moving a valid encrypted chunk from File A into File B), each chunk's GCM encryption binds the file identifier and sequence index via AAD:
  $$\text{AAD} = \text{fileId (UUIDv4 16-byte binary or ASCII string)} \mathbin{\Vert} \text{chunkIndex (64-bit big-endian integer)}$$
  If an adversary reorders chunks or substitutes a chunk from another file, GCM authentication tag verification will immediately fail on the client.

### 2. Encrypted File Manifest
File metadata (original filename, MIME type, file size, creation timestamp, and total chunk count) is never stored in cleartext.
- The client packages file metadata into a canonical JSON object.
- The manifest is encrypted using the file's DEK with AES-256-GCM (fresh 96-bit IV, AAD = `"ciphervault-file-manifest-v1"`).
- The resulting ciphertext is stored in PostgreSQL in the `files` table under `encrypted_metadata`.

### 3. Database Schema Overview
```sql
-- User credentials and cryptographic keys
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    user_salt BYTEA NOT NULL,                 -- Cleartext PBKDF2/HKDF salt (16 bytes)
    auth_key_hash VARCHAR(255) NOT NULL,      -- Argon2id hash of authKey
    public_key_spki TEXT NOT NULL,            -- Cleartext RSA-OAEP 3072 public key (SPKI PEM/B64)
    encrypted_private_key BYTEA NOT NULL,     -- AES-256-GCM wrapped RSA private key
    private_key_iv BYTEA NOT NULL,            -- IV for wrapped private key (12 bytes)
    recovery_encrypted_privkey BYTEA NOT NULL,-- Recovery-wrapped RSA private key
    recovery_privkey_iv BYTEA NOT NULL,       -- IV for recovery wrapped key (12 bytes)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Encrypted files catalog
CREATE TABLE files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_metadata BYTEA NOT NULL,        -- AES-256-GCM encrypted filename, mime, size
    metadata_iv BYTEA NOT NULL,               -- IV for metadata (12 bytes)
    chunk_size INTEGER NOT NULL DEFAULT 8388608,
    total_chunks INTEGER NOT NULL,
    total_size_bytes BIGINT NOT NULL,         -- Ciphertext size for storage quota accounting
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- File key grants (asymmetric DEK distribution)
CREATE TABLE file_key_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_dek BYTEA NOT NULL,               -- RSA-OAEP 3072 encrypted DEK
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(file_id, recipient_id)
);

-- Chunk storage references
CREATE TABLE file_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    iv BYTEA NOT NULL,                        -- 12-byte IV used for this chunk
    ciphertext_hash BYTEA NOT NULL,           -- SHA-256 of the stored chunk ciphertext
    s3_storage_key TEXT NOT NULL,             -- S3 object path: files/{fileId}/chunks/{chunkIndex}
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(file_id, chunk_index)
);
```

---

## 5. Zero-Knowledge Trust Boundary

The CipherVault architecture defines an absolute boundary between cleartext accessible strictly to the client and ciphertext/metadata processed by the server.

```
+---------------------------------------------------------------------------------------+
|                                 CLIENT TRUST DOMAIN                                   |
|  Plaintext Files | File Names | MIME Types | User Passwords | Master Key | Unwrapped DEKs |
+---------------------------------------------------------------------------------------+
                                           |
                                   Web Crypto Boundary
                                 (Encryption / Wrapping)
                                           |
                                           v
+---------------------------------------------------------------------------------------+
|                                 SERVER / CLOUD DOMAIN                                 |
|                               (Untrusted Infrastructure)                              |
+---------------------------------------------------------------------------------------+
```

### Knowledge Matrix

| System Entity / Attribute | Server CAN See | Server CANNOT See | Cryptographic Guarantee |
| :--- | :---: | :---: | :--- |
| **Plaintext File Contents** | ❌ | ✅ | Only exists in client memory during encryption/decryption. |
| **Original Filename & Extension** | ❌ | ✅ | Encrypted inside manifest with AES-256-GCM under DEK. |
| **MIME / Content Type** | ❌ | ✅ | Encrypted inside manifest with AES-256-GCM under DEK. |
| **User Password** | ❌ | ✅ | Never sent over network. Client derives `authKey` via PBKDF2 + HKDF. |
| **Master Key (MK)** | ❌ | ✅ | Kept in ephemeral client memory; never sent to server. |
| **Unwrapped RSA Private Key** | ❌ | ✅ | Stored only as AES-256-GCM ciphertext in PostgreSQL. |
| **Unwrapped File DEK** | ❌ | ✅ | Wrapped via RSA-OAEP or link wrapping key before transmission. |
| **Share Link Decryption Secret** | ❌ | ✅ | Transferred exclusively in URL hash fragment (`#...`); browser never transmits fragments to server. |
| **User Email Address** | ✅ | ❌ | Required for identity, authentication routing, and sharing lookups. |
| **Argon2id Hash of authKey** | ✅ | ❌ | One-way cryptographic digest used to verify login. |
| **RSA Public Keys (SPKI)** | ✅ | ❌ | Stored in PostgreSQL to allow other users to encrypt DEKs. |
| **Ciphertext Payload Sizes** | ✅ | ❌ | Server observes total byte counts to enforce storage quotas. |
| **Number of File Chunks** | ✅ | ❌ | Required to coordinate chunk assembly and upload completion. |
| **File Sharing Graph** | ✅ | ❌ | Server tracks grants (`fileId`, `recipientId`) to enforce download authorization. |
| **IP Addresses & Access Timestamps** | ✅ | ❌ | Recorded in network logs for DDoS mitigation and audit logging. |
| **Share Link Expiration & Access Limits**| ✅ | ❌ | Enforced by server-side rate limiters and expiration timers. |

---

## 6. Residual Risks & Attack Surfaces

While CipherVault provides rigorous end-to-end cryptographic protection, certain residual risks are inherent to the web platform and distributed cloud architectures.

### 1. Web-Delivered Client Risk (Malicious Server Payload)
- **The Threat:** In a web application, the client code (HTML/JavaScript) is fetched from the server on every session. If the server or CDN infrastructure is compromised, an attacker can modify the served JavaScript bundle to inject code that intercepts the user's password, Master Key, or unwrapped DEKs as they are computed in memory.
- **Severity:** Critical (Fundamental to all web-based E2EE applications).
- **Mitigations:**
  - Strict Content Security Policy (CSP) headers disallowing inline scripts (`script-src 'self'`, `object-src 'none'`).
  - Subresource Integrity (SRI) for all external dependencies.
  - HTTP Strict Transport Security (HSTS) with preloading.
  - Code signing and reproducible builds with verifiable hashes.
  - Long-term roadmap: Standalone desktop clients (Tauri/Electron with signed binaries) and WebExtensions that execute audited, immutable client code.

### 2. Cross-Site Scripting (XSS)
- **The Threat:** XSS represents the single most dangerous vulnerability in client-side cryptography. If an attacker injects and executes arbitrary JavaScript in the application's origin, the browser's memory isolation is broken. The malicious script can hook Web Crypto APIs, extract unencrypted data from memory, or wrap keys for the attacker.
- **Severity:** Critical.
- **Mitigations:**
  - Automated HTML escaping and reliance on modern UI frameworks (React) that prevent raw HTML injection.
  - Content Security Policy disabling `unsafe-eval` and `unsafe-inline`.
  - DOMPurify sanitization applied to any user-rendered strings.
  - Cryptographic keys held in non-extractable CryptoKey handles where the platform allows.

### 3. Metadata Leakage & Traffic Analysis
- **The Threat:** Even when payloads and filenames are fully encrypted, an observer or compromised server can observe:
  - Exact file ciphertext sizes.
  - Upload and download frequency and timestamps.
  - Access patterns (which users access which files and when).
  - Network endpoints and IP addresses.
  An adversary possessing external intelligence could perform traffic fingerprinting to correlate file sizes with known documents.
- **Severity:** Low to Moderate.
- **Mitigations:**
  - Fixed 8 MiB chunking partially masks fine-grained file size variances for multi-chunk files.
  - Future support for optional random-padding blocks on the final chunk.
  - Audit logs subjected to strict time-to-live (TTL) retention policies.

---

## 7. Sharing Key Exchange Protocols

CipherVault supports two secure sharing mechanisms: **Direct User-to-User Sharing** and **Public Share Links**. Both operate under zero-knowledge guarantees.

### 1. Direct Share Protocol

When User Alice wishes to share File $F$ with User Bob:

```
Alice (Owner)                            Server                              Bob (Recipient)
     |                                      |                                       |
     | 1. GET /users/pubkey?email=bob       |                                       |
     |------------------------------------->|                                       |
     |    Return Bob's RSA Public Key       |                                       |
     |<-------------------------------------|                                       |
     |                                      |                                       |
     | 2. Unwrap DEK using Alice PrivateKey |                                       |
     | 3. Wrap DEK with Bob PublicKey       |                                       |
     |    wrappedDEK = RSA-OAEP(Bob_Pub,DEK)|                                       |
     |                                      |                                       |
     | 4. POST /files/{id}/grants           |                                       |
     |    { recipientId: Bob, wrappedDEK }  |                                       |
     |------------------------------------->|                                       |
     |                                      | 5. Notification / Grant Stored        |
     |                                      |-------------------------------------->|
     |                                      |                                       |
     |                                      | 6. GET /files/{id}/chunks + wrappedDEK|
     |                                      |<--------------------------------------|
     |                                      |    Send Chunks + wrappedDEK           |
     |                                      |-------------------------------------->|
     |                                      |                                       |
     |                                      | 7. Unwrap DEK using Bob PrivateKey    |
     |                                      | 8. Verify GCM Tags & Decrypt Chunks   |
```

1. **Public Key Retrieval:** Alice queries the backend API for Bob's public key (`SPKI`).
2. **Local DEK Decryption:** Alice retrieves her own `wrappedDEK` from memory or server, and unwraps it using her RSA-OAEP private key in client memory.
3. **Re-Wrapping:** Alice encrypts the raw DEK using Bob's RSA-OAEP 3072-bit public key.
4. **Grant Creation:** Alice transmits `{ fileId, recipientId: Bob, wrappedDEK }` to the server. The server stores this in `file_key_grants`.
5. **Decryption by Bob:** When Bob accesses the file, he downloads `wrappedDEK`, unwraps it using his RSA private key, downloads the encrypted chunks, and decrypts them.

### 2. Public Share Link Protocol (URL Fragment Zero-Knowledge)

CipherVault allows generating public share links accessible to users who do not have a CipherVault account. This protocol relies on **RFC 3986 URL Hash Fragments**.

```
Standard Share URL Structure:
https://ciphervault.io/share/550e8400-e29b-41d4-a716-446655440000#k8Z2P-9xM...32bytes
\_______________________________________________________________/ \________________/
                               |                                          |
                Path & Query: Sent to Server                   URL Fragment: Never Sent to Server
                 Contains: shareLinkId                          Contains: linkSecret
```

#### Protocol Flow:
1. **Secret Generation:** The client generates 256 bits of CSPRNG entropy: `linkSecret = crypto.getRandomValues(32)`.
2. **Link Key Derivation:**
   $$\text{LinkWrappingKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{shareLinkId}, \text{linkSecret}), \text{"ciphervault-sharelink-wrap-v1"}, 32)$$
3. **DEK Wrapping:** The client encrypts the file's DEK using `LinkWrappingKey` with AES-256-GCM (fresh 96-bit IV).
4. **Server Storage:** The client sends `{ shareLinkId, wrappedDEK, iv, authTag, expiration, maxDownloads }` to the server. **The server never receives `linkSecret`.**
5. **URL Composition:** The client displays the full link containing `#linkSecret` to the owner.
6. **Recipient Retrieval:**
   - The recipient's browser navigates to the URL.
   - The browser sends *only* `/share/{shareLinkId}` to the server (HTTP specifications dictate browsers never send the fragment `#` to the server).
   - The server returns `wrappedDEK`, `iv`, and encrypted chunks.
   - The client-side JavaScript extracts `window.location.hash`, parses `linkSecret`, derives `LinkWrappingKey`, unwraps the DEK, and decrypts the file.

#### Optional Password-Protected Share Links:
If the owner configures a password for the share link:
- Client derives: $\text{PasswordKey} = \text{PBKDF2-HMAC-SHA256}(\text{password}, \text{salt}=\text{shareLinkId}, \text{rounds}=600000, \text{len}=32)$.
- Combined derivation:
  $$\text{ProtectedWrapKey} = \text{HKDF-Expand}(\text{HKDF-Extract}(\text{shareLinkId}, \text{linkSecret} \mathbin{\Vert} \text{PasswordKey}), \text{"ciphervault-pwd-sharelink-wrap-v1"}, 32)$$
- The DEK is wrapped under `ProtectedWrapKey`. Both the URL fragment secret AND the password are cryptographically required to decrypt the DEK.

### 3. Known Man-in-the-Middle (MITM) Limitation (Trust-On-First-Use)
In the Direct Share flow, Alice fetches Bob's public key from the server over TLS.
- **The Limitation:** If the server is malicious or compromised, it could return an attacker's public key instead of Bob's. Alice would unknowingly wrap the DEK for the attacker.
- **Current Mitigation:** Trust-On-First-Use (TOFU) model with public key pinning after first interaction.
- **Future Enhancement:** Out-of-band public key fingerprint verification (Safety Numbers / QR code scanning) and an append-only Key Transparency log (RFC 9162).

---

## 8. Revocation Limitations & Hard Revocation Options

Understanding the boundaries of cryptographic revocation is essential for accurate risk modeling.

### 1. Soft Revocation (Access List Truncation)
- **Mechanism:** The file owner calls `DELETE /files/{id}/grants/{recipientId}` or deletes a share link.
- **Effect:** The server deletes the corresponding `file_key_grants` record or share link. The revoked user or link holder is immediately blocked from making further API requests for chunk downloads.
- **Limitation:** **Cryptography cannot reach out and erase plaintext that the recipient has already downloaded and saved to their local disk or memory.**

### 2. Hard Revocation (Key Rotation & Re-Encryption Protocol)
If a collaborator's access is revoked, but remaining authorized users continue to update or access new versions of the file, the file owner's client can execute **Hard Revocation**:

```
Owner Client                                Server / S3
    |                                            |
    | 1. Download existing chunks & decrypt      |
    |------------------------------------------->|
    |                                            |
    | 2. Generate brand new DEK_v2 (AES-256)     |
    | 3. Re-encrypt chunks under DEK_v2          |
    | 4. Wrap DEK_v2 ONLY for remaining users    |
    |                                            |
    | 5. Upload re-encrypted chunks              |
    |------------------------------------------->|
    | 6. Replace file_key_grants & delete old    |
    |------------------------------------------->|
    |    Old chunks and old grants destroyed     |
```

1. The owner downloads the latest file version and decrypts it.
2. The owner generates a **fresh, independent DEK (`DEK_v2`)**.
3. All chunks are re-encrypted under `DEK_v2` with fresh IVs.
4. The owner fetches public keys *only* for the remaining legitimate collaborators, wraps `DEK_v2` for them, and uploads the new grants.
5. The server purges the old chunk ciphertexts and old grants from S3 and PostgreSQL.
6. **Result:** Even if the revoked user retained the old `DEK_v1`, it is mathematically useless against the new chunks stored in the system.

---

## 9. Security Trade-offs Log

Building a production-grade system requires conscious, documented trade-offs between theoretical cryptography, performance, and user experience.

| Architectural Decision | Trade-Off Description | Security Rationale & Risk Acceptance |
| :--- | :--- | :--- |
| **No Server-Side Malware Scanning** | Server-side antivirus / scanning engines cannot inspect file payloads. | **Incompatible with Zero-Knowledge E2EE.** We accept that the server cannot scan for malware because doing so would require decrypting files on the server, completely breaking our zero-knowledge invariant. Malware defense is delegated to client-side endpoint protection and browser sandboxing. |
| **Account Recovery Key** | Offering an emergency recovery key introduces a secondary key wrapping slot. | In a pure zero-knowledge system, losing a password results in permanent data loss. To prevent user data loss while preserving zero-knowledge, we provide a 256-bit Recovery Key. This introduces a risk: if an attacker steals the printed/stored Recovery Key, they can compromise the account. We mitigate this by generating 256 bits of high entropy and displaying it only once. |
| **Share Link Password Verification** | Server verifies an Argon2id hash of the share link password in addition to client decryption. | The server-side password check is a **UX and rate-limiting gate**, not the cryptographic boundary. Verifying the password hash on the server allows the API to enforce exponential backoff and rate limits against online brute-force attacks before transmitting ciphertexts. Even if the server were compromised and bypassed this check, the attacker still cannot decrypt the payload without knowing the password to unwrap the DEK. |
| **Trust-On-First-Use (TOFU) for Public Keys** | Fetching peer public keys from PostgreSQL without a distributed PKI or Key Transparency log. | Implementing a decentralized transparency ledger (e.g., Certificate Transparency style) adds substantial architectural complexity. For V1, we rely on TLS-secured retrieval of public keys from the database, accompanied by client-side public key caching. Out-of-band verification and Key Transparency are scheduled for V2. |
| **Fixed 8 MiB Chunk Size** | Chunks are fixed at 8 MiB rather than dynamic or padded variable lengths. | 8 MiB provides an optimal balance between browser memory usage (preventing DOM/V8 heap crashes on multi-gigabyte files) and HTTP network overhead. However, it leaks total file size to within 8 MiB precision. This trade-off is accepted as standard for high-performance cloud storage. |

---

## 10. Cryptographic Invariants & Non-Negotiables

All engineers, contributors, and automated pipelines contributing to CipherVault must strictly enforce the following non-negotiable security invariants. **Any pull request violating these rules will be rejected.**

### Rule 1: Never Transmit Secrets to the Server
- Plaintext passwords, the Master Key, unwrapped RSA private keys, and unwrapped Data Encryption Keys (DEKs) must **never, under any circumstance, be transmitted over the network**.
- Secrets must never appear in HTTP request URLs, query parameters, headers, or request bodies.
- Secrets must never be logged to the browser console, remote observability tools (Datadog, Sentry), or persistent storage.

### Rule 2: Never Reuse an IV / Nonce with the Same Key
- In AES-256-GCM, reusing an IV with the same key destroys authenticity guarantees and allows an attacker to recover the authentication key (the classic GCM nonce-reuse catastrophe).
- Every single chunk and key wrap operation must generate a fresh 96-bit IV via `crypto.getRandomValues(12)`.
- Incremental counters or deterministic sequences must **never** be used for IV generation.

### Rule 3: Never Implement Custom Cryptography
- No custom ciphers, hashing algorithms, or mathematical primitives may be implemented.
- All client-side cryptographic operations must execute exclusively through the standardized **W3C Web Cryptography API** (`window.crypto.subtle`).
- All server-side cryptographic checks must rely on audited platform libraries (e.g., Node.js `crypto` with OpenSSL bindings).

### Rule 4: Never Persist Unwrapped Keys in Browser Storage
- The Master Key, unwrapped RSA private key, and file DEKs must exist solely in ephemeral JavaScript memory.
- **Never write sensitive keys or plaintext data to `window.localStorage`, `window.sessionStorage`, `window.indexedDB`, or browser cookies.**

### Rule 5: Never Bypass Authenticated Additional Data (AAD)
- Chunk encryption and decryption must always supply the canonical `AAD = fileId || chunkIndex`.
- Decryption routines must fail closed: if the Web Crypto `decrypt()` operation rejects the tag or AAD, the entire file download must abort immediately without rendering partial plaintext.

### Rule 6: Never Weaken Key Derivation Parameters
- PBKDF2 iterations must never be configured below 600,000 rounds.
- Argon2id parameters on the server must never be configured below $m=64\text{ MiB}, t=3, p=4$.
- RSA key sizes must never be configured below 3072 bits.

### Rule 7: Enforce Timing-Safe Comparisons
- All token, signature, and cryptographic hash verifications executed on the server or client must utilize constant-time comparison functions (e.g., `crypto.timingSafeEqual`) to prevent timing side-channel attacks.

---

## 11. Security Audit & Incident Reporting

If you discover a security vulnerability or architectural flaw within CipherVault, please notify the security team responsibly:

- **Security Contact:** `security@ciphervault.io`
- **PGP Key Fingerprint:** `4D6B 8A2F 9E1C 7B5A 3F0D 6E8C 1A2B 3C4D 5E6F 7A8B`
- **Policy:** We support coordinated vulnerability disclosure and will acknowledge receipt of reports within 24 hours. Do not open public GitHub issues for potential security vulnerabilities.
