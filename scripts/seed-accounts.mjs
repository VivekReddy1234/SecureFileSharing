import argon2 from 'argon2';
import databasePkg from '../apps/api/dist/config/database.js';
import cryptoPkg from '@ciphervault/crypto';

const { prisma } = databasePkg;
const {
  deriveAuthKey,
  generateRsaKeyPair,
  exportPublicKey,
  wrapPrivateKey,
  wrapPrivateKeyWithRecoveryKey,
  generateRecoveryKey,
  generateSalt,
  toBase64,
  MIN_KDF_ITERATIONS,
} = cryptoPkg;

async function seedUser(email, password, role = 'USER') {
  console.log(`Seeding ${role} account: ${email}...`);

  const salt = generateSalt();
  const iterations = MIN_KDF_ITERATIONS || 600000;

  // 1. Derive masterKey and authKey from password + salt
  const { masterKey, authKey } = await deriveAuthKey(password, salt, iterations);

  // 2. Generate RSA-OAEP 3072 identity keypair
  const keyPair = await generateRsaKeyPair();
  const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);

  // 3. Wrap private key with masterKey
  const { wrappedPrivateKeyBase64, wrappedPrivateKeyIvBase64 } = await wrapPrivateKey(
    keyPair.privateKey,
    masterKey
  );

  // 4. Wrap private key with recovery key
  const recoveryKey = generateRecoveryKey();
  const { recoveryWrappedPrivateKeyBase64, recoveryWrappedKeyIvBase64 } =
    await wrapPrivateKeyWithRecoveryKey(keyPair.privateKey, recoveryKey);

  // 5. Server hashes the client-derived authKey with Argon2id
  const authKeyBase64 = toBase64(authKey);
  const authHash = await argon2.hash(authKeyBase64, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });

  // 6. Upsert user in database
  const user = await prisma.user.upsert({
    where: { email: email.toLowerCase().trim() },
    update: {
      authHash,
      authSalt: toBase64(salt),
      kdfIterations: iterations,
      publicKey: publicKeyBase64,
      wrappedPrivateKey: wrappedPrivateKeyBase64,
      wrappedPrivateKeyIv: wrappedPrivateKeyIvBase64,
      recoveryWrappedPrivateKey: recoveryWrappedPrivateKeyBase64,
      recoveryWrappedKeyIv: recoveryWrappedKeyIvBase64,
      role,
      isDisabled: false,
    },
    create: {
      email: email.toLowerCase().trim(),
      role,
      authHash,
      authSalt: toBase64(salt),
      kdfIterations: iterations,
      publicKey: publicKeyBase64,
      wrappedPrivateKey: wrappedPrivateKeyBase64,
      wrappedPrivateKeyIv: wrappedPrivateKeyIvBase64,
      recoveryWrappedPrivateKey: recoveryWrappedPrivateKeyBase64,
      recoveryWrappedKeyIv: recoveryWrappedKeyIvBase64,
    },
  });

  console.log(`✓ Seeded ${user.email} (ID: ${user.id}, Role: ${user.role})`);
  console.log(`  Recovery Key: ${toBase64(recoveryKey)}`);
}

async function main() {
  await seedUser('alice@ciphervault.io', 'Password123!', 'USER');
  await seedUser('admin@ciphervault.io', 'AdminPassword123!', 'ADMIN');
  console.log('\nAll test accounts seeded successfully!');
  await prisma.$disconnect();
}

main().catch((err) => {
  console.error('Failed to seed accounts:', err);
  process.exit(1);
});
