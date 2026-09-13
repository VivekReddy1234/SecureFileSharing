'use client';

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { api, setAccessToken } from './api';
import {
  deriveAuthKey,
  generateRsaKeyPair,
  exportPublicKey,
  wrapPrivateKey,
  unwrapPrivateKey,
  wrapPrivateKeyWithRecoveryKey,
  generateRecoveryKey,
  generateSalt,
  toBase64,
  fromBase64,
  MIN_KDF_ITERATIONS,
} from '@ciphervault/crypto';
import { UserRole } from '@ciphervault/shared';

export interface AuthUser {
  id: string;
  email: string;
  role: UserRole;
  publicKeyBase64?: string;
}

interface AuthContextType {
  user: AuthUser | null;
  privateKey: CryptoKey | null;
  masterKey: CryptoKey | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (credentials: { email: string; password: string }) => Promise<void>;
  register: (credentials: { email: string; password: string }) => Promise<string>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [privateKey, setPrivateKey] = useState<CryptoKey | null>(null);
  const [masterKey, setMasterKey] = useState<CryptoKey | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const refreshRes = await api.refresh();
        setAccessToken(refreshRes.accessToken);
        const meRes = await api.getMe();
        setUser({
          id: meRes.id,
          email: meRes.email,
          role: meRes.role,
        });
        // Note: Keys are held only in memory. After page reload, user will need
        // to re-login to unlock file decryption. This is a deliberate zero-knowledge guarantee.
      } catch {
        setAccessToken(null);
        setUser(null);
      } finally {
        setIsLoading(false);
      }
    };
    checkAuth();
  }, []);

  const login = async ({ email, password }: { email: string; password: string }) => {
    const saltRes = await api.getSalt(email);
    const saltBytes = fromBase64(saltRes.authSaltBase64);
    const iterations = saltRes.kdfIterations || MIN_KDF_ITERATIONS;

    const { masterKey: derivedMasterKey, authKey } = await deriveAuthKey(
      password,
      saltBytes,
      iterations
    );

    const loginRes = await api.login({
      email: email.toLowerCase().trim(),
      authKeyBase64: toBase64(authKey),
    });

    setAccessToken(loginRes.accessToken);
    setUser({
      id: loginRes.user.id,
      email: loginRes.user.email,
      role: loginRes.user.role,
      publicKeyBase64: loginRes.user.publicKeyBase64,
    });
    setMasterKey(derivedMasterKey);

    const unwrappedPrivateKey = await unwrapPrivateKey(
      loginRes.user.wrappedPrivateKeyBase64,
      loginRes.user.wrappedPrivateKeyIvBase64,
      derivedMasterKey
    );
    setPrivateKey(unwrappedPrivateKey);
  };

  const register = async ({ email, password }: { email: string; password: string }): Promise<string> => {
    const salt = generateSalt();
    const iterations = MIN_KDF_ITERATIONS;

    const { masterKey: derivedMasterKey, authKey } = await deriveAuthKey(
      password,
      salt,
      iterations
    );

    const keyPair = await generateRsaKeyPair();
    const publicKeyBase64 = await exportPublicKey(keyPair.publicKey);

    const { wrappedPrivateKeyBase64, wrappedPrivateKeyIvBase64 } = await wrapPrivateKey(
      keyPair.privateKey,
      derivedMasterKey
    );

    const recoveryKey = generateRecoveryKey();
    const { recoveryWrappedPrivateKeyBase64, recoveryWrappedKeyIvBase64 } =
      await wrapPrivateKeyWithRecoveryKey(keyPair.privateKey, recoveryKey);

    await api.register({
      email: email.toLowerCase().trim(),
      authKeyBase64: toBase64(authKey),
      authSaltBase64: toBase64(salt),
      kdfIterations: iterations,
      publicKeyBase64,
      wrappedPrivateKeyBase64,
      wrappedPrivateKeyIvBase64,
      recoveryWrappedPrivateKeyBase64,
      recoveryWrappedKeyIvBase64,
    });

    return toBase64(recoveryKey);
  };

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      // Best-effort
    }
    setAccessToken(null);
    setUser(null);
    setPrivateKey(null);
    setMasterKey(null);
    if (typeof window !== 'undefined') {
      window.location.href = '/login';
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        privateKey,
        masterKey,
        isAuthenticated: !!user,
        isLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
