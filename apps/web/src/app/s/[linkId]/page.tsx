'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import {
  unwrapShareLinkDek,
  decryptManifest,
  decryptFile,
} from '@/lib/crypto-operations';
import { fromBase64, type FileManifest } from '@ciphervault/crypto';

export default function ShareLinkPage({ params }: { params: { linkId: string } }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [manifest, setManifest] = useState<FileManifest | null>(null);
  const [dek, setDek] = useState<CryptoKey | null>(null);
  const [downloadProgress, setDownloadProgress] = useState<number | null>(null);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);

  const loadLink = async (pwd?: string) => {
    try {
      setLoading(true);
      setError('');

      const secret = window.location.hash ? window.location.hash.substring(1) : '';
      if (!secret) {
        throw new Error('Invalid share link: Encryption secret missing from URL fragment.');
      }

      const res = await api.accessShareLink(params.linkId, pwd);

      if (res.requiresPassword && !pwd) {
        setNeedsPassword(true);
        setLoading(false);
        return;
      }

      const unwrappedDek = await unwrapShareLinkDek(res.wrappedKeyBase64, secret, pwd);
      setDek(unwrappedDek);

      const decryptedManifest = await decryptManifest(
        fromBase64(res.encryptedManifestBase64),
        fromBase64(res.manifestIvBase64),
        unwrappedDek
      );

      setManifest(decryptedManifest);
      setNeedsPassword(false);

      setDownloadUrl(res.downloadUrl);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to access share link';
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLink();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.linkId]);

  const handleDownload = async () => {
    if (!manifest || !dek) return;

    try {
      setDownloadProgress(10);

      // Download ciphertext
      let ciphertextBuffer: ArrayBuffer;
      if (downloadUrl) {
        const res = await fetch(downloadUrl);
        if (!res.ok) throw new Error('Failed to download ciphertext from storage');
        ciphertextBuffer = await res.arrayBuffer();
      } else {
        throw new Error('No download URL available');
      }

      setDownloadProgress(50);
      const ciphertext = new Uint8Array(ciphertextBuffer);

      // Split into chunks based on manifest
      const chunks: Uint8Array[] = [];
      let offset = 0;
      for (const chunkInfo of manifest.chunks) {
        const chunkBytes = ciphertext.slice(offset, offset + chunkInfo.cipherTextLength);
        chunks.push(chunkBytes);
        offset += chunkInfo.cipherTextLength;
      }

      setDownloadProgress(80);
      const blob = await decryptFile(chunks, manifest, dek, (pct) => {
        setDownloadProgress(80 + Math.round(pct * 0.2));
      });

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = manifest.originalFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setDownloadProgress(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Decryption failed';
      alert(msg);
      setDownloadProgress(null);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
      <div className="sm:mx-auto sm:w-full sm:max-w-md bg-white py-8 px-6 shadow-xl rounded-2xl">
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900">CipherVault</h1>
          <p className="text-xs text-gray-500 mt-1">End-to-End Encrypted Secure Transfer</p>
        </div>

        {loading ? (
          <div className="text-center py-8">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-600 border-t-transparent mb-3" />
            <p className="text-sm text-gray-600">Unwrapping keys and verifying integrity...</p>
          </div>
        ) : error ? (
          <div className="p-4 bg-red-50 text-red-700 text-sm rounded-xl border border-red-200 text-center">
            <p className="font-semibold mb-1">Access Denied</p>
            <p>{error}</p>
          </div>
        ) : needsPassword ? (
          <div className="space-y-4">
            <p className="text-sm text-gray-600 text-center">
              This link is password protected. Enter the password to derive the decryption key.
            </p>
            <div>
              <input
                type="password"
                placeholder="Enter password"
                className="block w-full px-4 py-2.5 border border-gray-300 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <button
              onClick={() => loadLink(password)}
              disabled={!password}
              className="w-full bg-indigo-600 text-white py-2.5 rounded-xl text-sm font-semibold hover:bg-indigo-700 disabled:opacity-50 transition"
            >
              Unlock & Decrypt
            </button>
          </div>
        ) : manifest ? (
          <div className="space-y-6">
            <div className="p-4 bg-indigo-50 rounded-xl border border-indigo-100 space-y-1">
              <p className="text-xs text-indigo-500 font-semibold uppercase tracking-wider">
                Decrypted File
              </p>
              <p className="text-lg font-bold text-gray-900 break-words">
                {manifest.originalFileName}
              </p>
              <p className="text-sm text-gray-600">
                {(manifest.originalSizeBytes / 1024 / 1024).toFixed(2)} MB • {manifest.chunks.length} chunks
              </p>
            </div>

            {downloadProgress !== null && (
              <div className="space-y-1">
                <div className="flex justify-between text-xs text-gray-600">
                  <span>Downloading & Decrypting...</span>
                  <span>{downloadProgress}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-indigo-600 h-2 rounded-full transition-all duration-300"
                    style={{ width: `${downloadProgress}%` }}
                  />
                </div>
              </div>
            )}

            <button
              onClick={handleDownload}
              disabled={downloadProgress !== null}
              className="w-full bg-indigo-600 text-white py-3 rounded-xl text-sm font-semibold hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
            >
              {downloadProgress !== null ? 'Processing...' : 'Download & Decrypt in Browser'}
            </button>

            <p className="text-xs text-gray-400 text-center">
              All decryption happens directly in your browser. The server never saw this file in plaintext.
            </p>
          </div>
        ) : null}
      </div>
    </div>
  );
}
