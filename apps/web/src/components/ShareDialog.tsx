'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import {
  createShareLinkKeys,
  wrapDekForUser,
  unwrapDek,
  wrapDekForShareLink,
} from '@/lib/crypto-operations';
import { useAuth } from '@/lib/auth-context';

export default function ShareDialog({
  fileId,
  wrappedDek,
  isOpen,
  onClose,
}: {
  fileId: string;
  wrappedDek: string;
  isOpen: boolean;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<'direct' | 'link'>('direct');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [generatedLink, setGeneratedLink] = useState('');
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const { privateKey } = useAuth();

  if (!isOpen) return null;

  const handleDirectShare = async () => {
    try {
      setMessage(null);
      setLoading(true);
      if (!privateKey) throw new Error('Private key is not loaded in memory. Please re-login.');

      const userRes = await api.lookupUser(email);
      const dek = await unwrapDek(wrappedDek, privateKey);
      const newWrappedDek = await wrapDekForUser(dek, userRes.publicKeyBase64);

      await api.createShare(fileId, {
        recipientEmail: email.toLowerCase().trim(),
        wrappedKeyBase64: newWrappedDek,
        canView: true,
        canDownload: true,
        canReshare: false,
      });

      setMessage({ type: 'success', text: `Successfully shared with ${email}` });
      setEmail('');
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to share file';
      setMessage({ type: 'error', text: msg });
    } finally {
      setLoading(false);
    }
  };

  const handleLinkShare = async () => {
    try {
      setMessage(null);
      setLoading(true);
      if (!privateKey) throw new Error('Private key is not loaded in memory. Please re-login.');

      const { linkSecretBase64Url, wrappingKey } = await createShareLinkKeys(
        password ? password : undefined
      );

      const dek = await unwrapDek(wrappedDek, privateKey);
      const symWrappedDek = await wrapDekForShareLink(dek, wrappingKey);

      const res = await api.createShareLink(fileId, {
        wrappedKeyBase64: symWrappedDek,
        canDownload: true,
      });

      const url = `${window.location.origin}/s/${res.id}#${linkSecretBase64Url}`;
      setGeneratedLink(url);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to create share link';
      setMessage({ type: 'error', text: msg });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-2xl p-6 max-w-md w-full">
        <div className="flex border-b border-gray-200 mb-5">
          <button
            onClick={() => {
              setTab('direct');
              setMessage(null);
            }}
            className={`py-2.5 px-4 text-sm font-semibold transition ${
              tab === 'direct'
                ? 'border-b-2 border-indigo-600 text-indigo-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Direct Share
          </button>
          <button
            onClick={() => {
              setTab('link');
              setMessage(null);
            }}
            className={`py-2.5 px-4 text-sm font-semibold transition ${
              tab === 'link'
                ? 'border-b-2 border-indigo-600 text-indigo-600'
                : 'text-gray-500 hover:text-gray-700'
            }`}
          >
            Public Share Link
          </button>
        </div>

        {message && (
          <div
            className={`mb-4 p-3 rounded-lg text-sm ${
              message.type === 'success'
                ? 'bg-green-50 text-green-700 border border-green-200'
                : 'bg-red-50 text-red-700 border border-red-200'
            }`}
          >
            {message.text}
          </div>
        )}

        {tab === 'direct' ? (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Recipient Email
              </label>
              <input
                type="email"
                placeholder="user@example.com"
                className="block w-full px-3.5 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <button
              onClick={handleDirectShare}
              disabled={!email || loading}
              className="w-full bg-indigo-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
            >
              {loading ? 'Encrypting & Sharing...' : 'Share File'}
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Optional Password Protection
              </label>
              <input
                type="password"
                placeholder="Leave blank for no password"
                className="block w-full px-3.5 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            {!generatedLink ? (
              <button
                onClick={handleLinkShare}
                disabled={loading}
                className="w-full bg-indigo-600 text-white py-2.5 rounded-lg text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
              >
                {loading ? 'Generating Encrypted Link...' : 'Generate Share Link'}
              </button>
            ) : (
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-700">
                  Share Link (secret key is in URL hash fragment)
                </label>
                <div className="flex gap-2">
                  <input
                    readOnly
                    type="text"
                    className="block w-full px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 text-xs text-gray-800 select-all"
                    value={generatedLink}
                  />
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(generatedLink);
                      alert('Link copied to clipboard!');
                    }}
                    className="px-3 py-2 bg-indigo-50 text-indigo-700 font-medium text-xs rounded-lg hover:bg-indigo-100 whitespace-nowrap"
                  >
                    Copy
                  </button>
                </div>
                <p className="text-xs text-gray-500">
                  Note: The server never receives the encryption secret in the link fragment.
                </p>
              </div>
            )}
          </div>
        )}

        <div className="mt-6 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
