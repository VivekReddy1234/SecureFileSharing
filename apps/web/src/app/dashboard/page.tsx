'use client';

import AuthGuard from '@/components/AuthGuard';
import UploadDialog from '@/components/UploadDialog';
import ShareDialog from '@/components/ShareDialog';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';
import {
  unwrapDek,
  decryptManifest,
  decryptFile,
} from '@/lib/crypto-operations';
import { fromBase64, type FileManifest } from '@ciphervault/crypto';
import { FileListItem } from '@ciphervault/shared';
import { useEffect, useState, useCallback } from 'react';

interface DecryptedFileItem extends FileListItem {
  manifest?: FileManifest;
  decryptError?: boolean;
}

export default function Dashboard() {
  const { user, privateKey, logout } = useAuth();
  const [files, setFiles] = useState<DecryptedFileItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [shareDialogTarget, setShareDialogTarget] = useState<{
    fileId: string;
    wrappedKey: string;
  } | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  const fetchFiles = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getFiles();
      const rawItems: FileListItem[] = res.items || [];

      // Attempt to decrypt manifests if privateKey is available in memory
      const decryptedItems: DecryptedFileItem[] = await Promise.all(
        rawItems.map(async (f) => {
          if (!privateKey || !f.wrappedKeyBase64 || !f.encryptedManifestBase64) {
            return f;
          }
          try {
            const dek = await unwrapDek(f.wrappedKeyBase64, privateKey);
            const manifest = await decryptManifest(
              fromBase64(f.encryptedManifestBase64),
              fromBase64(f.manifestIvBase64),
              dek
            );
            return { ...f, manifest };
          } catch {
            return { ...f, decryptError: true };
          }
        })
      );

      setFiles(decryptedItems);
    } catch (e) {
      console.error('Failed to fetch files:', e);
    } finally {
      setLoading(false);
    }
  }, [privateKey]);

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  const handleDownload = async (fileItem: DecryptedFileItem) => {
    if (!privateKey || !fileItem.wrappedKeyBase64) {
      alert('Cannot download: Private key missing. Please log in again.');
      return;
    }

    try {
      setDownloadingId(fileItem.id);

      // 1. Get presigned download URL
      const { downloadUrl } = await api.getDownloadUrl(fileItem.id);

      // 2. Fetch ciphertext directly from S3
      const s3Res = await fetch(downloadUrl);
      if (!s3Res.ok) throw new Error('Failed to retrieve file from S3');
      const ciphertextBuffer = await s3Res.arrayBuffer();
      const ciphertext = new Uint8Array(ciphertextBuffer);

      // 3. Unwrap DEK
      const dek = await unwrapDek(fileItem.wrappedKeyBase64, privateKey);

      // 4. Decrypt manifest if not cached
      const manifest =
        fileItem.manifest ??
        (await decryptManifest(
          fromBase64(fileItem.encryptedManifestBase64),
          fromBase64(fileItem.manifestIvBase64),
          dek
        ));

      // 5. Partition chunks based on manifest
      const chunks: Uint8Array[] = [];
      let offset = 0;
      for (const chunkInfo of manifest.chunks) {
        const chunkBytes = ciphertext.slice(offset, offset + chunkInfo.cipherTextLength);
        chunks.push(chunkBytes);
        offset += chunkInfo.cipherTextLength;
      }

      // 6. Decrypt chunk by chunk
      const blob = await decryptFile(chunks, manifest, dek);

      // 7. Trigger browser download
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = manifest.originalFileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Download failed';
      alert(`Error during download: ${msg}`);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this file?')) return;
    try {
      await api.deleteFile(id);
      fetchFiles();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to delete file';
      alert(msg);
    }
  };

  return (
    <AuthGuard>
      <div className="min-h-screen bg-gray-50">
        <nav className="bg-white border-b border-gray-200">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex justify-between h-16">
              <div className="flex items-center space-x-3">
                <span className="text-xl font-bold text-indigo-600">CipherVault</span>
                <span className="text-xs bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded-full font-medium">
                  Zero-Knowledge
                </span>
              </div>
              <div className="flex items-center space-x-6">
                <a href="/audit" className="text-sm font-medium text-gray-600 hover:text-gray-900">
                  Audit Logs
                </a>
                <a href="/settings" className="text-sm font-medium text-gray-600 hover:text-gray-900">
                  Settings
                </a>
                {user?.role === 'ADMIN' && (
                  <a href="/admin" className="text-sm font-medium text-purple-600 hover:text-purple-800">
                    Admin
                  </a>
                )}
                <span className="text-sm text-gray-500">{user?.email}</span>
                <button
                  onClick={logout}
                  className="text-sm font-medium text-red-600 hover:text-red-700"
                >
                  Logout
                </button>
              </div>
            </div>
          </div>
        </nav>

        <main className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center mb-8">
            <div>
              <h2 className="text-2xl font-bold text-gray-900">Your Files</h2>
              <p className="text-sm text-gray-500 mt-1">
                Encrypted with AES-256-GCM in your browser before upload
              </p>
            </div>
            <button
              onClick={() => setIsUploadOpen(true)}
              className="bg-indigo-600 text-white px-5 py-2.5 rounded-xl font-medium hover:bg-indigo-700 transition shadow-sm"
            >
              Upload File
            </button>
          </div>

          {loading ? (
            <div className="text-center py-16 bg-white rounded-2xl shadow-sm border border-gray-100">
              <div className="inline-block animate-spin rounded-full h-8 w-8 border-4 border-indigo-600 border-t-transparent mb-2" />
              <p className="text-sm text-gray-500">Decrypting file headers in memory...</p>
            </div>
          ) : files.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-2xl shadow-sm border border-gray-100">
              <p className="text-gray-500 text-base mb-3">No encrypted files stored yet.</p>
              <button
                onClick={() => setIsUploadOpen(true)}
                className="text-sm font-medium text-indigo-600 hover:text-indigo-500"
              >
                Upload your first file &rarr;
              </button>
            </div>
          ) : (
            <div className="bg-white shadow-sm rounded-2xl border border-gray-200 overflow-hidden">
              <ul className="divide-y divide-gray-100">
                {files.map((file) => (
                  <li key={file.id} className="p-5 flex items-center justify-between hover:bg-gray-50 transition">
                    <div className="flex flex-col space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-gray-900 text-base">
                          {file.manifest?.originalFileName || `Ciphertext Blob (${file.id.slice(0, 8)}...)`}
                        </span>
                        {!file.isOwner && (
                          <span className="text-xs bg-green-50 text-green-700 px-2 py-0.5 rounded-md font-medium">
                            Shared with you
                          </span>
                        )}
                        <span className="text-xs bg-gray-100 text-gray-600 px-2 py-0.5 rounded-md">
                          {file.status}
                        </span>
                      </div>
                      <div className="text-xs text-gray-500 flex items-center space-x-3">
                        <span>
                          {file.manifest
                            ? `${(file.manifest.originalSizeBytes / 1024 / 1024).toFixed(2)} MB`
                            : `${(Number(file.sizeBytes) / 1024 / 1024).toFixed(2)} MB (ciphertext)`}
                        </span>
                        <span>•</span>
                        <span>{new Date(file.createdAt).toLocaleDateString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => handleDownload(file)}
                        disabled={downloadingId === file.id}
                        className="px-3 py-1.5 bg-indigo-50 text-indigo-600 hover:bg-indigo-100 rounded-lg text-sm font-medium transition disabled:opacity-50"
                      >
                        {downloadingId === file.id ? 'Decrypting...' : 'Download'}
                      </button>
                      {file.isOwner && (
                        <>
                          <button
                            onClick={() =>
                              setShareDialogTarget({
                                fileId: file.id,
                                wrappedKey: file.wrappedKeyBase64,
                              })
                            }
                            className="px-3 py-1.5 bg-gray-100 text-gray-700 hover:bg-gray-200 rounded-lg text-sm font-medium transition"
                          >
                            Share
                          </button>
                          <button
                            onClick={() => handleDelete(file.id)}
                            className="px-3 py-1.5 text-red-600 hover:bg-red-50 rounded-lg text-sm font-medium transition"
                          >
                            Delete
                          </button>
                        </>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </main>

        <UploadDialog
          isOpen={isUploadOpen}
          onClose={() => setIsUploadOpen(false)}
          onUploadComplete={fetchFiles}
        />

        {shareDialogTarget && (
          <ShareDialog
            fileId={shareDialogTarget.fileId}
            wrappedDek={shareDialogTarget.wrappedKey}
            isOpen={true}
            onClose={() => setShareDialogTarget(null)}
          />
        )}
      </div>
    </AuthGuard>
  );
}
