'use client';

import { useState } from 'react';
import { encryptFile, wrapDekForUser } from '@/lib/crypto-operations';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth-context';

export default function UploadDialog({
  isOpen,
  onClose,
  onUploadComplete,
}: {
  isOpen: boolean;
  onClose: () => void;
  onUploadComplete: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<{ stage: string; percent: number } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { user } = useAuth();

  if (!isOpen) return null;

  const handleUpload = async () => {
    if (!file || !user?.publicKeyBase64) {
      setError('Cannot upload: user public key missing or no file selected');
      return;
    }

    try {
      setError(null);
      setProgress({ stage: 'encrypting', percent: 0 });

      const {
        chunks,
        encryptedManifestBase64,
        manifestIvBase64,
        totalCiphertextSize,
        dek,
      } = await encryptFile(file, (stage, percent) => {
        setProgress({ stage, percent });
      });

      const wrappedKeyBase64 = await wrapDekForUser(dek, user.publicKeyBase64);

      setProgress({ stage: 'initiating', percent: 5 });
      const initRes = await api.initUpload({
        totalSizeBytes: totalCiphertextSize,
        chunkCount: chunks.length,
        encryptedManifestBase64,
        manifestIvBase64,
        wrappedKeyBase64,
      });

      const { fileId, uploadId, presignedUrls } = initRes;
      const parts = [];

      for (let i = 0; i < chunks.length; i++) {
        setProgress({
          stage: 'uploading',
          percent: 10 + Math.round((i / chunks.length) * 80),
        });

        const partUrlInfo = presignedUrls[i];
        if (!partUrlInfo) throw new Error(`Missing presigned URL for part ${i + 1}`);

        const chunkData = chunks[i]!;
        const uploadRes = await fetch(partUrlInfo.url, {
          method: 'PUT',
          body: chunkData.ciphertext as unknown as BodyInit,
        });

        if (!uploadRes.ok) {
          throw new Error(`S3 upload failed for part ${i + 1}`);
        }

        const rawEtag = uploadRes.headers.get('ETag') || `part-${i + 1}`;
        parts.push({
          partNumber: i + 1,
          etag: rawEtag.replace(/"/g, ''),
        });
      }

      setProgress({ stage: 'finalizing', percent: 95 });
      await api.completeUpload(fileId, {
        uploadId,
        parts,
      });

      setProgress({ stage: 'done', percent: 100 });
      setTimeout(() => {
        onUploadComplete();
        onClose();
        setFile(null);
        setProgress(null);
      }, 800);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Upload failed';
      setError(msg);
      setProgress(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-black bg-opacity-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-xl shadow-2xl p-6 max-w-md w-full">
        <h3 className="text-xl font-bold text-gray-900 mb-4">Upload Encrypted File</h3>

        <input
          type="file"
          onChange={(e) => {
            setFile(e.target.files?.[0] || null);
            setError(null);
          }}
          disabled={!!progress}
          className="block w-full text-sm text-gray-500 file:mr-4 file:py-2.5 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 file:text-indigo-700 hover:file:bg-indigo-100 cursor-pointer"
        />

        {file && (
          <div className="mt-4 p-3 bg-gray-50 rounded-lg text-sm text-gray-700 space-y-1">
            <p className="font-medium truncate">{file.name}</p>
            <p className="text-gray-500">{(file.size / 1024 / 1024).toFixed(2)} MB</p>
          </div>
        )}

        {error && (
          <div className="mt-4 p-3 bg-red-50 text-red-700 text-sm rounded-lg border border-red-200">
            {error}
          </div>
        )}

        {progress && (
          <div className="mt-4 space-y-2">
            <div className="flex justify-between text-sm font-medium text-gray-700">
              <span className="capitalize">{progress.stage}...</span>
              <span>{progress.percent}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2.5 overflow-hidden">
              <div
                className="bg-indigo-600 h-2.5 rounded-full transition-all duration-300"
                style={{ width: `${progress.percent}%` }}
              />
            </div>
          </div>
        )}

        <div className="mt-6 flex justify-end space-x-3">
          <button
            onClick={onClose}
            disabled={!!progress}
            className="px-4 py-2 border border-gray-300 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={handleUpload}
            disabled={!file || !!progress}
            className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 disabled:opacity-50 transition shadow-sm"
          >
            Encrypt & Upload
          </button>
        </div>
      </div>
    </div>
  );
}
