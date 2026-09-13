/**
 * S3 Integration Service for CipherVault
 *
 * Handles presigned URL generation for secure, direct client-to-S3 transfers.
 * The backend NEVER receives file content — only generates presigned URLs and
 * verifies objects after upload.
 *
 * Design:
 * - S3 keys are server-generated UUIDs — never derived from user filenames (prevents path traversal)
 * - Presigned URLs are short-lived (15 min for upload, 5 min for download)
 * - The bucket is private, no public ACLs, server-side encryption enabled (defense in depth)
 */

import {
  S3Client,
  CreateMultipartUploadCommand,
  UploadPartCommand,
  CompleteMultipartUploadCommand,
  AbortMultipartUploadCommand,
  HeadObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { v4 as uuidv4 } from 'uuid';

// Lazy-initialize to avoid import-time env access
let s3Client: S3Client | null = null;
let bucketName: string | null = null;

function getS3Client(): S3Client {
  if (!s3Client) {
    s3Client = new S3Client({
      region: process.env.AWS_REGION,
      credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? '',
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? '',
      },
    });
  }
  return s3Client;
}

function getBucket(): string {
  if (!bucketName) {
    bucketName = process.env.AWS_S3_BUCKET ?? '';
    if (!bucketName) {
      throw new Error('AWS_S3_BUCKET environment variable is not set');
    }
  }
  return bucketName;
}

/** Upload presigned URL expiry: 15 minutes */
const UPLOAD_URL_EXPIRY_SECONDS = 900;

/** Download presigned URL expiry: 5 minutes */
const DOWNLOAD_URL_EXPIRY_SECONDS = 300;

/**
 * Generate a unique S3 key for a new file.
 * Uses UUID v4 — never derived from user-supplied filenames.
 */
export function generateS3Key(userId: string): string {
  // Organize by user ID for easier lifecycle management
  return `files/${userId}/${uuidv4()}`;
}

/**
 * Initiate an S3 multipart upload.
 * Returns the uploadId needed for subsequent part uploads and completion.
 */
export async function initiateMultipartUpload(s3Key: string): Promise<string> {
  const client = getS3Client();
  const command = new CreateMultipartUploadCommand({
    Bucket: getBucket(),
    Key: s3Key,
    // Content type is always application/octet-stream since the server
    // only sees ciphertext — the actual MIME type is in the encrypted manifest
    ContentType: 'application/octet-stream',
  });

  const response = await client.send(command);
  if (!response.UploadId) {
    throw new Error('S3 multipart upload initiation failed — no UploadId returned');
  }
  return response.UploadId;
}

/**
 * Generate presigned URLs for uploading parts of a multipart upload.
 *
 * @param s3Key - The S3 object key
 * @param uploadId - The multipart upload ID from initiateMultipartUpload
 * @param partCount - Number of parts to generate URLs for
 * @returns Array of { partNumber, url, expiresAt }
 */
export async function generateUploadPartUrls(
  s3Key: string,
  uploadId: string,
  partCount: number
): Promise<Array<{ partNumber: number; url: string; expiresAt: string }>> {
  const client = getS3Client();
  const bucket = getBucket();
  const now = new Date();

  const urlPromises = Array.from({ length: partCount }, async (_, i) => {
    const partNumber = i + 1; // S3 part numbers are 1-based
    const command = new UploadPartCommand({
      Bucket: bucket,
      Key: s3Key,
      UploadId: uploadId,
      PartNumber: partNumber,
    });

    const url = await getSignedUrl(client, command, {
      expiresIn: UPLOAD_URL_EXPIRY_SECONDS,
    });

    const expiresAt = new Date(now.getTime() + UPLOAD_URL_EXPIRY_SECONDS * 1000);

    return {
      partNumber,
      url,
      expiresAt: expiresAt.toISOString(),
    };
  });

  return Promise.all(urlPromises);
}

/**
 * Complete a multipart upload after all parts have been uploaded.
 *
 * @param s3Key - The S3 object key
 * @param uploadId - The multipart upload ID
 * @param parts - Array of { partNumber, etag } from the client's direct S3 uploads
 */
export async function completeMultipartUpload(
  s3Key: string,
  uploadId: string,
  parts: Array<{ partNumber: number; etag: string }>
): Promise<void> {
  const client = getS3Client();

  // Parts MUST be sorted by partNumber for S3
  const sortedParts = [...parts].sort((a, b) => a.partNumber - b.partNumber);

  const command = new CompleteMultipartUploadCommand({
    Bucket: getBucket(),
    Key: s3Key,
    UploadId: uploadId,
    MultipartUpload: {
      Parts: sortedParts.map((p) => ({
        PartNumber: p.partNumber,
        ETag: p.etag,
      })),
    },
  });

  await client.send(command);
}

/**
 * Abort a multipart upload (cleanup on failure).
 */
export async function abortMultipartUpload(
  s3Key: string,
  uploadId: string
): Promise<void> {
  const client = getS3Client();
  const command = new AbortMultipartUploadCommand({
    Bucket: getBucket(),
    Key: s3Key,
    UploadId: uploadId,
  });

  try {
    await client.send(command);
  } catch {
    // Best-effort cleanup — S3 lifecycle rules will handle truly orphaned parts
  }
}

/**
 * Verify an S3 object exists and return its size.
 * Used after upload completion to verify the object was written correctly.
 */
export async function headObject(
  s3Key: string
): Promise<{ contentLength: number; exists: boolean }> {
  const client = getS3Client();
  try {
    const command = new HeadObjectCommand({
      Bucket: getBucket(),
      Key: s3Key,
    });
    const response = await client.send(command);
    return {
      contentLength: response.ContentLength ?? 0,
      exists: true,
    };
  } catch (error: unknown) {
    if (error instanceof Error && error.name === 'NotFound') {
      return { contentLength: 0, exists: false };
    }
    throw error;
  }
}

/**
 * Generate a presigned download URL.
 * ONLY call this AFTER authorization has been verified.
 */
export async function generateDownloadUrl(s3Key: string): Promise<{
  url: string;
  expiresAt: string;
}> {
  const client = getS3Client();
  const command = new GetObjectCommand({
    Bucket: getBucket(),
    Key: s3Key,
  });

  const url = await getSignedUrl(client, command, {
    expiresIn: DOWNLOAD_URL_EXPIRY_SECONDS,
  });

  const expiresAt = new Date(
    Date.now() + DOWNLOAD_URL_EXPIRY_SECONDS * 1000
  );

  return { url, expiresAt: expiresAt.toISOString() };
}

/**
 * Delete an S3 object.
 * Called when a file is permanently deleted.
 */
export async function deleteObject(s3Key: string): Promise<void> {
  const client = getS3Client();
  const command = new DeleteObjectCommand({
    Bucket: getBucket(),
    Key: s3Key,
  });
  await client.send(command);
}
