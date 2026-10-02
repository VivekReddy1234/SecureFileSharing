import {
  AuthRegisterRequest,
  AuthLoginRequest,
  AuthLoginResponse,
  AuthRefreshResponse,
  AuthSaltResponse,
  AuthChangePasswordRequest,
  FileInitUploadRequest,
  FileInitUploadResponse,
  FileCompleteUploadRequest,
  FileCompleteUploadResponse,
  FileDownloadUrlResponse,
  ShareCreateRequest,
  ShareLinkCreateRequest,
  ShareLinkCreateResponse,
  ShareLinkAccessResponse,
  ShareResponse,
  PaginatedResponse,
  FileListItem,
  AuditLogEntry,
  AdminUserListItem,
  AdminUserUpdateRequest,
  UserPublicInfo,
  UserProfile,
} from '@ciphervault/shared';

export const NEXT_PUBLIC_API_URL =
  (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000').replace(/\/+$/, '');

let memoryAccessToken: string | null = null;

export const setAccessToken = (token: string | null) => {
  memoryAccessToken = token;
};

export const getAccessToken = () => memoryAccessToken;

async function fetchWithAuth<T = unknown>(url: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers || {});
  headers.set('X-Requested-With', 'CipherVault');

  if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }

  if (memoryAccessToken) {
    headers.set('Authorization', `Bearer ${memoryAccessToken}`);
  }

  const reqOptions: RequestInit = {
    ...options,
    headers,
    credentials: 'include', // for refresh token httpOnly cookie
  };

  let res = await fetch(`${NEXT_PUBLIC_API_URL}${url}`, reqOptions);

  if (res.status === 401 && !url.includes('/auth/login') && !url.includes('/auth/refresh')) {
    // Try silent refresh
    try {
      const refreshRes = await fetch(`${NEXT_PUBLIC_API_URL}/auth/refresh`, {
        method: 'POST',
        headers: { 'X-Requested-With': 'CipherVault' },
        credentials: 'include',
      });
      if (refreshRes.ok) {
        const data: AuthRefreshResponse = await refreshRes.json();
        setAccessToken(data.accessToken);
        headers.set('Authorization', `Bearer ${data.accessToken}`);
        reqOptions.headers = headers;
        res = await fetch(`${NEXT_PUBLIC_API_URL}${url}`, reqOptions);
      } else {
        setAccessToken(null);
      }
    } catch {
      setAccessToken(null);
    }
  }

  if (!res.ok) {
    let errorMsg = 'API Error';
    try {
      const errorData = await res.json();
      errorMsg = errorData.error?.message || errorData.message || errorMsg;
    } catch {
      errorMsg = res.statusText || errorMsg;
    }
    throw new Error(errorMsg);
  }

  if (res.status === 204) {
    return {} as T;
  }

  return res.json();
}

export const api = {
  getSalt: (email: string) =>
    fetchWithAuth<AuthSaltResponse>(`/auth/salt?email=${encodeURIComponent(email.toLowerCase().trim())}`, {
      method: 'GET',
    }),

  register: (data: AuthRegisterRequest) =>
    fetchWithAuth<{ id: string; email: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  login: (data: AuthLoginRequest) =>
    fetchWithAuth<AuthLoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  refresh: () =>
    fetchWithAuth<AuthRefreshResponse>('/auth/refresh', {
      method: 'POST',
    }),

  logout: () =>
    fetchWithAuth<{ success: boolean }>('/auth/logout', {
      method: 'POST',
    }),

  changePassword: (data: AuthChangePasswordRequest) =>
    fetchWithAuth<{ success: boolean }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getMe: () =>
    fetchWithAuth<UserProfile>('/users/me', {
      method: 'GET',
    }),

  lookupUser: (email: string) =>
    fetchWithAuth<UserPublicInfo>(`/users/lookup?email=${encodeURIComponent(email)}`, {
      method: 'GET',
    }),

  initUpload: (data: FileInitUploadRequest) =>
    fetchWithAuth<FileInitUploadResponse>('/files/init-upload', {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  completeUpload: (fileId: string, data: FileCompleteUploadRequest) =>
    fetchWithAuth<FileCompleteUploadResponse>(`/files/${fileId}/complete-upload`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getFiles: (cursor?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (cursor) params.append('cursor', cursor);
    if (limit) params.append('limit', limit.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchWithAuth<PaginatedResponse<FileListItem>>(`/files${query}`, {
      method: 'GET',
    });
  },

  getFile: (id: string) =>
    fetchWithAuth<{
      id: string;
      ownerId: string;
      sizeBytes: string;
      status: string;
      createdAt: string;
      updatedAt: string;
      encryptedManifestBase64: string;
      manifestIvBase64: string;
      wrappedKeyBase64: string;
    }>(`/files/${id}`, {
      method: 'GET',
    }),

  getDownloadUrl: (id: string) =>
    fetchWithAuth<FileDownloadUrlResponse>(`/files/${id}/download-url`, {
      method: 'GET',
    }),

  deleteFile: (id: string) =>
    fetchWithAuth<void>(`/files/${id}`, {
      method: 'DELETE',
    }),

  createShare: (fileId: string, data: ShareCreateRequest) =>
    fetchWithAuth<ShareResponse>(`/files/${fileId}/shares`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  getShares: (fileId: string) =>
    fetchWithAuth<ShareResponse[]>(`/files/${fileId}/shares`, {
      method: 'GET',
    }),

  revokeShare: (shareId: string) =>
    fetchWithAuth<void>(`/shares/${shareId}`, {
      method: 'DELETE',
    }),

  createShareLink: (fileId: string, data: ShareLinkCreateRequest) =>
    fetchWithAuth<ShareLinkCreateResponse>(`/files/${fileId}/share-links`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),

  accessShareLink: (linkId: string, password?: string) => {
    const query = password ? `?password=${encodeURIComponent(password)}` : '';
    return fetchWithAuth<ShareLinkAccessResponse>(`/share-links/${linkId}${query}`, {
      method: 'GET',
    });
  },

  revokeShareLink: (linkId: string) =>
    fetchWithAuth<void>(`/share-links/${linkId}`, {
      method: 'DELETE',
    }),

  getAuditLog: (cursor?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (cursor) params.append('cursor', cursor);
    if (limit) params.append('limit', limit.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchWithAuth<PaginatedResponse<AuditLogEntry>>(`/audit${query}`, {
      method: 'GET',
    });
  },

  adminGetUsers: (cursor?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (cursor) params.append('cursor', cursor);
    if (limit) params.append('limit', limit.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchWithAuth<PaginatedResponse<AdminUserListItem>>(`/admin/users${query}`, {
      method: 'GET',
    });
  },

  adminUpdateUser: (id: string, data: AdminUserUpdateRequest) =>
    fetchWithAuth<AdminUserListItem>(`/admin/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    }),

  adminGetAudit: (cursor?: string, limit?: number) => {
    const params = new URLSearchParams();
    if (cursor) params.append('cursor', cursor);
    if (limit) params.append('limit', limit.toString());
    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchWithAuth<PaginatedResponse<AuditLogEntry>>(`/admin/audit${query}`, {
      method: 'GET',
    });
  },
};
