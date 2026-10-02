const rawApiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

let apiOrigin = 'http://localhost:4000';
let apiWebSocketOrigin = 'ws://localhost:4000';

try {
  const parsed = new URL(rawApiUrl);
  apiOrigin = parsed.origin;
  parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
  apiWebSocketOrigin = parsed.origin;
} catch {
  // Keep secure localhost fallbacks for malformed env values
}

const connectSrc = ["'self'", apiOrigin, apiWebSocketOrigin];
if (process.env.NODE_ENV !== 'production') {
  connectSrc.push('ws://localhost:3000');
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  headers: async () => {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-DNS-Prefetch-Control',
            value: 'off',
          },
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
          },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=63072000; includeSubDomains; preload',
          },
          {
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: blob:",
              "font-src 'self' data:",
              `connect-src ${connectSrc.join(' ')}`,
              "object-src 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              "frame-ancestors 'none'",
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default nextConfig;
