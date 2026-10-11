
const rawApiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000';

let apiOrigin = 'http://localhost:4000';
let apiWebSocketOrigin = 'ws://localhost:4000';

try {
  const parsed = new URL(rawApiUrl);
  apiOrigin = parsed.origin;
  parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
  apiWebSocketOrigin = parsed.origin;
} catch {
  // Relative URLs such as /api/backend use the same origin.
}

const connectSrc = [
  "'self'",
  apiOrigin,
  apiWebSocketOrigin,
  'https://cipher-vault-s3-bucket.s3.ap-southeast-2.amazonaws.com',
];

if (process.env.NODE_ENV !== 'production') {
  connectSrc.push('ws://localhost:3000');
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  // Proxy API calls through the Vercel domain so the browser
  // can use a same-origin cookie instead of a third-party cookie.
  async rewrites() {
    return [
      {
        source: '/api/backend/:path*',
        destination:
          'https://securefilesharing-hy08.onrender.com/:path*',
      },
    ];
  },

  async headers() {
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
            value:
              'camera=(), microphone=(), geolocation=(), browsing-topics=()',
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
