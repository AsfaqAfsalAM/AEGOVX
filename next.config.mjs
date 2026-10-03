/** @type {import('next').NextConfig} */

// ─── CSP Audit (full codebase scan 2026-10-03) ──────────────────────────────
//
// SCRIPTS     : 'self' + 'unsafe-inline'. Tailwind=build-time. Lucide=npm bundle.
//               Next.js 15 injects inline hydration scripts → unsafe-inline needed.
//               'unsafe-eval' NOT needed → REMOVED (was a serious XSS risk).
//
// STYLES      : 'self' + 'unsafe-inline'. Tailwind dark-mode utilities use style
//               injection. NO Google Fonts — confirmed zero usage in codebase.
//
// FONTS       : 'self' only. No Google Fonts, Typekit, or any external font CDN.
//
// IMAGES      : 'self' + data: (Lucide inline SVGs) + blob: (window.print() PDFs)
//
// CONNECT-SRC : 'self' only. ALL external API calls (VirusTotal, URLhaus,
//               Google Safe Browsing, RDAP, Spamhaus) are server-side in
//               Next.js API routes. The browser only calls /api/* on 'self'.
//
// FRAME-SRC   : 'none'. No iframes anywhere in the codebase.
// OBJECT-SRC  : 'none'. No Flash, no plugins.
// BASE-URI    : 'self'. Prevents base-tag injection.
// FORM-ACTION : 'self'. All forms POST to /api/scan.
// ─────────────────────────────────────────────────────────────────────────────

const ContentSecurityPolicy = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "frame-src 'none'",
  "object-src 'none'",
  "worker-src 'self' blob:",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "upgrade-insecure-requests",
].join('; ');

const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  async headers() {
    return [
      {
        // Apply to ALL routes
        source: '/(.*)',
        headers: [
          // Clickjacking — DENY is stricter than SAMEORIGIN; no pages should be iframed
          { key: 'X-Frame-Options', value: 'DENY' },

          // MIME sniffing
          { key: 'X-Content-Type-Options', value: 'nosniff' },

          // Referrer leakage — sends origin only; omits on downgrade
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },

          // Browser features — disable everything not used
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), battery=(), interest-cohort=()',
          },

          // DNS prefetch performance hint
          { key: 'X-DNS-Prefetch-Control', value: 'on' },

          // HSTS — 1 year, includeSubDomains, eligible for preload list
          { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' },

          // Cross-Origin Policies — isolate from Spectre-class attacks
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Embedder-Policy', value: 'require-corp' },

          // CSP — see full audit comment above
          { key: 'Content-Security-Policy', value: ContentSecurityPolicy },
        ],
      },

      // Badge SVG API — must be cross-origin embeddable by other websites
      // Relaxes CORP + adds CORS for this route only
      {
        source: '/api/public/badge',
        headers: [
          { key: 'Cross-Origin-Resource-Policy', value: 'cross-origin' },
          { key: 'Cross-Origin-Embedder-Policy', value: 'unsafe-none' },
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Cache-Control', value: 'public, max-age=3600, stale-while-revalidate=86400' },
        ],
      },

      // Public API — allow cross-origin JSON fetches (for third-party integrations)
      {
        source: '/api/public/:path*',
        headers: [
          { key: 'Access-Control-Allow-Origin', value: '*' },
          { key: 'Access-Control-Allow-Methods', value: 'GET, OPTIONS' },
          { key: 'Cross-Origin-Resource-Policy', value: 'cross-origin' },
          { key: 'Cross-Origin-Embedder-Policy', value: 'unsafe-none' },
        ],
      },
    ];
  },
};

export default nextConfig;
