import type { NextConfig } from "next";

/**
 * The browser only ever talks to this origin. Next proxies two prefixes to
 * the FastAPI backend so the refresh cookie keeps working unchanged:
 *
 *   /auth/*  -> {API}/auth/*   (cookie is Path=/auth, SameSite=Strict, so it
 *                               must be served same-origin at this exact path)
 *   /api/*   -> {API}/*        (everything else: /me, /orgs/...)
 *
 * Consequence: no page may live under /auth or /api.
 */
const API_ORIGIN = (process.env.SECUREAI_API_ORIGIN ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const isDev = process.env.NODE_ENV === "development";

// Static CSP (no nonces): nonces would force every route to dynamic rendering.
// 'unsafe-inline' for scripts is needed by Next's inline bootstrap without
// nonces. The access token never touches storage, and React escapes output,
// so this is defence in depth, not the primary XSS control.
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' blob: data:",
  "font-src 'self'",
  `connect-src 'self'${isDev ? " ws:" : ""}`,
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  poweredByHeader: false,
  experimental: {
    // Every page renders behind a client-side session check (the access token
    // only exists in browser memory), so implicit instant-navigation
    // validation of every page can't succeed by design. Validate only segments
    // that opt in with `export const instant = true`.
    instantInsights: { validationLevel: "manual-warning" },
  },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [
      { source: "/auth/:path*", destination: `${API_ORIGIN}/auth/:path*` },
      { source: "/api/:path*", destination: `${API_ORIGIN}/:path*` },
    ];
  },
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "Content-Security-Policy", value: csp },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          // Reset/verify tokens travel in the URL fragment; never leak the URL.
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
