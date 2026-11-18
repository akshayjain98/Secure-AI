/**
 * HTTP client for the SecureAI API.
 *
 * Session model (matches app/api/routes_auth.py):
 * - The access token (JWT, ~10 min) lives ONLY in this module's memory. It is
 *   never written to localStorage/sessionStorage/cookies, so an XSS payload
 *   can't lift a long-lived credential from storage.
 * - The refresh token is an HttpOnly, SameSite=Strict cookie scoped to
 *   Path=/auth. JavaScript never sees it; the browser attaches it to
 *   /auth/refresh and /auth/logout, which also need the X-SecureAI-CSRF header.
 * - Refresh tokens are single-use with reuse detection and NO grace window:
 *   two concurrent refreshes look like a replay and revoke the whole session.
 *   So refreshes are single-flight within a tab and serialized across tabs
 *   with the Web Locks API.
 */

import type { TokenOut } from "./types";

export const CSRF_HEADER = "X-SecureAI-CSRF";
const REFRESH_LOCK = "secureai-refresh";
const EXPIRY_SKEW_MS = 30_000;

// ------------------------------------------------------------------ errors
export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly requestId: string | null = null,
    public readonly fieldErrors: Record<string, string> = {},
  ) {
    super(message);
    this.name = "ApiError";
  }

  get isNotFound() {
    return this.status === 404;
  }
  get isForbidden() {
    return this.status === 403;
  }
}

type FastApiValidationItem = { loc?: (string | number)[]; msg?: string };

async function toApiError(res: Response): Promise<ApiError> {
  const requestId = res.headers.get("X-Request-ID");
  let detail: unknown = undefined;
  try {
    detail = (await res.json())?.detail;
  } catch {
    /* empty or non-JSON body */
  }
  if (typeof detail === "string") return new ApiError(res.status, detail, requestId);
  if (Array.isArray(detail)) {
    // FastAPI/Pydantic 422: [{loc: ["body", "field"], msg}]
    const fieldErrors: Record<string, string> = {};
    for (const item of detail as FastApiValidationItem[]) {
      const field = item.loc?.filter((p) => p !== "body" && p !== "query" && p !== "path").join(".");
      if (field && item.msg && !fieldErrors[field]) fieldErrors[field] = item.msg.replace(/^Value error, /, "");
    }
    const first = Object.entries(fieldErrors)[0];
    const msg = first ? `${first[0]}: ${first[1]}` : "Invalid request";
    return new ApiError(res.status, msg, requestId, fieldErrors);
  }
  const fallback: Record<number, string> = {
    401: "Not authenticated",
    403: "You don't have permission to do that",
    404: "Not found",
    429: "Too many requests, please wait a moment",
  };
  return new ApiError(res.status, fallback[res.status] ?? "Something went wrong", requestId);
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof TypeError) return "Can't reach the server. Check your connection.";
  return "Something went wrong";
}

// ------------------------------------------------------------------ token store
type Listener = (authenticated: boolean) => void;

let accessToken: string | null = null;
let expiresAt = 0;
const listeners = new Set<Listener>();

export const tokenStore = {
  get: () => accessToken,
  isFresh: () => accessToken !== null && Date.now() < expiresAt - EXPIRY_SKEW_MS,
  set(t: TokenOut) {
    accessToken = t.access_token;
    expiresAt = Date.now() + t.expires_in * 1000;
    listeners.forEach((l) => l(true));
  },
  clear() {
    const had = accessToken !== null;
    accessToken = null;
    expiresAt = 0;
    if (had) listeners.forEach((l) => l(false));
  },
  subscribe(l: Listener) {
    listeners.add(l);
    return () => void listeners.delete(l);
  },
};

// ------------------------------------------------------------------ refresh
let inflightRefresh: Promise<string | null> | null = null;

async function withCrossTabLock<T>(fn: () => Promise<T>): Promise<T> {
  if (typeof navigator !== "undefined" && navigator.locks?.request) {
    return navigator.locks.request(REFRESH_LOCK, fn) as Promise<T>;
  }
  return fn();
}

/**
 * Exchanges the refresh cookie for a new access token.
 * Resolves to the token, or null when there is no valid session (401/403).
 * Rejects on transient failures (network, 429, 5xx) WITHOUT ending the session.
 */
export function refreshAccessToken(): Promise<string | null> {
  if (inflightRefresh) return inflightRefresh;
  inflightRefresh = withCrossTabLock(async () => {
    const res = await fetch("/auth/refresh", {
      method: "POST",
      headers: { [CSRF_HEADER]: "1" },
      credentials: "same-origin",
      cache: "no-store",
    });
    if (res.ok) {
      const token = (await res.json()) as TokenOut;
      tokenStore.set(token);
      return token.access_token;
    }
    if (res.status === 401 || res.status === 403) {
      tokenStore.clear();
      return null;
    }
    throw await toApiError(res);
  }).finally(() => {
    inflightRefresh = null;
  });
  return inflightRefresh;
}

// ------------------------------------------------------------------ requests
export type Query = Record<string, string | number | boolean | null | undefined>;

export interface RequestOptions {
  method?: "GET" | "POST" | "PATCH" | "PUT" | "DELETE";
  body?: unknown;
  query?: Query;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Send the bearer token (default true). */
  auth?: boolean;
}

function buildUrl(path: string, query?: Query) {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== "" && v !== false) qs.set(k, String(v));
  }
  const s = qs.toString();
  return s ? `${path}?${s}` : path;
}

async function send(url: string, opts: RequestOptions, token: string | null) {
  const headers: Record<string, string> = { Accept: "application/json", ...opts.headers };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers.Authorization = `Bearer ${token}`;
  return fetch(url, {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    credentials: "same-origin",
    cache: "no-store",
    signal: opts.signal,
  });
}

/**
 * Low-level request against a same-origin path ("/api/..." or "/auth/...").
 * Authenticated requests refresh lazily when the token is about to expire,
 * and retry exactly once after a 401.
 */
export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const url = buildUrl(path, opts.query);
  const authed = opts.auth !== false;

  let token: string | null = null;
  if (authed) {
    token = tokenStore.isFresh() ? tokenStore.get() : await refreshAccessToken();
    if (!token) throw new ApiError(401, "Session expired, please sign in again");
  }

  let res = await send(url, opts, token);
  if (res.status === 401 && authed) {
    token = await refreshAccessToken();
    if (!token) throw new ApiError(401, "Session expired, please sign in again");
    res = await send(url, opts, token);
    if (res.status === 401) tokenStore.clear();
  }

  if (!res.ok) throw await toApiError(res);
  if (res.status === 204 || res.headers.get("content-length") === "0") return undefined as T;
  return (await res.json()) as T;
}

/** Shorthand for the proxied resource API (/api -> backend root). */
export const api = <T>(path: string, opts?: RequestOptions) => request<T>(`/api${path}`, opts);
