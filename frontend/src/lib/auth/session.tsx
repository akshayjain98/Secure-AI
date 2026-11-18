"use client";

import { useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";

import { refreshAccessToken, tokenStore } from "@/lib/api/client";
import { authApi } from "@/lib/api/endpoints";

export type AuthStatus = "loading" | "authenticated" | "unauthenticated" | "offline";

interface AuthContextValue {
  status: AuthStatus;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  retry: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

// Set by an explicit sign-out so the auth gate doesn't add ?next=<previous page>:
// the next person to sign in on this browser shouldn't land on the last user's URL.
let signedOutDeliberately = false;
export function consumeDeliberateSignOut() {
  const v = signedOutDeliberately;
  signedOutDeliberately = false;
  return v;
}
const CHANNEL = "secureai-auth";
type AuthMessage = { type: "login" } | { type: "logout" };

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient();
  // Survives client-side navigation: the provider stays mounted, so a token
  // already in memory means we're signed in. On a fresh load it's "loading".
  const [status, setStatus] = useState<AuthStatus>(() => (tokenStore.get() ? "authenticated" : "loading"));
  const channel = useRef<BroadcastChannel | null>(null);

  /** Ask the server whether the refresh cookie still holds a session. */
  const bootstrap = useCallback(() => {
    refreshAccessToken()
      .then((t) => setStatus(t ? "authenticated" : "unauthenticated"))
      // Network/5xx/429: the session may still be valid. Don't log the user out.
      .catch(() => setStatus("offline"));
  }, []);

  const retry = useCallback(() => {
    setStatus("loading");
    bootstrap();
  }, [bootstrap]);

  useEffect(() => {
    const unsubscribe = tokenStore.subscribe((authed) => {
      setStatus(authed ? "authenticated" : "unauthenticated");
      // Another user's cached data must never survive a session change.
      if (!authed) queryClient.clear();
    });
    if (!tokenStore.get()) bootstrap();
    return unsubscribe;
  }, [bootstrap, queryClient]);

  // Keep tabs in sync: signing out anywhere signs out everywhere; signing in
  // elsewhere lets an idle tab pick up the new session.
  useEffect(() => {
    if (typeof BroadcastChannel === "undefined") return;
    const ch = new BroadcastChannel(CHANNEL);
    ch.onmessage = (e: MessageEvent<AuthMessage>) => {
      if (e.data?.type === "logout") tokenStore.clear();
      if (e.data?.type === "login" && !tokenStore.get()) bootstrap();
    };
    channel.current = ch;
    return () => {
      ch.close();
      channel.current = null;
    };
  }, [bootstrap]);

  const login = useCallback(
    async (email: string, password: string) => {
      queryClient.clear();
      await authApi.login(email, password);
      channel.current?.postMessage({ type: "login" } satisfies AuthMessage);
    },
    [queryClient],
  );

  const logout = useCallback(async () => {
    signedOutDeliberately = true;
    try {
      await authApi.logout();
    } finally {
      queryClient.clear();
      channel.current?.postMessage({ type: "logout" } satisfies AuthMessage);
    }
  }, [queryClient]);

  const value = useMemo(() => ({ status, login, logout, retry }), [status, login, logout, retry]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

/** Only same-site relative paths are accepted as a post-login destination (no open redirect). */
export function safeNext(next: string | null | undefined, fallback = "/"): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) return fallback;
  if (next.startsWith("/auth") || next.startsWith("/api")) return fallback;
  return next;
}
