"use client";

import { CloudOffIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageLoader } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { consumeDeliberateSignOut, useAuth } from "@/lib/auth/session";

/** Renders children only with a live session; otherwise sends the visitor to /login?next=… */
export function AuthGate({ children }: { children: React.ReactNode }) {
  const { status, retry } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") {
      if (consumeDeliberateSignOut()) return router.replace("/login");
      const next = window.location.pathname + window.location.search;
      router.replace(`/login?next=${encodeURIComponent(next)}`);
    }
  }, [status, router]);

  if (status === "offline")
    return (
      <div className="flex min-h-svh flex-col items-center justify-center gap-3 p-6 text-center">
        <CloudOffIcon className="size-8 text-muted-foreground" />
        <h1 className="font-heading text-lg font-semibold">Can&apos;t reach the server</h1>
        <p className="max-w-sm text-sm text-muted-foreground">
          Your session is still intact. Check your connection or that the API is running, then try again.
        </p>
        <Button onClick={retry}>Try again</Button>
      </div>
    );
  if (status !== "authenticated") return <FullPageLoader label="Checking your session…" />;
  return <>{children}</>;
}
