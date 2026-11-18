"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { FullPageLoader } from "@/components/common/states";
import { safeNext, useAuth } from "@/lib/auth/session";

/** For sign-in / sign-up: an already signed-in visitor goes straight to the app. */
export function GuestOnly({ children }: { children: React.ReactNode }) {
  const { status } = useAuth();
  const router = useRouter();
  useEffect(() => {
    if (status === "authenticated") {
      router.replace(safeNext(new URLSearchParams(window.location.search).get("next")));
    }
  }, [status, router]);
  if (status === "loading" || status === "authenticated") return <FullPageLoader label="Checking your session…" />;
  return <>{children}</>;
}
