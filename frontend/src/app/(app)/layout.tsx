import { Suspense } from "react";

import { AppFrame } from "@/components/app-shell/app-frame";
import { AuthGate } from "@/components/app-shell/auth-gate";
import { FullPageLoader } from "@/components/common/states";

// The session lives in browser memory (see lib/api/client.ts), so everything
// below renders on the client behind <AuthGate>; the server only sends the
// static shell. Navigations into this area may block on that client-side
// session check, so it opts out of instant-navigation validation. It is still
// prerendered and streamed.
export const instant = false;

export default function AppLayout({ children }: LayoutProps<"/">) {
  return (
    <Suspense fallback={<FullPageLoader />}>
      <AuthGate>
        <AppFrame>{children}</AppFrame>
      </AuthGate>
    </Suspense>
  );
}
