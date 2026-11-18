"use client";

import { ShieldOffIcon } from "lucide-react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo } from "react";

import { EmptyState, ErrorState, ListSkeleton } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api/client";
import { isUuid } from "@/lib/format";
import { setLastOrg } from "@/lib/last-org";
import { OrgContextProvider } from "@/lib/org-context";
import { useDirectory, useMeInOrg, type DirectoryEntry } from "@/lib/queries";

function NoAccess() {
  // One message for "doesn't exist", "another tenant's org" and "suspended":
  // the backend deliberately makes them indistinguishable.
  return (
    <EmptyState
      icon={<ShieldOffIcon />}
      title="No access to this organization"
      description="It doesn't exist, or your membership isn't active."
      action={<Button nativeButton={false} render={<Link href="/orgs" />}>Your organizations</Button>}
    />
  );
}

/**
 * Binds the org from the URL. The server re-checks membership on EVERY
 * request (set_context()), so this only decides what to render.
 */
export function OrgGate({ children }: { children: React.ReactNode }) {
  const { orgId } = useParams<{ orgId: string }>();
  const valid = isUuid(orgId);
  const meQ = useMeInOrg(valid ? orgId : "");
  const current = meQ.data?.current_org;
  const canReadDirectory = !!current?.permissions.includes("user.read");
  const dirQ = useDirectory(orgId, !!current);

  useEffect(() => {
    if (current) setLastOrg(orgId);
  }, [current, orgId]);

  const directory = useMemo(() => {
    const m = new Map<string, DirectoryEntry>();
    for (const mem of dirQ.data ?? []) {
      m.set(mem.user_id, { name: mem.display_name ?? mem.email ?? "Invited user", email: mem.email, member: mem });
    }
    return m;
  }, [dirQ.data]);

  if (!valid) return <NoAccess />;
  if (meQ.isPending || (canReadDirectory && dirQ.isPending)) return <ListSkeleton rows={6} />;
  if (meQ.error) {
    if (meQ.error instanceof ApiError && meQ.error.status === 403) return <NoAccess />;
    return <ErrorState error={meQ.error} onRetry={() => meQ.refetch()} what="this organization" />;
  }
  const me = meQ.data!;
  const org = me.organizations.find((o) => o.id === orgId);
  if (!current || !org) return <NoAccess />;

  return (
    <OrgContextProvider me={me} org={org} role={current.role} permissions={current.permissions} directory={directory}>
      {children}
    </OrgContextProvider>
  );
}
