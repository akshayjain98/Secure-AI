"use client";

import { createContext, useCallback, useContext, useMemo } from "react";

import { orgApi, type OrgApi } from "@/lib/api/endpoints";
import type { Me, MeOrg, Permission, RoleKey, UUID } from "@/lib/api/types";
import { ROLES } from "@/lib/api/types";
import { shortId } from "@/lib/format";
import type { DirectoryEntry } from "@/lib/queries";

export interface OrgContextValue {
  orgId: UUID;
  org: MeOrg;
  me: Me;
  role: RoleKey;
  rank: number;
  permissions: ReadonlySet<Permission>;
  api: OrgApi;
  /**
   * UI hint only: hides controls the backend would refuse anyway. The
   * database (RLS) is the authority; every action still handles 403/404.
   */
  can: (p: Permission) => boolean;
  directory: ReadonlyMap<UUID, DirectoryEntry>;
  userName: (id: UUID | null | undefined) => string;
}

const OrgContext = createContext<OrgContextValue | null>(null);

export function OrgContextProvider({
  me,
  org,
  role,
  permissions,
  directory,
  children,
}: {
  me: Me;
  org: MeOrg;
  role: RoleKey;
  permissions: Permission[];
  directory: ReadonlyMap<UUID, DirectoryEntry>;
  children: React.ReactNode;
}) {
  const permSet = useMemo(() => new Set(permissions), [permissions]);
  const can = useCallback((p: Permission) => permSet.has(p), [permSet]);
  const userName = useCallback(
    (id: UUID | null | undefined) => {
      if (!id) return "Unassigned";
      if (id === me.id) return `${me.display_name} (you)`;
      const e = directory.get(id);
      return e?.name ?? e?.email ?? `User ${shortId(id)}`;
    },
    [directory, me],
  );

  const value = useMemo<OrgContextValue>(
    () => ({
      orgId: org.id,
      org,
      me,
      role,
      rank: ROLES[role]?.rank ?? 0,
      permissions: permSet,
      api: orgApi(org.id),
      can,
      directory,
      userName,
    }),
    [org, me, role, permSet, can, directory, userName],
  );
  return <OrgContext.Provider value={value}>{children}</OrgContext.Provider>;
}

export function useOrg() {
  const ctx = useContext(OrgContext);
  if (!ctx) throw new Error("useOrg must be used within an organization route");
  return ctx;
}
