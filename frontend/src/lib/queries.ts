"use client";

import {
  keepPreviousData,
  useInfiniteQuery,
  useQuery,
  type InfiniteData,
  type QueryKey,
} from "@tanstack/react-query";

import { meApi, orgApi, type PageQuery } from "@/lib/api/endpoints";
import type { OrgMember, Page, UUID } from "@/lib/api/types";
import { useAuth } from "@/lib/auth/session";

export const PAGE_SIZE = 50;

export const keys = {
  me: ["me"] as const,
  meInOrg: (orgId: UUID) => ["me", orgId] as const,
  invitations: ["invitations"] as const,
  org: (orgId: UUID) => ["org", orgId] as const,
  orgDetails: (orgId: UUID) => ["org", orgId, "details"] as const,
  members: (orgId: UUID, f?: object) => ["org", orgId, "members", f ?? {}] as const,
  directory: (orgId: UUID) => ["org", orgId, "directory"] as const,
  overrides: (orgId: UUID, userId: UUID) => ["org", orgId, "overrides", userId] as const,
  projects: (orgId: UUID, f?: object) => ["org", orgId, "projects", f ?? {}] as const,
  project: (orgId: UUID, id: UUID) => ["org", orgId, "project", id] as const,
  projectMembers: (orgId: UUID, id: UUID) => ["org", orgId, "project", id, "members"] as const,
  tasks: (orgId: UUID, f?: object) => ["org", orgId, "tasks", f ?? {}] as const,
  task: (orgId: UUID, id: UUID) => ["org", orgId, "task", id] as const,
  documents: (orgId: UUID, f?: object) => ["org", orgId, "documents", f ?? {}] as const,
  audit: (orgId: UUID, f?: object) => ["org", orgId, "audit", f ?? {}] as const,
};

/** Prefixes for invalidation (match every filter combination). */
export const prefixes = {
  members: (orgId: UUID) => ["org", orgId, "members"],
  projects: (orgId: UUID) => ["org", orgId, "projects"],
  tasks: (orgId: UUID) => ["org", orgId, "tasks"],
  documents: (orgId: UUID) => ["org", orgId, "documents"],
};

// ------------------------------------------------------------------ me
export function useMe() {
  const { status } = useAuth();
  return useQuery({ queryKey: keys.me, queryFn: () => meApi.get(), enabled: status === "authenticated" });
}

export function useMeInOrg(orgId: UUID) {
  const { status } = useAuth();
  return useQuery({
    queryKey: keys.meInOrg(orgId),
    queryFn: () => meApi.get(orgId),
    enabled: status === "authenticated" && !!orgId,
  });
}

export function useInvitations() {
  const { status } = useAuth();
  return useQuery({
    queryKey: keys.invitations,
    queryFn: () => meApi.invitations(),
    enabled: status === "authenticated",
  });
}

// ------------------------------------------------------------------ pagination
/** Cursor-paginated list (keyset pagination on the backend). */
export function usePaged<T>(key: QueryKey, fetchPage: (q: PageQuery) => Promise<Page<T>>, enabled = true) {
  const query = useInfiniteQuery<Page<T>, Error, InfiniteData<Page<T>>, QueryKey, string | null>({
    queryKey: key,
    queryFn: ({ pageParam }) => fetchPage({ cursor: pageParam, limit: PAGE_SIZE }),
    initialPageParam: null,
    getNextPageParam: (last) => last.next_cursor,
    placeholderData: keepPreviousData,
    enabled,
  });
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  return { ...query, items };
}

// ------------------------------------------------------------------ directory
export interface DirectoryEntry {
  name: string;
  email: string | null;
  member?: OrgMember;
}

/**
 * user_id -> name for the whole org. Requires user.read; without it RLS returns
 * only the caller's own row, and the UI falls back to short ids.
 */
export function useDirectory(orgId: UUID, enabled = true) {
  return useQuery({
    queryKey: keys.directory(orgId),
    staleTime: 60_000,
    enabled,
    queryFn: async () => {
      const api = orgApi(orgId);
      const all: OrgMember[] = [];
      let cursor: string | null = null;
      for (let i = 0; i < 20; i++) {
        const page: Page<OrgMember> = await api.members({ cursor, limit: 100 });
        all.push(...page.items);
        cursor = page.next_cursor;
        if (!cursor) break;
      }
      return all;
    },
  });
}
