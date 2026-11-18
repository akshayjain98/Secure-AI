"use client";

import { useQuery } from "@tanstack/react-query";
import { useMemo } from "react";

import { useOrg } from "@/lib/org-context";
import { keys } from "@/lib/queries";

/** id -> name for the projects the caller can see (first 100, both statuses). */
export function useProjectNames() {
  const { api, orgId, can } = useOrg();
  const q = useQuery({
    queryKey: keys.projects(orgId, { names: true }),
    queryFn: () => api.projects({ limit: 100 }),
    enabled: can("project.read"),
    staleTime: 60_000,
  });
  const names = useMemo(() => new Map((q.data?.items ?? []).map((p) => [p.id, p.name])), [q.data]);
  return { names, projects: q.data?.items ?? [] };
}
