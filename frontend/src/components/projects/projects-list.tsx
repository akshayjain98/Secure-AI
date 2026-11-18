"use client";

import { ArchiveIcon, FolderKanbanIcon, PlusIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { PageHeader } from "@/components/common/page-header";
import { EmptyState, ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { UserAvatar } from "@/components/common/user-avatar";
import { ProjectFormDialog } from "@/components/projects/project-form-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ProjectStatus } from "@/lib/api/types";
import { fmtRelative } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, usePaged } from "@/lib/queries";

export function ProjectsList() {
  const { api, orgId, can, userName } = useOrg();
  const [status, setStatus] = useState<ProjectStatus>("active");
  const [creating, setCreating] = useState(false);
  const q = usePaged(keys.projects(orgId, { status }), (p) => api.projects({ ...p, status }));

  return (
    <>
      <PageHeader
        title="Projects"
        description={
          can("project.read_all")
            ? "All projects in the organization."
            : "Projects you own or are a member of."
        }
        actions={
          can("project.create") && (
            <Button onClick={() => setCreating(true)}>
              <PlusIcon /> New project
            </Button>
          )
        }
      />
      <Tabs value={status} onValueChange={(v) => setStatus(v as ProjectStatus)} className="mb-4">
        <TabsList>
          <TabsTrigger value="active">Active</TabsTrigger>
          <TabsTrigger value="archived">Archived</TabsTrigger>
        </TabsList>
      </Tabs>

      {q.isPending ? (
        <ListSkeleton rows={3} />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="projects" />
      ) : q.items.length === 0 ? (
        <EmptyState
          icon={status === "active" ? <FolderKanbanIcon /> : <ArchiveIcon />}
          title={status === "active" ? "No active projects" : "No archived projects"}
          description={
            status === "active"
              ? can("project.create")
                ? "Create your first project to start organizing tasks and documents."
                : "You'll see projects here once someone adds you to one."
              : "Archived projects are read-only and kept for reference."
          }
          action={
            status === "active" &&
            can("project.create") && (
              <Button onClick={() => setCreating(true)}>
                <PlusIcon /> New project
              </Button>
            )
          }
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {q.items.map((p) => (
            <Link key={p.id} href={`/orgs/${orgId}/projects/${p.id}`} className="group">
              <Card className="h-full transition-colors group-hover:bg-muted/40">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <span className="truncate">{p.name}</span>
                    {p.status === "archived" && <Badge variant="secondary">Archived</Badge>}
                  </CardTitle>
                  <CardDescription className="line-clamp-2 min-h-10">{p.description || "No description"}</CardDescription>
                </CardHeader>
                <CardFooter className="mt-auto gap-2 text-xs text-muted-foreground">
                  <UserAvatar name={userName(p.owner_id)} seed={p.owner_id} size="sm" />
                  <span className="truncate">{userName(p.owner_id)}</span>
                  <span className="ml-auto shrink-0">Updated {fmtRelative(p.updated_at)}</span>
                </CardFooter>
              </Card>
            </Link>
          ))}
        </div>
      )}
      <LoadMore {...q} />
      <ProjectFormDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}
