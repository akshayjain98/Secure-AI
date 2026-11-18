"use client";

import { useQuery } from "@tanstack/react-query";
import { ArrowRightIcon, CheckSquareIcon, FileTextIcon, FolderKanbanIcon, type LucideIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

import { PriorityLabel, TaskStatusBadge, VisibilityBadge } from "@/components/common/badges";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { TaskFormDialog } from "@/components/tasks/task-form-dialog";
import type { Task } from "@/lib/api/types";
import { dueLabel, fmtRelative, roleName } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys } from "@/lib/queries";
import { cn } from "@/lib/utils";

function count(n: number | undefined, more: boolean) {
  if (n === undefined) return "—";
  return more ? `${n}+` : String(n);
}

function Stat({ label, value, icon: Icon, href, loading }: { label: string; value: string; icon: LucideIcon; href: string; loading: boolean }) {
  return (
    <Link href={href} className="group">
      <Card className="transition-colors group-hover:bg-muted/40">
        <CardHeader>
          <CardDescription>{label}</CardDescription>
          <CardTitle className="text-3xl font-semibold tabular-nums">{loading ? <Skeleton className="h-9 w-12" /> : value}</CardTitle>
          <CardAction>
            <Icon className="size-5 text-muted-foreground" />
          </CardAction>
        </CardHeader>
      </Card>
    </Link>
  );
}

function SectionCard({ title, href, children }: { title: string; href: string; children: React.ReactNode }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardAction>
          <Button variant="ghost" size="sm" nativeButton={false} render={<Link href={href} />}>
            View all <ArrowRightIcon />
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>{children}</CardContent>
    </Card>
  );
}

const Empty = ({ children }: { children: React.ReactNode }) => <p className="py-6 text-center text-sm text-muted-foreground">{children}</p>;

export function Overview() {
  const { api, orgId, me, org, role, can } = useOrg();
  const [openTask, setOpenTask] = useState<Task | undefined>();

  const myTasks = useQuery({
    queryKey: keys.tasks(orgId, { assigned_to_me: true, overview: true }),
    queryFn: () => api.tasks({ assigned_to_me: true, limit: 100 }),
    enabled: can("task.read"),
  });
  const projects = useQuery({
    queryKey: keys.projects(orgId, { status: "active", overview: true }),
    queryFn: () => api.projects({ status: "active", limit: 100 }),
    enabled: can("project.read"),
  });
  const docs = useQuery({
    queryKey: keys.documents(orgId, { overview: true }),
    queryFn: () => api.documents({ limit: 100 }),
    enabled: can("document.read"),
  });

  const open = myTasks.data?.items.filter((t) => t.status !== "done") ?? [];
  const firstName = me.display_name.split(" ")[0];

  return (
    <>
      <div className="mb-6 space-y-1">
        <h1 className="font-heading text-2xl font-semibold tracking-tight">Welcome back, {firstName}</h1>
        <p className="text-sm text-muted-foreground">
          {org.name} · {roleName(role)}
        </p>
      </div>

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        {can("task.read") && (
          <Stat
            label="Open tasks assigned to you"
            value={count(myTasks.data ? open.length : undefined, !!myTasks.data?.next_cursor)}
            icon={CheckSquareIcon}
            href={`/orgs/${orgId}/tasks`}
            loading={myTasks.isPending}
          />
        )}
        {can("project.read") && (
          <Stat
            label="Active projects"
            value={count(projects.data?.items.length, !!projects.data?.next_cursor)}
            icon={FolderKanbanIcon}
            href={`/orgs/${orgId}/projects`}
            loading={projects.isPending}
          />
        )}
        {can("document.read") && (
          <Stat
            label="Documents you can see"
            value={count(docs.data?.items.length, !!docs.data?.next_cursor)}
            icon={FileTextIcon}
            href={`/orgs/${orgId}/documents`}
            loading={docs.isPending}
          />
        )}
      </div>

      <div className="grid gap-6 lg:grid-cols-5">
        {can("task.read") && (
          <div className="lg:col-span-3">
            <SectionCard title="Your open tasks" href={`/orgs/${orgId}/tasks`}>
              {myTasks.isPending ? (
                <Skeleton className="h-32 w-full" />
              ) : open.length === 0 ? (
                <Empty>Nothing assigned to you. Nice.</Empty>
              ) : (
                <ul className="-mx-2 divide-y">
                  {open.slice(0, 7).map((t) => {
                    const due = dueLabel(t.due_date);
                    return (
                      <li key={t.id}>
                        <button
                          onClick={() => setOpenTask(t)}
                          className="flex w-full items-center gap-3 rounded-md px-2 py-2.5 text-left hover:bg-muted/50"
                        >
                          <span className="min-w-0 flex-1 truncate text-sm font-medium">{t.title}</span>
                          <PriorityLabel priority={t.priority} />
                          {due && (
                            <span className={cn("hidden w-14 text-right text-xs text-muted-foreground sm:block", due.overdue && "text-red-600 dark:text-red-400")}>
                              {due.text}
                            </span>
                          )}
                          <TaskStatusBadge status={t.status} />
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </SectionCard>
          </div>
        )}
        <div className="space-y-6 lg:col-span-2">
          {can("project.read") && (
            <SectionCard title="Projects" href={`/orgs/${orgId}/projects`}>
              {projects.isPending ? (
                <Skeleton className="h-24 w-full" />
              ) : !projects.data?.items.length ? (
                <Empty>No active projects yet.</Empty>
              ) : (
                <ul className="-mx-2">
                  {projects.data.items.slice(0, 5).map((p) => (
                    <li key={p.id}>
                      <Link href={`/orgs/${orgId}/projects/${p.id}`} className="flex items-center gap-2 rounded-md px-2 py-2 hover:bg-muted/50">
                        <FolderKanbanIcon className="size-4 text-muted-foreground" />
                        <span className="min-w-0 flex-1 truncate text-sm">{p.name}</span>
                        <span className="text-xs text-muted-foreground">{fmtRelative(p.updated_at)}</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </SectionCard>
          )}
          {can("document.read") && (
            <SectionCard title="Recent documents" href={`/orgs/${orgId}/documents`}>
              {docs.isPending ? (
                <Skeleton className="h-24 w-full" />
              ) : !docs.data?.items.length ? (
                <Empty>No documents yet.</Empty>
              ) : (
                <ul className="space-y-2.5">
                  {docs.data.items.slice(0, 5).map((d) => (
                    <li key={d.id} className="flex items-center gap-2">
                      <FileTextIcon className="size-4 shrink-0 text-muted-foreground" />
                      <span className="min-w-0 flex-1 truncate text-sm">{d.title}</span>
                      <VisibilityBadge visibility={d.visibility} />
                    </li>
                  ))}
                </ul>
              )}
            </SectionCard>
          )}
        </div>
      </div>
      <TaskFormDialog open={!!openTask} onOpenChange={(o) => !o && setOpenTask(undefined)} task={openTask} />
    </>
  );
}
