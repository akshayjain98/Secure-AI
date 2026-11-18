"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArchiveIcon,
  ArchiveRestoreIcon,
  ChevronLeftIcon,
  MoreHorizontalIcon,
  PencilIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { UserAvatar } from "@/components/common/user-avatar";
import { DocumentsPanel } from "@/components/documents/documents-panel";
import { ProjectFormDialog } from "@/components/projects/project-form-dialog";
import { ProjectMembers } from "@/components/projects/project-members";
import { TaskBoard } from "@/components/tasks/task-board";
import { TaskFormDialog } from "@/components/tasks/task-form-dialog";
import { TaskTable } from "@/components/tasks/task-table";
import { ViewToggle, type TaskView } from "@/components/tasks/view-toggle";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { errorMessage } from "@/lib/api/client";
import type { Project, Task, TaskStatus } from "@/lib/api/types";
import { fmtDate } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes, usePaged } from "@/lib/queries";

function ProjectTasks({ project, canCreate }: { project: Project; canCreate: boolean }) {
  const { api, orgId } = useOrg();
  const [view, setView] = useState<TaskView>("board");
  const [dialog, setDialog] = useState<{ open: boolean; task?: Task; status?: TaskStatus }>({ open: false });
  const filters = { project_id: project.id };
  const q = usePaged(keys.tasks(orgId, filters), (p) => api.tasks({ ...p, ...filters }));

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <ViewToggle value={view} onChange={setView} />
        {canCreate && (
          <Button size="sm" onClick={() => setDialog({ open: true })}>
            <PlusIcon /> New task
          </Button>
        )}
      </div>
      {q.isPending ? (
        <ListSkeleton />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="tasks" />
      ) : view === "board" ? (
        <TaskBoard
          tasks={q.items}
          onOpen={(task) => setDialog({ open: true, task })}
          onCreate={canCreate ? (status) => setDialog({ open: true, status }) : undefined}
        />
      ) : q.items.length === 0 ? (
        <p className="py-10 text-center text-sm text-muted-foreground">No tasks you can see in this project yet.</p>
      ) : (
        <TaskTable tasks={q.items} onOpen={(task) => setDialog({ open: true, task })} />
      )}
      <LoadMore {...q} />
      <TaskFormDialog
        open={dialog.open}
        onOpenChange={(open) => setDialog((d) => ({ ...d, open }))}
        task={dialog.task}
        projectId={project.id}
        initialStatus={dialog.status}
      />
    </div>
  );
}

export function ProjectDetail() {
  const { projectId } = useParams<{ projectId: string }>();
  const { api, orgId, me, can, userName } = useOrg();
  const qc = useQueryClient();
  const router = useRouter();
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const q = useQuery({ queryKey: keys.project(orgId, projectId), queryFn: () => api.project(projectId) });
  const membersQ = useQuery({
    queryKey: keys.projectMembers(orgId, projectId),
    queryFn: () => api.projectMembers(projectId),
    enabled: q.isSuccess,
  });

  const setStatus = useMutation({
    mutationFn: (status: Project["status"]) => api.updateProject(projectId, { status }),
    onSuccess: (p) => {
      qc.setQueryData(keys.project(orgId, p.id), p);
      qc.invalidateQueries({ queryKey: prefixes.projects(orgId) });
      toast.success(p.status === "archived" ? "Project archived" : "Project restored");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });
  const remove = useMutation({
    mutationFn: () => api.deleteProject(projectId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: prefixes.projects(orgId) });
      toast.success("Project deleted");
      router.push(`/orgs/${orgId}/projects`);
    },
    // 409 "still has tasks or documents; archive it instead" is shown as-is.
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (q.isPending) return <ListSkeleton rows={6} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} what="this project" />;
  const project = q.data;

  // UI hints mirroring the RLS policies; the database still decides.
  const isOwner = project.owner_id === me.id;
  const myMembership = membersQ.data?.find((m) => m.user_id === me.id);
  const isManager = isOwner || myMembership?.project_role === "lead";
  const canEdit = can("project.update") && isManager;
  const canDelete = can("project.delete") && isOwner;
  const participates = isOwner || !!myMembership;
  const archived = project.status === "archived";

  return (
    <>
      <Link
        href={`/orgs/${orgId}/projects`}
        className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ChevronLeftIcon className="size-4" /> Projects
      </Link>
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="font-heading text-2xl font-semibold tracking-tight break-words">{project.name}</h1>
            {archived && <Badge variant="secondary">Archived</Badge>}
            {isOwner ? <Badge variant="outline">Owner</Badge> : myMembership && <Badge variant="outline" className="capitalize">{myMembership.project_role}</Badge>}
          </div>
          {project.description && <p className="max-w-2xl text-sm whitespace-pre-line text-muted-foreground">{project.description}</p>}
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <UserAvatar name={userName(project.owner_id)} seed={project.owner_id} size="sm" />
            Owned by {userName(project.owner_id)} · Created {fmtDate(project.created_at)}
          </div>
        </div>
        {(canEdit || canDelete) && (
          <DropdownMenu>
            <DropdownMenuTrigger render={<Button variant="outline" size="sm" />}>
              <MoreHorizontalIcon /> Manage
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-48">
              {canEdit && (
                <>
                  <DropdownMenuItem onClick={() => setEditing(true)}>
                    <PencilIcon /> Edit details
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => setStatus.mutate(archived ? "active" : "archived")}>
                    {archived ? <ArchiveRestoreIcon /> : <ArchiveIcon />} {archived ? "Restore" : "Archive"}
                  </DropdownMenuItem>
                </>
              )}
              {canDelete && (
                <>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem variant="destructive" onClick={() => setConfirmDelete(true)}>
                    <Trash2Icon /> Delete project
                  </DropdownMenuItem>
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {archived && (
        <Alert className="mb-4">
          <ArchiveIcon />
          <AlertDescription>This project is archived. Restore it to keep working on it.</AlertDescription>
        </Alert>
      )}

      <Tabs defaultValue="tasks">
        <TabsList className="mb-4">
          <TabsTrigger value="tasks">Tasks</TabsTrigger>
          <TabsTrigger value="documents">Documents</TabsTrigger>
          <TabsTrigger value="members">
            Members
            {membersQ.data && ` (${membersQ.data.length + (membersQ.data.some((m) => m.user_id === project.owner_id) ? 0 : 1)})`}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="tasks">
          <ProjectTasks project={project} canCreate={can("task.create") && participates && !archived} />
        </TabsContent>
        <TabsContent value="documents">
          <DocumentsPanel projectId={project.id} showAdd={participates && !archived} />
        </TabsContent>
        <TabsContent value="members">
          <ProjectMembers project={project} canManage={canEdit} />
        </TabsContent>
      </Tabs>

      <ProjectFormDialog open={editing} onOpenChange={setEditing} project={project} />
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title="Delete this project?"
        description="This can't be undone. A project that still has tasks or documents can't be deleted; archive it instead."
        confirmLabel="Delete project"
        destructive
        onConfirm={() => remove.mutateAsync()}
      />
    </>
  );
}
