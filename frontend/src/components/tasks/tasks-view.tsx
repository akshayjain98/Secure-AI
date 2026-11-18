"use client";

import { CheckSquareIcon, PlusIcon } from "lucide-react";
import { useState } from "react";

import { PageHeader } from "@/components/common/page-header";
import { SimpleSelect } from "@/components/common/simple-select";
import { EmptyState, ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { useProjectNames } from "@/components/projects/use-project-names";
import { TaskBoard } from "@/components/tasks/task-board";
import { TaskFormDialog } from "@/components/tasks/task-form-dialog";
import { TaskTable } from "@/components/tasks/task-table";
import { ViewToggle, type TaskView } from "@/components/tasks/view-toggle";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import type { Task, TaskStatus } from "@/lib/api/types";
import { TASK_STATUS, TASK_STATUSES } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, usePaged } from "@/lib/queries";

const ALL = "all";

export function TasksView() {
  const { api, orgId, can } = useOrg();
  const { names, projects } = useProjectNames();
  const [view, setView] = useState<TaskView>("list");
  const [projectId, setProjectId] = useState<string>(ALL);
  const [status, setStatus] = useState<TaskStatus | typeof ALL>(ALL);
  const [mine, setMine] = useState(false);
  const [dialog, setDialog] = useState<{ open: boolean; task?: Task; status?: TaskStatus }>({ open: false });

  const filters = {
    project_id: projectId === ALL ? undefined : projectId,
    status: status === ALL || view === "board" ? undefined : status,
    assigned_to_me: mine || undefined,
  };
  const q = usePaged(keys.tasks(orgId, filters), (p) => api.tasks({ ...p, ...filters }));

  return (
    <>
      <PageHeader
        title="Tasks"
        description="Every task you're allowed to see across the organization. Private tasks are visible only to their owner and assignee."
        actions={
          can("task.create") && (
            <Button onClick={() => setDialog({ open: true })}>
              <PlusIcon /> New task
            </Button>
          )
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <ViewToggle value={view} onChange={setView} />
        <SimpleSelect
          aria-label="Filter by project"
          className="w-48"
          value={projectId}
          onChange={setProjectId}
          options={[{ value: ALL, label: "All projects" }, ...projects.map((p) => ({ value: p.id, label: p.name }))]}
        />
        {view === "list" && (
          <SimpleSelect<TaskStatus | typeof ALL>
            aria-label="Filter by status"
            className="w-40"
            value={status}
            onChange={setStatus}
            options={[{ value: ALL, label: "Any status" }, ...TASK_STATUSES.map((s) => ({ value: s, label: TASK_STATUS[s].label }))]}
          />
        )}
        <div className="flex items-center gap-2">
          <Switch id="mine" checked={mine} onCheckedChange={setMine} />
          <Label htmlFor="mine">Assigned to me</Label>
        </div>
      </div>

      {q.isPending ? (
        <ListSkeleton />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="tasks" />
      ) : q.items.length === 0 && view === "list" ? (
        <EmptyState
          icon={<CheckSquareIcon />}
          title="No tasks match"
          description={mine || projectId !== ALL || status !== ALL ? "Try clearing the filters." : "Create a task in one of your projects to get started."}
        />
      ) : view === "board" ? (
        <TaskBoard tasks={q.items} onOpen={(task) => setDialog({ open: true, task })} />
      ) : (
        <TaskTable tasks={q.items} projectNames={names} onOpen={(task) => setDialog({ open: true, task })} />
      )}
      <LoadMore {...q} />

      <TaskFormDialog
        open={dialog.open}
        onOpenChange={(open) => setDialog((d) => ({ ...d, open }))}
        task={dialog.task}
        initialStatus={dialog.status}
        projectId={dialog.task ? undefined : projectId === ALL ? undefined : projectId}
      />
    </>
  );
}
