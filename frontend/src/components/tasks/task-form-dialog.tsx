"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { SimpleSelect } from "@/components/common/simple-select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import type { TaskInput } from "@/lib/api/endpoints";
import type { Priority, Task, TaskStatus, TaskVisibility } from "@/lib/api/types";
import { applyServerError } from "@/lib/forms";
import { PRIORITIES, PRIORITY, TASK_STATUS, TASK_STATUSES } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes } from "@/lib/queries";

const NONE = "__none__";

const schema = z.object({
  project_id: z.string().min(1, "Choose a project"),
  title: z.string().trim().min(1, "Give the task a title").max(300),
  description: z.string().max(10000),
  status: z.enum(["todo", "in_progress", "blocked", "done"]),
  priority: z.enum(["low", "medium", "high", "urgent"]),
  visibility: z.enum(["private", "project"]),
  due_date: z.string(),
  assignee_id: z.string(),
});
type Values = z.infer<typeof schema>;

function toValues(task: Task | undefined, projectId: string | undefined, status?: TaskStatus): Values {
  return {
    project_id: task?.project_id ?? projectId ?? "",
    title: task?.title ?? "",
    description: task?.description ?? "",
    status: task?.status ?? status ?? "todo",
    priority: task?.priority ?? "medium",
    visibility: task?.visibility ?? "private",
    due_date: task?.due_date ?? "",
    assignee_id: task?.assignee_id ?? NONE,
  };
}

function toInput(v: Values): Required<TaskInput> {
  return {
    title: v.title.trim(),
    description: v.description.trim() || null,
    status: v.status,
    priority: v.priority,
    visibility: v.visibility,
    due_date: v.due_date || null,
    assignee_id: v.assignee_id === NONE ? null : v.assignee_id,
  };
}

/**
 * Create (task undefined) or edit a task. For edits only changed fields are
 * sent, so a PATCH never touches a column the caller didn't mean to change
 * (and can't trip a rule like "only the owner may change visibility").
 */
export function TaskFormDialog({
  open,
  onOpenChange,
  task,
  projectId,
  initialStatus,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  task?: Task;
  projectId?: string;
  initialStatus?: TaskStatus;
}) {
  const { api, orgId, me, userName } = useOrg();
  const qc = useQueryClient();
  const editing = !!task;
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: toValues(task, projectId, initialStatus) });
  const { errors, isSubmitting } = form.formState;

  useEffect(() => {
    if (open) form.reset(toValues(task, projectId, initialStatus));
  }, [open, task, projectId, initialStatus, form]);

  const selectedProject = useWatch({ control: form.control, name: "project_id" });
  const projectsQ = useQuery({
    queryKey: keys.projects(orgId, { status: "active", picker: true }),
    queryFn: () => api.projects({ status: "active", limit: 100 }),
    enabled: open && !projectId && !editing,
  });
  const membersQ = useQuery({
    queryKey: keys.projectMembers(orgId, selectedProject),
    queryFn: () => api.projectMembers(selectedProject),
    enabled: open && !!selectedProject,
  });

  const assigneeOptions = [
    { value: NONE, label: "Unassigned" },
    ...(membersQ.data ?? []).map((m) => ({
      value: m.user_id,
      label: m.user_id === me.id ? `${m.display_name ?? "You"} (you)` : (m.display_name ?? userName(m.user_id)),
    })),
  ];
  const currentAssignee = useWatch({ control: form.control, name: "assignee_id" });
  if (currentAssignee !== NONE && !assigneeOptions.some((o) => o.value === currentAssignee)) {
    assigneeOptions.push({ value: currentAssignee, label: userName(currentAssignee) });
  }

  const save = useMutation({
    mutationFn: async (v: Values) => {
      const input = toInput(v);
      if (!task) return api.createTask(v.project_id, input);
      const before = toInput(toValues(task, undefined));
      const diff = Object.fromEntries(
        Object.entries(input).filter(([k, val]) => before[k as keyof TaskInput] !== val),
      ) as Partial<TaskInput>;
      if (Object.keys(diff).length === 0) return task;
      return api.updateTask(task.id, diff);
    },
    onSuccess: (saved) => {
      qc.setQueryData(keys.task(orgId, saved.id), saved);
      qc.invalidateQueries({ queryKey: prefixes.tasks(orgId) });
      toast.success(editing ? "Task updated" : "Task created");
      onOpenChange(false);
    },
    onError: (err) => applyServerError(err, form.setError, ["title", "description", "due_date"]),
  });

  const isOwner = !task || task.owner_id === me.id;

  return (
    <Dialog open={open} onOpenChange={(o) => !isSubmitting && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{editing ? "Edit task" : "New task"}</DialogTitle>
          <DialogDescription>
            {editing ? "Changes are checked against your role and the task's visibility." : "Tasks are private by default: only you and the assignee can see them."}
          </DialogDescription>
        </DialogHeader>
        <form id="task-form" onSubmit={form.handleSubmit((v) => save.mutateAsync(v).catch(() => {}))} noValidate>
          <FieldGroup className="gap-4">
            {errors.root && (
              <Alert variant="destructive">
                <AlertDescription>{errors.root.message}</AlertDescription>
              </Alert>
            )}
            {!projectId && !editing && (
              <Field data-invalid={!!errors.project_id}>
                <FieldLabel htmlFor="task-project">Project</FieldLabel>
                <Controller
                  control={form.control}
                  name="project_id"
                  render={({ field }) => (
                    <SimpleSelect
                      id="task-project"
                      value={field.value || null}
                      onChange={(v) => {
                        field.onChange(v);
                        form.setValue("assignee_id", NONE);
                      }}
                      placeholder={projectsQ.isPending ? "Loading projects…" : "Choose a project"}
                      options={(projectsQ.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))}
                    />
                  )}
                />
                <FieldError errors={[errors.project_id]} />
              </Field>
            )}
            <Field data-invalid={!!errors.title}>
              <FieldLabel htmlFor="task-title">Title</FieldLabel>
              <Input id="task-title" autoFocus aria-invalid={!!errors.title} {...form.register("title")} />
              <FieldError errors={[errors.title]} />
            </Field>
            <Field data-invalid={!!errors.description}>
              <FieldLabel htmlFor="task-desc">Description</FieldLabel>
              <Textarea id="task-desc" rows={4} placeholder="Add more detail…" {...form.register("description")} />
              <FieldError errors={[errors.description]} />
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="task-status">Status</FieldLabel>
                <Controller
                  control={form.control}
                  name="status"
                  render={({ field }) => (
                    <SimpleSelect<TaskStatus>
                      id="task-status"
                      value={field.value}
                      onChange={field.onChange}
                      options={TASK_STATUSES.map((s) => ({ value: s, label: TASK_STATUS[s].label }))}
                    />
                  )}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="task-priority">Priority</FieldLabel>
                <Controller
                  control={form.control}
                  name="priority"
                  render={({ field }) => (
                    <SimpleSelect<Priority>
                      id="task-priority"
                      value={field.value}
                      onChange={field.onChange}
                      options={PRIORITIES.map((p) => ({ value: p, label: PRIORITY[p].label }))}
                    />
                  )}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="task-assignee">Assignee</FieldLabel>
                <Controller
                  control={form.control}
                  name="assignee_id"
                  render={({ field }) => (
                    <SimpleSelect
                      id="task-assignee"
                      value={field.value}
                      onChange={field.onChange}
                      disabled={!selectedProject}
                      options={assigneeOptions}
                    />
                  )}
                />
              </Field>
              <Field data-invalid={!!errors.due_date}>
                <FieldLabel htmlFor="task-due">Due date</FieldLabel>
                <Input id="task-due" type="date" {...form.register("due_date")} />
                <FieldError errors={[errors.due_date]} />
              </Field>
            </div>
            <Field>
              <FieldLabel htmlFor="task-visibility">Visibility</FieldLabel>
              <Controller
                control={form.control}
                name="visibility"
                render={({ field }) => (
                  <SimpleSelect<TaskVisibility>
                    id="task-visibility"
                    value={field.value}
                    onChange={field.onChange}
                    disabled={!isOwner}
                    options={[
                      { value: "private", label: "Private — owner and assignee only" },
                      { value: "project", label: "Project — everyone on the project" },
                    ]}
                  />
                )}
              />
              {!isOwner && <FieldDescription>Only the task owner can change visibility.</FieldDescription>}
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" form="task-form" disabled={isSubmitting}>
            {isSubmitting && <Spinner />} {editing ? "Save changes" : "Create task"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
