"use client";

import { CalendarIcon, EyeOffIcon, PlusIcon } from "lucide-react";
import { useState } from "react";

import { PriorityLabel } from "@/components/common/badges";
import { UserAvatar } from "@/components/common/user-avatar";
import { TaskMenu } from "@/components/tasks/task-menu";
import { useTaskActions } from "@/components/tasks/use-task-actions";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import type { Task, TaskStatus } from "@/lib/api/types";
import { dueLabel, TASK_STATUS, TASK_STATUSES } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { cn } from "@/lib/utils";

const DRAG_TYPE = "application/x-secureai-task";

function TaskCard({ task, onOpen }: { task: Task; onOpen: (t: Task) => void }) {
  const { userName, can } = useOrg();
  const due = dueLabel(task.due_date);
  return (
    <div
      draggable={can("task.update")}
      onDragStart={(e) => {
        e.dataTransfer.setData(DRAG_TYPE, task.id);
        e.dataTransfer.effectAllowed = "move";
      }}
      className="group relative rounded-lg border bg-card p-3 text-left shadow-xs transition-shadow hover:shadow-sm has-focus-visible:ring-3 has-focus-visible:ring-ring/50"
    >
      <div className="flex items-start gap-2">
        {/* The title is the card's one primary control; its ::after stretches over the
            whole card so a click anywhere opens it, without nesting interactive elements. */}
        <button
          type="button"
          onClick={() => onOpen(task)}
          className="min-w-0 flex-1 cursor-pointer text-left text-sm leading-snug font-medium break-words outline-none after:absolute after:inset-0 after:content-['']"
        >
          {task.title}
        </button>
        <div className="relative z-10 -mt-1 -mr-1 opacity-60 group-hover:opacity-100 focus-within:opacity-100">
          <TaskMenu task={task} onEdit={() => onOpen(task)} />
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground [&_[data-slot=tooltip-trigger]]:relative [&_[data-slot=tooltip-trigger]]:z-10">
        <PriorityLabel priority={task.priority} />
        {due && (
          <span className={cn("inline-flex items-center gap-1", due.overdue && task.status !== "done" && "text-red-600 dark:text-red-400")}>
            <CalendarIcon className="size-3" /> {due.text}
          </span>
        )}
        {task.visibility === "private" && (
          <Tooltip>
            <TooltipTrigger render={<span className="inline-flex" />}>
              <EyeOffIcon className="size-3" aria-label="Private" />
            </TooltipTrigger>
            <TooltipContent>Private: owner and assignee only</TooltipContent>
          </Tooltip>
        )}
        <span className="flex-1" />
        {task.assignee_id && (
          <Tooltip>
            <TooltipTrigger render={<span className="inline-flex" />}>
              <UserAvatar name={userName(task.assignee_id)} seed={task.assignee_id} size="sm" />
            </TooltipTrigger>
            <TooltipContent>Assigned to {userName(task.assignee_id)}</TooltipContent>
          </Tooltip>
        )}
      </div>
    </div>
  );
}

/** Kanban by status. Drag a card between columns, or use its menu (keyboard accessible). */
export function TaskBoard({
  tasks,
  onOpen,
  onCreate,
}: {
  tasks: Task[];
  onOpen: (t: Task) => void;
  onCreate?: (status: TaskStatus) => void;
}) {
  const { setStatus } = useTaskActions();
  const [over, setOver] = useState<TaskStatus | null>(null);

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {TASK_STATUSES.map((status) => {
        const column = tasks.filter((t) => t.status === status);
        return (
          <section
            key={status}
            aria-label={TASK_STATUS[status].label}
            onDragOver={(e) => {
              if (e.dataTransfer.types.includes(DRAG_TYPE)) {
                e.preventDefault();
                setOver(status);
              }
            }}
            onDragLeave={() => setOver((s) => (s === status ? null : s))}
            onDrop={(e) => {
              e.preventDefault();
              setOver(null);
              const task = tasks.find((t) => t.id === e.dataTransfer.getData(DRAG_TYPE));
              if (task && task.status !== status) setStatus.mutate({ task, status });
            }}
            className={cn(
              "flex min-h-40 flex-col gap-2 rounded-xl bg-muted/50 p-2 transition-colors",
              over === status && "bg-primary/5 ring-2 ring-primary/30",
            )}
          >
            <header className="flex items-center gap-2 px-1.5 pt-1 pb-0.5">
              <span className={cn("size-2 rounded-full", TASK_STATUS[status].dot)} />
              <h3 className="text-sm font-medium">{TASK_STATUS[status].label}</h3>
              <span className="text-xs text-muted-foreground tabular-nums">{column.length}</span>
              <span className="flex-1" />
              {onCreate && (
                <Button variant="ghost" size="icon-xs" aria-label={`Add task to ${TASK_STATUS[status].label}`} onClick={() => onCreate(status)}>
                  <PlusIcon />
                </Button>
              )}
            </header>
            {column.map((t) => (
              <TaskCard key={t.id} task={t} onOpen={onOpen} />
            ))}
            {column.length === 0 && <p className="px-2 py-6 text-center text-xs text-muted-foreground">No tasks</p>}
          </section>
        );
      })}
    </div>
  );
}
