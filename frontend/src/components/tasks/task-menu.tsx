"use client";

import { MoreHorizontalIcon, PencilIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { useTaskActions } from "@/components/tasks/use-task-actions";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { Task, TaskStatus } from "@/lib/api/types";
import { TASK_STATUS, TASK_STATUSES } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { cn } from "@/lib/utils";

export function TaskMenu({ task, onEdit }: { task: Task; onEdit: () => void }) {
  const { can } = useOrg();
  const { setStatus, remove } = useTaskActions();
  const [confirm, setConfirm] = useState(false);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger
          render={<Button variant="ghost" size="icon-sm" aria-label={`Actions for ${task.title}`} onClick={(e) => e.stopPropagation()} />}
        >
          <MoreHorizontalIcon />
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48" onClick={(e) => e.stopPropagation()}>
          <DropdownMenuItem onClick={onEdit}>
            <PencilIcon /> Open / edit
          </DropdownMenuItem>
          {can("task.update") && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuGroup>
                <DropdownMenuLabel>Move to</DropdownMenuLabel>
                <DropdownMenuRadioGroup
                  value={task.status}
                  onValueChange={(s) => s !== task.status && setStatus.mutate({ task, status: s as TaskStatus })}
                >
                  {TASK_STATUSES.map((s) => (
                    <DropdownMenuRadioItem key={s} value={s}>
                      <span className={cn("size-2 rounded-full", TASK_STATUS[s].dot)} /> {TASK_STATUS[s].label}
                    </DropdownMenuRadioItem>
                  ))}
                </DropdownMenuRadioGroup>
              </DropdownMenuGroup>
            </>
          )}
          {can("task.delete") && (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem variant="destructive" onClick={() => setConfirm(true)}>
                <Trash2Icon /> Delete
              </DropdownMenuItem>
            </>
          )}
        </DropdownMenuContent>
      </DropdownMenu>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title="Delete this task?"
        description={`"${task.title}" will be permanently deleted. This can't be undone.`}
        confirmLabel="Delete task"
        destructive
        onConfirm={() => remove.mutateAsync(task)}
      />
    </>
  );
}
