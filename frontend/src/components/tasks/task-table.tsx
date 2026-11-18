"use client";

import Link from "next/link";

import { PriorityLabel, TaskStatusBadge } from "@/components/common/badges";
import { TaskMenu } from "@/components/tasks/task-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Task } from "@/lib/api/types";
import { dueLabel } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { cn } from "@/lib/utils";

export function TaskTable({
  tasks,
  onOpen,
  projectNames,
}: {
  tasks: Task[];
  onOpen: (t: Task) => void;
  projectNames?: ReadonlyMap<string, string>;
}) {
  const { userName, orgId } = useOrg();
  return (
    <div className="overflow-hidden rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/50 hover:bg-muted/50">
            <TableHead className="w-[40%]">Task</TableHead>
            {projectNames && <TableHead className="hidden md:table-cell">Project</TableHead>}
            <TableHead>Status</TableHead>
            <TableHead className="hidden sm:table-cell">Priority</TableHead>
            <TableHead className="hidden lg:table-cell">Assignee</TableHead>
            <TableHead className="hidden sm:table-cell">Due</TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {tasks.map((t) => {
            const due = dueLabel(t.due_date);
            return (
              <TableRow key={t.id} className="cursor-pointer" onClick={() => onOpen(t)}>
                <TableCell className="max-w-0 font-medium">
                  <span className="block truncate">{t.title}</span>
                </TableCell>
                {projectNames && (
                  <TableCell className="hidden max-w-40 truncate text-muted-foreground md:table-cell">
                    <Link
                      href={`/orgs/${orgId}/projects/${t.project_id}`}
                      className="hover:text-foreground hover:underline"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {projectNames.get(t.project_id) ?? "Project"}
                    </Link>
                  </TableCell>
                )}
                <TableCell>
                  <TaskStatusBadge status={t.status} />
                </TableCell>
                <TableCell className="hidden sm:table-cell">
                  <PriorityLabel priority={t.priority} />
                </TableCell>
                <TableCell className="hidden max-w-40 truncate text-muted-foreground lg:table-cell">{userName(t.assignee_id)}</TableCell>
                <TableCell
                  className={cn(
                    "hidden text-muted-foreground sm:table-cell",
                    due?.overdue && t.status !== "done" && "text-red-600 dark:text-red-400",
                  )}
                >
                  {due?.text ?? "—"}
                </TableCell>
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <TaskMenu task={t} onEdit={() => onOpen(t)} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
