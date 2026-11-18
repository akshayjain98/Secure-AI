"use client";

import { useMutation, useQueryClient, type InfiniteData } from "@tanstack/react-query";
import { toast } from "sonner";

import { errorMessage } from "@/lib/api/client";
import type { Page, Task, TaskStatus } from "@/lib/api/types";
import { TASK_STATUS } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes } from "@/lib/queries";

/** Quick status change (optimistic) and delete, shared by board and list. */
export function useTaskActions() {
  const { api, orgId } = useOrg();
  const qc = useQueryClient();

  const patchCached = (id: string, patch: Partial<Task> | null) => {
    qc.setQueriesData<InfiniteData<Page<Task>>>({ queryKey: prefixes.tasks(orgId) }, (data) =>
      data && {
        ...data,
        pages: data.pages.map((p) => ({
          ...p,
          items: patch === null ? p.items.filter((t) => t.id !== id) : p.items.map((t) => (t.id === id ? { ...t, ...patch } : t)),
        })),
      },
    );
  };

  const setStatus = useMutation({
    mutationFn: ({ task, status }: { task: Task; status: TaskStatus }) => api.updateTask(task.id, { status }),
    onMutate: async ({ task, status }) => {
      await qc.cancelQueries({ queryKey: prefixes.tasks(orgId) });
      const snapshot = qc.getQueriesData({ queryKey: prefixes.tasks(orgId) });
      patchCached(task.id, { status });
      return { snapshot };
    },
    onError: (err, _v, ctx) => {
      ctx?.snapshot.forEach(([key, data]) => qc.setQueryData(key, data));
      toast.error(errorMessage(err));
    },
    onSuccess: (saved) => {
      qc.setQueryData(keys.task(orgId, saved.id), saved);
      toast.success(`Moved to ${TASK_STATUS[saved.status].label}`);
    },
    onSettled: () => qc.invalidateQueries({ queryKey: prefixes.tasks(orgId) }),
  });

  const remove = useMutation({
    mutationFn: (task: Task) => api.deleteTask(task.id),
    onSuccess: (_d, task) => {
      patchCached(task.id, null);
      qc.invalidateQueries({ queryKey: prefixes.tasks(orgId) });
      toast.success("Task deleted");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return { setStatus, remove };
}
