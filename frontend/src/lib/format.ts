import { format, formatDistanceToNowStrict, isPast, isToday, parseISO } from "date-fns";

import type { Priority, ProjectStatus, RoleKey, TaskStatus } from "@/lib/api/types";
import { ROLES } from "@/lib/api/types";

export const shortId = (id: string) => id.slice(0, 8);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (v: string | null | undefined): v is string => !!v && UUID_RE.test(v);

export function initials(name: string | null | undefined) {
  if (!name) return "?";
  // Letters/digits only: "Akshay (you)" -> "A", "jane.doe@x.io" -> "JD".
  const parts = name
    .replace(/\(.*?\)/g, " ")
    .split(/[\s@._-]+/)
    .map((p) => p.replace(/[^\p{L}\p{N}]/gu, ""))
    .filter(Boolean);
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() || "?";
}

export const fmtDate = (iso: string) => format(parseISO(iso), "MMM d, yyyy");
export const fmtDateTime = (iso: string) => format(parseISO(iso), "MMM d, yyyy HH:mm:ss");
export const fmtRelative = (iso: string) => `${formatDistanceToNowStrict(parseISO(iso))} ago`;

export function dueLabel(due: string | null) {
  if (!due) return null;
  const d = parseISO(due);
  return { text: format(d, "MMM d"), overdue: isPast(d) && !isToday(d), today: isToday(d) };
}

export function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

export const roleName = (r: RoleKey | string) => ROLES[r as RoleKey]?.name ?? r;
/** Unknown roles rank as "above everyone" so the UI never offers actions on them. */
export const roleRank = (r: RoleKey | string) => ROLES[r as RoleKey]?.rank ?? 1000;

export const TASK_STATUS: Record<TaskStatus, { label: string; dot: string }> = {
  todo: { label: "To do", dot: "bg-slate-400" },
  in_progress: { label: "In progress", dot: "bg-blue-500" },
  blocked: { label: "Blocked", dot: "bg-red-500" },
  done: { label: "Done", dot: "bg-emerald-500" },
};
export const TASK_STATUSES = Object.keys(TASK_STATUS) as TaskStatus[];

export const PRIORITY: Record<Priority, { label: string; className: string }> = {
  low: { label: "Low", className: "text-muted-foreground" },
  medium: { label: "Medium", className: "text-foreground" },
  high: { label: "High", className: "text-amber-600 dark:text-amber-400" },
  urgent: { label: "Urgent", className: "text-red-600 dark:text-red-400" },
};
export const PRIORITIES = Object.keys(PRIORITY) as Priority[];

export const PROJECT_STATUS: Record<ProjectStatus, string> = { active: "Active", archived: "Archived" };
