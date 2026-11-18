import { EyeOffIcon, GlobeIcon, UsersIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { AuditOutcome, DocVisibility, MemberStatus, Priority, RoleKey, TaskStatus } from "@/lib/api/types";
import { PRIORITY, roleName, TASK_STATUS } from "@/lib/format";
import { cn } from "@/lib/utils";

export function TaskStatusBadge({ status }: { status: TaskStatus }) {
  return (
    <Badge variant="outline" className="gap-1.5">
      <span className={cn("size-1.5 rounded-full", TASK_STATUS[status].dot)} />
      {TASK_STATUS[status].label}
    </Badge>
  );
}

export function PriorityLabel({ priority }: { priority: Priority }) {
  const bars = { low: 1, medium: 2, high: 3, urgent: 4 }[priority];
  return (
    <span className={cn("inline-flex items-center gap-1.5 text-xs font-medium", PRIORITY[priority].className)}>
      <span className="flex items-end gap-px" aria-hidden>
        {[1, 2, 3, 4].map((i) => (
          <span key={i} className={cn("w-0.5 rounded-full bg-current", i <= bars ? "opacity-100" : "opacity-20")} style={{ height: 3 + i * 2 }} />
        ))}
      </span>
      {PRIORITY[priority].label}
    </span>
  );
}

const VIS = {
  private: { label: "Private", icon: EyeOffIcon },
  project: { label: "Project", icon: UsersIcon },
  organization: { label: "Organization", icon: GlobeIcon },
} as const;

export function VisibilityBadge({ visibility }: { visibility: DocVisibility }) {
  const v = VIS[visibility];
  return (
    <Badge variant="secondary" className="gap-1">
      <v.icon /> {v.label}
    </Badge>
  );
}

export function RoleBadge({ role }: { role: RoleKey }) {
  return (
    <Badge variant={role === "org_admin" || role === "super_admin" ? "default" : "secondary"}>{roleName(role)}</Badge>
  );
}

const MEMBER_STATUS: Record<MemberStatus, string> = {
  active: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  invited: "bg-sky-500/10 text-sky-700 dark:text-sky-400",
  suspended: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  removed: "bg-muted text-muted-foreground",
};

export function MemberStatusBadge({ status }: { status: MemberStatus }) {
  return <Badge className={cn("capitalize", MEMBER_STATUS[status])}>{status}</Badge>;
}

const OUTCOME: Record<AuditOutcome, string> = {
  success: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  denied: "bg-amber-500/10 text-amber-700 dark:text-amber-400",
  failure: "bg-red-500/10 text-red-700 dark:text-red-400",
  error: "bg-red-500/10 text-red-700 dark:text-red-400",
};

export function OutcomeBadge({ outcome }: { outcome: AuditOutcome }) {
  return <Badge className={cn("capitalize", OUTCOME[outcome])}>{outcome}</Badge>;
}
