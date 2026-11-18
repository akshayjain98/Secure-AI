"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  KeyRoundIcon,
  MailIcon,
  MoreHorizontalIcon,
  PauseCircleIcon,
  PlayCircleIcon,
  UserMinusIcon,
  UserPlusIcon,
  UsersIcon,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { MemberStatusBadge, RoleBadge } from "@/components/common/badges";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { PageHeader } from "@/components/common/page-header";
import { EmptyState, ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { UserAvatar } from "@/components/common/user-avatar";
import { InviteDialog, useAssignableRoles } from "@/components/members/invite-dialog";
import { OverridesSheet } from "@/components/members/overrides-sheet";
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { errorMessage } from "@/lib/api/client";
import type { MemberStatus, OrgMember } from "@/lib/api/types";
import { fmtDate, roleName, roleRank } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes, usePaged } from "@/lib/queries";

type Tab = MemberStatus | "all";

function MemberActions({
  m,
  onPermissions,
  onRemove,
  onReinvite,
}: {
  m: OrgMember;
  onPermissions: () => void;
  onRemove: () => void;
  onReinvite: () => void;
}) {
  const { api, orgId, me, can, rank } = useOrg();
  const qc = useQueryClient();
  const roles = useAssignableRoles();
  const isMe = m.user_id === me.id;
  // Mirrors memberships_update: never my own row, target not above my rank.
  const manageable = !isMe && roleRank(m.role) <= rank;
  const canUpdate = can("user.update") && manageable;
  const canRemove = can("user.delete") && can("user.update") && manageable && m.status !== "removed";

  const update = useMutation({
    mutationFn: (body: { role?: string; status?: "active" | "suspended" }) => api.updateMember(m.user_id, body),
    onSuccess: (_d, body) => {
      qc.invalidateQueries({ queryKey: prefixes.members(orgId) });
      qc.invalidateQueries({ queryKey: keys.directory(orgId) });
      toast.success(
        body.role ? `Role changed to ${roleName(body.role)}` : body.status === "suspended" ? "Member suspended and signed out" : "Member reactivated",
      );
    },
    // 409 for the last active administrator comes back with a clear message.
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label="Member actions" />}>
        <MoreHorizontalIcon />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuItem onClick={onPermissions}>
          <KeyRoundIcon /> {can("permission.manage") && !isMe ? "Manage permissions" : "View permissions"}
        </DropdownMenuItem>
        {canUpdate && (m.status === "active" || m.status === "suspended" || m.status === "invited") && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuGroup>
              <DropdownMenuLabel>Role</DropdownMenuLabel>
              <DropdownMenuRadioGroup value={m.role} onValueChange={(r) => r !== m.role && update.mutate({ role: r as string })}>
                {roles.map((r) => (
                  <DropdownMenuRadioItem key={r.value} value={r.value}>
                    {r.label}
                  </DropdownMenuRadioItem>
                ))}
              </DropdownMenuRadioGroup>
            </DropdownMenuGroup>
          </>
        )}
        {canUpdate && m.status === "active" && (
          <DropdownMenuItem onClick={() => update.mutate({ status: "suspended" })}>
            <PauseCircleIcon /> Suspend
          </DropdownMenuItem>
        )}
        {canUpdate && m.status === "suspended" && (
          <DropdownMenuItem onClick={() => update.mutate({ status: "active" })}>
            <PlayCircleIcon /> Reactivate
          </DropdownMenuItem>
        )}
        {m.status === "removed" && can("user.create") && m.email && (
          <DropdownMenuItem onClick={onReinvite}>
            <MailIcon /> Invite again
          </DropdownMenuItem>
        )}
        {canRemove && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={onRemove}>
              <UserMinusIcon /> Remove from organization
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function MembersPage() {
  const { api, orgId, can, me } = useOrg();
  const qc = useQueryClient();
  const [tab, setTab] = useState<Tab>("active");
  const [inviting, setInviting] = useState<{ open: boolean; email?: string }>({ open: false });
  const [permsFor, setPermsFor] = useState<OrgMember | null>(null);
  const [removing, setRemoving] = useState<OrgMember | null>(null);
  const status = tab === "all" ? undefined : tab;
  const q = usePaged(keys.members(orgId, { status }), (p) => api.members({ ...p, status }));

  const remove = useMutation({
    mutationFn: (m: OrgMember) => api.removeMember(m.user_id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: prefixes.members(orgId) });
      qc.invalidateQueries({ queryKey: keys.directory(orgId) });
      toast.success("Member removed and signed out");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <>
      <PageHeader
        title="Members"
        description="People in this organization, their roles and access."
        actions={
          can("user.create") && (
            <Button onClick={() => setInviting({ open: true })}>
              <UserPlusIcon /> Invite member
            </Button>
          )
        }
      />
      <Tabs value={tab} onValueChange={(v) => setTab(v as Tab)} className="mb-4">
        <TabsList>
          <TabsTrigger value="active">Active</TabsTrigger>
          <TabsTrigger value="invited">Invited</TabsTrigger>
          <TabsTrigger value="suspended">Suspended</TabsTrigger>
          <TabsTrigger value="removed">Removed</TabsTrigger>
          <TabsTrigger value="all">All</TabsTrigger>
        </TabsList>
      </Tabs>

      {q.isPending ? (
        <ListSkeleton />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="members" />
      ) : q.items.length === 0 ? (
        <EmptyState icon={<UsersIcon />} title={`No ${tab === "all" ? "" : tab + " "}members`} />
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/50 hover:bg-muted/50">
                <TableHead className="w-1/2">Member</TableHead>
                <TableHead>Role</TableHead>
                <TableHead className="hidden sm:table-cell">Status</TableHead>
                <TableHead className="hidden md:table-cell">Since</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {q.items.map((m) => {
                const name = m.display_name ?? (m.status === "invited" ? "Pending invitation" : (m.email ?? "Unknown"));
                return (
                  <TableRow key={m.user_id}>
                    <TableCell className="max-w-0">
                      <div className="flex items-center gap-3">
                        <UserAvatar name={m.display_name ?? m.email} seed={m.user_id} />
                        <div className="min-w-0">
                          <p className="truncate font-medium">
                            {name}
                            {m.user_id === me.id && <span className="text-muted-foreground"> (you)</span>}
                          </p>
                          <p className="truncate text-xs text-muted-foreground">{m.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <RoleBadge role={m.role} />
                    </TableCell>
                    <TableCell className="hidden sm:table-cell">
                      <MemberStatusBadge status={m.status} />
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">{fmtDate(m.created_at)}</TableCell>
                    <TableCell>
                      <MemberActions
                        m={m}
                        onPermissions={() => setPermsFor(m)}
                        onRemove={() => setRemoving(m)}
                        onReinvite={() => setInviting({ open: true, email: m.email ?? undefined })}
                      />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      <LoadMore {...q} />

      <InviteDialog open={inviting.open} initialEmail={inviting.email} onOpenChange={(open) => setInviting((s) => ({ ...s, open }))} />
      <OverridesSheet member={permsFor} onOpenChange={(o) => !o && setPermsFor(null)} />
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove member?"
        description={`${removing?.display_name ?? removing?.email} loses access immediately and is signed out everywhere. Their tasks and documents stay in the organization.`}
        confirmLabel="Remove member"
        destructive
        onConfirm={() => removing && remove.mutateAsync(removing)}
      />
    </>
  );
}
