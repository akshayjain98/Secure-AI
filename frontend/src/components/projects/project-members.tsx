"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LogOutIcon, MoreHorizontalIcon, UserMinusIcon, UserPlusIcon, UsersIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { SimpleSelect } from "@/components/common/simple-select";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/common/states";
import { UserAvatar } from "@/components/common/user-avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
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
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import { errorMessage } from "@/lib/api/client";
import type { Project, ProjectMember, ProjectRole } from "@/lib/api/types";
import { fmtDate } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes } from "@/lib/queries";

function AddMemberDialog({
  open,
  onOpenChange,
  project,
  existing,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  project: Project;
  existing: Set<string>;
}) {
  const { api, orgId, directory, can } = useOrg();
  const qc = useQueryClient();
  const [userId, setUserId] = useState<string | null>(null);
  const [role, setRole] = useState<ProjectRole>("member");
  const candidates = [...directory.values()]
    .filter((e) => e.member?.status === "active" && !existing.has(e.member.user_id))
    .sort((a, b) => a.name.localeCompare(b.name));

  const add = useMutation({
    mutationFn: () => api.addProjectMember(project.id, { user_id: userId!, project_role: role }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.projectMembers(orgId, project.id) });
      toast.success("Member added");
      setUserId(null);
      onOpenChange(false);
    },
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add project member</DialogTitle>
          <DialogDescription>Members can see project-visible tasks and documents, and can be assigned tasks.</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <Field>
            <FieldLabel htmlFor="pm-user">Person</FieldLabel>
            <SimpleSelect
              id="pm-user"
              value={userId}
              onChange={setUserId}
              placeholder={candidates.length ? "Choose an organization member" : "No one left to add"}
              disabled={!candidates.length}
              options={candidates.map((c) => ({
                value: c.member!.user_id,
                label: (
                  <span className="flex flex-col">
                    <span>{c.name}</span>
                    <span className="text-xs text-muted-foreground">{c.email}</span>
                  </span>
                ),
              }))}
            />
            {!can("user.read") && (
              <FieldDescription>You need the member directory permission (user.read) to pick people.</FieldDescription>
            )}
          </Field>
          <Field>
            <FieldLabel htmlFor="pm-role">Project role</FieldLabel>
            <SimpleSelect<ProjectRole>
              id="pm-role"
              value={role}
              onChange={setRole}
              options={[
                { value: "member", label: "Member" },
                { value: "lead", label: "Lead — can manage the project" },
              ]}
            />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={!userId || add.isPending} onClick={() => add.mutate()}>
            {add.isPending && <Spinner />} Add member
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function ProjectMembers({ project, canManage }: { project: Project; canManage: boolean }) {
  const { api, orgId, me, userName } = useOrg();
  const qc = useQueryClient();
  const router = useRouter();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<ProjectMember | null>(null);
  const q = useQuery({ queryKey: keys.projectMembers(orgId, project.id), queryFn: () => api.projectMembers(project.id) });

  const changeRole = useMutation({
    mutationFn: ({ m, role }: { m: ProjectMember; role: ProjectRole }) =>
      api.updateProjectMember(project.id, m.user_id, { project_role: role }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.projectMembers(orgId, project.id) });
      toast.success("Role updated");
    },
  });
  const remove = useMutation({
    mutationFn: (m: ProjectMember) => api.removeProjectMember(project.id, m.user_id),
    onSuccess: (_d, m) => {
      if (m.user_id === me.id) {
        toast.success("You left the project");
        qc.invalidateQueries({ queryKey: prefixes.projects(orgId) });
        router.push(`/orgs/${orgId}/projects`);
        return;
      }
      qc.invalidateQueries({ queryKey: keys.projectMembers(orgId, project.id) });
      toast.success("Member removed");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  if (q.isPending) return <ListSkeleton rows={3} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} what="project members" />;

  const name = (m: ProjectMember) => (m.user_id === me.id ? `${me.display_name} (you)` : (m.display_name ?? userName(m.user_id)));
  const existing = new Set(q.data.map((m) => m.user_id));
  // The owner participates by ownership and has no project_members row.
  const ownerListed = existing.has(project.owner_id);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          {q.data.length + (ownerListed ? 0 : 1)} {q.data.length + (ownerListed ? 0 : 1) === 1 ? "person" : "people"}
        </p>
        {canManage && (
          <Button size="sm" onClick={() => setAdding(true)}>
            <UserPlusIcon /> Add member
          </Button>
        )}
      </div>
      {q.data.length === 0 && ownerListed ? (
        <EmptyState icon={<UsersIcon />} title="No members yet" />
      ) : (
        <ul className="divide-y rounded-lg border">
          {!ownerListed && (
            <li className="flex items-center gap-3 px-4 py-3">
              <UserAvatar name={userName(project.owner_id)} seed={project.owner_id} />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{userName(project.owner_id)}</p>
                <p className="text-xs text-muted-foreground">Project owner</p>
              </div>
              <Badge variant="outline">Owner</Badge>
            </li>
          )}
          {q.data.map((m) => {
            const isMe = m.user_id === me.id;
            const isOwner = m.user_id === project.owner_id;
            return (
              <li key={m.user_id} className="flex items-center gap-3 px-4 py-3">
                <UserAvatar name={m.display_name ?? userName(m.user_id)} seed={m.user_id} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{name(m)}</p>
                  <p className="text-xs text-muted-foreground">Added {fmtDate(m.created_at)}</p>
                </div>
                {isOwner && <Badge variant="outline">Owner</Badge>}
                <Badge variant={m.project_role === "lead" ? "default" : "secondary"} className="capitalize">
                  {m.project_role}
                </Badge>
                {(canManage || isMe) && (
                  <DropdownMenu>
                    <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={`Actions for ${name(m)}`} />}>
                      <MoreHorizontalIcon />
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      {canManage && !isMe && (
                        <>
                          <DropdownMenuGroup>
                            <DropdownMenuLabel>Project role</DropdownMenuLabel>
                            <DropdownMenuRadioGroup
                              value={m.project_role}
                              onValueChange={(r) => r !== m.project_role && changeRole.mutate({ m, role: r as ProjectRole })}
                            >
                              <DropdownMenuRadioItem value="member">Member</DropdownMenuRadioItem>
                              <DropdownMenuRadioItem value="lead">Lead</DropdownMenuRadioItem>
                            </DropdownMenuRadioGroup>
                          </DropdownMenuGroup>
                          <DropdownMenuSeparator />
                        </>
                      )}
                      <DropdownMenuItem variant="destructive" onClick={() => setRemoving(m)}>
                        {isMe ? (
                          <>
                            <LogOutIcon /> Leave project
                          </>
                        ) : (
                          <>
                            <UserMinusIcon /> Remove from project
                          </>
                        )}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                )}
              </li>
            );
          })}
        </ul>
      )}
      <AddMemberDialog open={adding} onOpenChange={setAdding} project={project} existing={existing} />
      <ConfirmDialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={removing?.user_id === me.id ? "Leave this project?" : "Remove member?"}
        description={
          removing?.user_id === me.id
            ? "You'll lose access to its project-visible tasks and documents."
            : `${removing ? name(removing) : ""} will lose access to project-visible tasks and documents.`
        }
        confirmLabel={removing?.user_id === me.id ? "Leave" : "Remove"}
        destructive
        onConfirm={() => removing && remove.mutateAsync(removing)}
      />
    </div>
  );
}
