"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheckIcon, ShieldMinusIcon, ShieldPlusIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { RoleBadge } from "@/components/common/badges";
import { SimpleSelect } from "@/components/common/simple-select";
import { ErrorState, ListSkeleton } from "@/components/common/states";
import { UserAvatar } from "@/components/common/user-avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { errorMessage } from "@/lib/api/client";
import { PERMISSIONS, type OrgMember, type Override, type Permission } from "@/lib/api/types";
import { fmtDate, fmtDateTime, roleRank } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys } from "@/lib/queries";
import { cn } from "@/lib/utils";

const ALL_PERMS = Object.keys(PERMISSIONS) as Permission[];

function AddOverride({ member }: { member: OrgMember }) {
  const { api, orgId, can } = useOrg();
  const qc = useQueryClient();
  const [permission, setPermission] = useState<Permission | null>(null);
  const [effect, setEffect] = useState<"grant" | "deny">("deny");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState("");
  const [expiresOk, setExpiresOk] = useState(true);

  // RLS: a GRANT requires the grantor to hold that permission themselves.
  const grantBlocked = effect === "grant" && permission !== null && !can(permission);
  const reasonOk = reason.trim().length >= 3 && reason.trim().length <= 500;

  const save = useMutation({
    mutationFn: () =>
      api.setOverride(member.user_id, permission!, {
        effect,
        reason: reason.trim(),
        // datetime-local is wall-clock time; toISOString() adds the timezone the API requires.
        expires_at: expires ? new Date(expires).toISOString() : null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.overrides(orgId, member.user_id) });
      toast.success("Override saved");
      setPermission(null);
      setReason("");
      setExpires("");
      setExpiresOk(true);
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <FieldGroup className="gap-3">
      <Field>
        <FieldLabel htmlFor="ov-perm">Permission</FieldLabel>
        <SimpleSelect
          id="ov-perm"
          value={permission}
          onChange={setPermission}
          placeholder="Choose a permission"
          options={ALL_PERMS.map((p) => ({
            value: p,
            label: (
              <span className="flex flex-col">
                <span className="font-mono text-xs">{p}</span>
                <span className="text-xs text-muted-foreground">{PERMISSIONS[p]}</span>
              </span>
            ),
          }))}
        />
      </Field>
      <Field>
        <FieldLabel htmlFor="ov-effect">Effect</FieldLabel>
        <SimpleSelect<"grant" | "deny">
          id="ov-effect"
          value={effect}
          onChange={setEffect}
          options={[
            { value: "deny", label: "Deny — remove this permission even if the role has it" },
            { value: "grant", label: "Grant — add this permission on top of the role" },
          ]}
        />
        {grantBlocked && (
          <FieldDescription className="text-destructive">You can only grant permissions you hold yourself.</FieldDescription>
        )}
      </Field>
      <Field>
        <FieldLabel htmlFor="ov-reason">Reason</FieldLabel>
        <Textarea id="ov-reason" rows={2} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this needed? (recorded in the audit log)" />
      </Field>
      <Field>
        <FieldLabel htmlFor="ov-exp">Expires (optional)</FieldLabel>
        <Input id="ov-exp" type="datetime-local" value={expires} onChange={(e) => {
            const v = e.target.value;
            setExpires(v);
            setExpiresOk(!v || new Date(v).getTime() > Date.now());
          }}
        />
        {!expiresOk && <FieldDescription className="text-destructive">Must be in the future.</FieldDescription>}
      </Field>
      <div>
        <Button disabled={!permission || !reasonOk || !expiresOk || grantBlocked || save.isPending} onClick={() => save.mutate()}>
          {save.isPending && <Spinner />} Save override
        </Button>
      </div>
    </FieldGroup>
  );
}

function OverrideRow({ member, ov, canManage }: { member: OrgMember; ov: Override; canManage: boolean }) {
  const { api, orgId } = useOrg();
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: () => api.deleteOverride(member.user_id, ov.permission),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.overrides(orgId, member.user_id) });
      toast.success("Override removed");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });
  return (
    <li className={cn("flex items-start gap-3 py-3", !ov.active && "opacity-60")}>
      {ov.effect === "grant" ? (
        <ShieldPlusIcon className="mt-0.5 size-4 shrink-0 text-emerald-600" />
      ) : (
        <ShieldMinusIcon className="mt-0.5 size-4 shrink-0 text-red-600" />
      )}
      <div className="min-w-0 flex-1 space-y-1">
        <div className="flex flex-wrap items-center gap-1.5">
          <code className="text-xs font-medium">{ov.permission}</code>
          <Badge variant={ov.effect === "grant" ? "secondary" : "destructive"} className="capitalize">
            {ov.effect}
          </Badge>
          {!ov.active && <Badge variant="outline">Expired</Badge>}
        </div>
        <p className="text-sm break-words">{ov.reason}</p>
        <p className="text-xs text-muted-foreground">
          Added {fmtDate(ov.created_at)}
          {ov.expires_at && ` · ${ov.active ? "expires" : "expired"} ${fmtDateTime(ov.expires_at)}`}
        </p>
      </div>
      {canManage && (
        <Button variant="ghost" size="icon-sm" aria-label={`Remove ${ov.permission} override`} disabled={del.isPending} onClick={() => del.mutate()}>
          {del.isPending ? <Spinner /> : <Trash2Icon />}
        </Button>
      )}
    </li>
  );
}

/** Per-user permission overrides (grant/deny on top of the role). */
export function OverridesSheet({ member, onOpenChange }: { member: OrgMember | null; onOpenChange: (o: boolean) => void }) {
  return (
    <Sheet open={!!member} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">{member && <Body member={member} />}</SheetContent>
    </Sheet>
  );
}

function Body({ member }: { member: OrgMember }) {
  const { api, orgId, can, me, rank } = useOrg();
  const q = useQuery({ queryKey: keys.overrides(orgId, member.user_id), queryFn: () => api.overrides(member.user_id) });
  const isMe = member.user_id === me.id;
  const name = member.display_name ?? member.email ?? "Invited user";
  // Mirrors overrides_* policies: never on yourself, target not above my rank.
  const canManage = can("permission.manage") && !isMe && roleRank(member.role) <= rank;

  return (
    <>
      <SheetHeader>
        <SheetTitle>Permissions</SheetTitle>
        <SheetDescription>Overrides adjust one person&apos;s access on top of their role.</SheetDescription>
      </SheetHeader>
      <div className="space-y-5 px-4 pb-6">
        <div className="flex items-center gap-3">
          <UserAvatar name={name} seed={member.user_id} size="lg" />
          <div className="min-w-0">
            <p className="truncate font-medium">{name}</p>
            <p className="truncate text-xs text-muted-foreground">{member.email}</p>
          </div>
          <span className="flex-1" />
          <RoleBadge role={member.role} />
        </div>
        <Separator />
        <section>
          <h3 className="mb-1 flex items-center gap-2 text-sm font-medium">
            <ShieldCheckIcon className="size-4" /> Active overrides
          </h3>
          {q.isPending ? (
            <ListSkeleton rows={2} />
          ) : q.error ? (
            <ErrorState error={q.error} onRetry={() => q.refetch()} what="overrides" />
          ) : q.data.length === 0 ? (
            <p className="py-3 text-sm text-muted-foreground">
              {can("permission.manage") || isMe ? "No overrides. Access comes from the role alone." : "You can't view this member's overrides."}
            </p>
          ) : (
            <ul className="divide-y">
              {q.data.map((ov) => (
                <OverrideRow key={ov.permission} member={member} ov={ov} canManage={canManage} />
              ))}
            </ul>
          )}
        </section>
        {canManage && (
          <>
            <Separator />
            <section>
              <h3 className="mb-3 text-sm font-medium">Add or replace an override</h3>
              <AddOverride member={member} />
            </section>
          </>
        )}
        {isMe && can("permission.manage") && (
          <p className="text-xs text-muted-foreground">You can&apos;t change your own permissions; another administrator must.</p>
        )}
      </div>
    </>
  );
}
