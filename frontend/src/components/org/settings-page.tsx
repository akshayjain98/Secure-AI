"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckIcon, MinusIcon, ShieldMinusIcon, ShieldPlusIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { RoleBadge } from "@/components/common/badges";
import { PageHeader } from "@/components/common/page-header";
import { ErrorState, ListSkeleton } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { errorMessage } from "@/lib/api/client";
import { PERMISSIONS, type Org, type Permission } from "@/lib/api/types";
import { fmtDate } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys } from "@/lib/queries";
import { cn } from "@/lib/utils";

function OrgProfile() {
  const { api, orgId } = useOrg();
  const q = useQuery({ queryKey: keys.orgDetails(orgId), queryFn: () => api.get() });
  if (q.isPending) return <ListSkeleton rows={2} />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} what="organization settings" />;
  return <OrgProfileForm key={q.data.updated_at} org={q.data} />;
}

function OrgProfileForm({ org }: { org: Org }) {
  const { api, orgId, can } = useOrg();
  const qc = useQueryClient();
  const [name, setName] = useState(org.name);

  const save = useMutation({
    mutationFn: () => api.update({ name: name.trim() }),
    onSuccess: (org) => {
      qc.setQueryData(keys.orgDetails(orgId), org);
      qc.invalidateQueries({ queryKey: keys.me });
      qc.invalidateQueries({ queryKey: keys.meInOrg(orgId) });
      toast.success("Organization renamed");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  const editable = can("organization.update");
  const dirty = name.trim() !== org.name && name.trim().length > 0 && name.trim().length <= 200;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Organization</CardTitle>
        <CardDescription>Created {fmtDate(org.created_at)}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <form
          className="flex max-w-lg flex-col gap-2 sm:flex-row sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty) save.mutate();
          }}
        >
          <Field className="flex-1">
            <FieldLabel htmlFor="org-name">Name</FieldLabel>
            <Input id="org-name" value={name} maxLength={200} disabled={!editable} onChange={(e) => setName(e.target.value)} />
          </Field>
          {editable && (
            <Button type="submit" disabled={!dirty || save.isPending}>
              {save.isPending && <Spinner />} Save
            </Button>
          )}
        </form>
        <div className="grid max-w-lg gap-4 sm:grid-cols-2">
          <Field>
            <FieldLabel>Slug</FieldLabel>
            <code className="rounded-md bg-muted px-2 py-1.5 text-sm">{org.slug}</code>
            <FieldDescription>Set by platform operators.</FieldDescription>
          </Field>
          <Field>
            <FieldLabel>Status</FieldLabel>
            <div>
              <Badge variant="secondary" className="capitalize">
                {org.status}
              </Badge>
            </div>
          </Field>
        </div>
      </CardContent>
    </Card>
  );
}

const GROUPS = ["organization", "user", "permission", "project", "task", "document", "chatbot", "audit"] as const;

function MyAccess() {
  const { role, permissions, api, orgId, me } = useOrg();
  const overrides = useQuery({ queryKey: keys.overrides(orgId, me.id), queryFn: () => api.overrides(me.id) });
  const all = Object.keys(PERMISSIONS) as Permission[];
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Your access <RoleBadge role={role} />
        </CardTitle>
        <CardDescription>
          Effective permissions from your role plus any active overrides. The database enforces these on every request;
          this view is informational.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {overrides.data && overrides.data.length > 0 && (
          <div className="space-y-1.5 rounded-lg border p-3">
            <p className="text-sm font-medium">Overrides on your account</p>
            {overrides.data.map((o) => (
              <p key={o.permission} className={cn("flex items-center gap-2 text-sm", !o.active && "opacity-60")}>
                {o.effect === "grant" ? <ShieldPlusIcon className="size-4 text-emerald-600" /> : <ShieldMinusIcon className="size-4 text-red-600" />}
                <code className="text-xs">{o.permission}</code>
                <span className="truncate text-muted-foreground">— {o.reason}</span>
              </p>
            ))}
          </div>
        )}
        <div className="grid gap-x-8 gap-y-5 md:grid-cols-2">
          {GROUPS.map((g) => (
            <div key={g}>
              <h3 className="mb-1.5 text-xs font-medium tracking-wide text-muted-foreground uppercase">{g}</h3>
              <ul className="space-y-1">
                {all
                  .filter((p) => p.startsWith(g + "."))
                  .map((p) => {
                    const has = permissions.has(p);
                    return (
                      <li key={p} className="flex items-start gap-2 text-sm">
                        {has ? (
                          <CheckIcon className="mt-0.5 size-4 shrink-0 text-emerald-600" aria-label="Granted" />
                        ) : (
                          <MinusIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground/50" aria-label="Not granted" />
                        )}
                        <span className={cn(!has && "text-muted-foreground")}>
                          {PERMISSIONS[p]} <code className="ml-1 text-[11px] text-muted-foreground">{p}</code>
                        </span>
                      </li>
                    );
                  })}
              </ul>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

export function SettingsPage() {
  return (
    <>
      <PageHeader title="Settings" description="Organization profile and your access in it." />
      <div className="space-y-6">
        <OrgProfile />
        <MyAccess />
      </div>
    </>
  );
}
