"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { Controller, useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { SimpleSelect } from "@/components/common/simple-select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { ROLES, type RoleKey } from "@/lib/api/types";
import { applyServerError, emailSchema } from "@/lib/forms";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes } from "@/lib/queries";

const schema = z.object({ email: emailSchema, role: z.string() });
type Values = z.infer<typeof schema>;

/** Roles the caller may hand out: assignable via the API and not above their own rank. */
export function useAssignableRoles() {
  const { rank } = useOrg();
  return (Object.entries(ROLES) as [RoleKey, (typeof ROLES)[RoleKey]][])
    .filter(([, r]) => r.assignable && r.rank <= rank)
    .sort((a, b) => b[1].rank - a[1].rank)
    .map(([key, r]) => ({ value: key, label: r.name }));
}

export function InviteDialog({
  open,
  onOpenChange,
  initialEmail,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  initialEmail?: string;
}) {
  const { api, orgId, org } = useOrg();
  const qc = useQueryClient();
  const roles = useAssignableRoles();
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { email: "", role: "employee" } });
  const { errors, isSubmitting } = form.formState;

  useEffect(() => {
    if (open) form.reset({ email: initialEmail ?? "", role: "employee" });
  }, [open, initialEmail, form]);

  const invite = useMutation({
    mutationFn: (v: Values) => api.invite({ email: v.email.toLowerCase(), role: v.role }),
    onSuccess: (_m, v) => {
      qc.invalidateQueries({ queryKey: prefixes.members(orgId) });
      qc.invalidateQueries({ queryKey: keys.directory(orgId) });
      toast.success(`Invitation sent to ${v.email}`);
      onOpenChange(false);
    },
    onError: (err) => applyServerError(err, form.setError, ["email", "role"]),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !isSubmitting && onOpenChange(o)}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Invite to {org.name}</DialogTitle>
          <DialogDescription>
            They&apos;ll get an email and must sign in with this address to accept. The link alone grants nothing.
          </DialogDescription>
        </DialogHeader>
        <form id="invite-form" onSubmit={form.handleSubmit((v) => invite.mutateAsync(v).catch(() => {}))} noValidate>
          <FieldGroup className="gap-4">
            {errors.root && (
              <Alert variant="destructive">
                <AlertDescription>{errors.root.message}</AlertDescription>
              </Alert>
            )}
            <Field data-invalid={!!errors.email}>
              <FieldLabel htmlFor="invite-email">Email</FieldLabel>
              <Input id="invite-email" type="email" autoFocus aria-invalid={!!errors.email} {...form.register("email")} />
              <FieldError errors={[errors.email]} />
            </Field>
            <Field>
              <FieldLabel htmlFor="invite-role">Role</FieldLabel>
              <Controller
                control={form.control}
                name="role"
                render={({ field }) => <SimpleSelect id="invite-role" value={field.value} onChange={field.onChange} options={roles} />}
              />
              <FieldDescription>You can only assign roles up to your own.</FieldDescription>
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" form="invite-form" disabled={isSubmitting}>
            {isSubmitting && <Spinner />} Send invitation
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
