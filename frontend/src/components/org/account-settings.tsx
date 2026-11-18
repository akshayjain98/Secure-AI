"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { PageHeader } from "@/components/common/page-header";
import { PasswordInput } from "@/components/common/password-input";
import { UserAvatar } from "@/components/common/user-avatar";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api/client";
import { authApi } from "@/lib/api/endpoints";
import { applyServerError, PASSWORD_MIN, passwordSchema } from "@/lib/forms";
import { useMe } from "@/lib/queries";

const schema = z
  .object({ current: z.string().min(1, "Enter your current password"), next: passwordSchema, confirm: z.string() })
  .refine((v) => v.next === v.confirm, { path: ["confirm"], message: "Passwords don't match" })
  .refine((v) => v.next !== v.current, { path: ["next"], message: "Choose a different password" });
type Values = z.infer<typeof schema>;

function ChangePassword() {
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { current: "", next: "", confirm: "" } });
  const { errors, isSubmitting } = form.formState;

  async function onSubmit(v: Values) {
    try {
      await authApi.changePassword(v.current, v.next);
      form.reset();
      toast.success("Password changed. Your other sessions were signed out.");
    } catch (err) {
      if (err instanceof ApiError && err.status === 403)
        return form.setError("current", { type: "server", message: "Current password is incorrect" });
      if (err instanceof ApiError && err.status === 422)
        return form.setError("next", { type: "server", message: err.message });
      applyServerError(err, form.setError);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change password</CardTitle>
        <CardDescription>This session stays signed in; every other device is signed out.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={form.handleSubmit(onSubmit)} noValidate className="max-w-md">
          <FieldGroup>
            {errors.root && (
              <Alert variant="destructive">
                <AlertDescription>{errors.root.message}</AlertDescription>
              </Alert>
            )}
            <Field data-invalid={!!errors.current}>
              <FieldLabel htmlFor="current">Current password</FieldLabel>
              <PasswordInput id="current" autoComplete="current-password" aria-invalid={!!errors.current} {...form.register("current")} />
              <FieldError errors={[errors.current]} />
            </Field>
            <Field data-invalid={!!errors.next}>
              <FieldLabel htmlFor="next">New password</FieldLabel>
              <PasswordInput id="next" autoComplete="new-password" aria-invalid={!!errors.next} {...form.register("next")} />
              <FieldDescription>At least {PASSWORD_MIN} characters, and not your email.</FieldDescription>
              <FieldError errors={[errors.next]} />
            </Field>
            <Field data-invalid={!!errors.confirm}>
              <FieldLabel htmlFor="confirm">Confirm new password</FieldLabel>
              <PasswordInput id="confirm" autoComplete="new-password" aria-invalid={!!errors.confirm} {...form.register("confirm")} />
              <FieldError errors={[errors.confirm]} />
            </Field>
            <div>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting && <Spinner />} Update password
              </Button>
            </div>
          </FieldGroup>
        </form>
      </CardContent>
    </Card>
  );
}

export function AccountSettings() {
  const { data: me } = useMe();
  return (
    <>
      <PageHeader title="Account & security" description="Your profile and sign-in settings." />
      <div className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Profile</CardTitle>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <UserAvatar name={me?.display_name} seed={me?.id} size="lg" />
            <div className="min-w-0">
              <p className="truncate font-medium">{me?.display_name}</p>
              <p className="truncate text-sm text-muted-foreground">{me?.email}</p>
            </div>
          </CardContent>
        </Card>
        <ChangePassword />
      </div>
    </>
  );
}
