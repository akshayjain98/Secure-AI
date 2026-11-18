"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { CheckCircle2Icon, LinkIcon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { AuthCard } from "@/components/auth/auth-card";
import { useFragmentToken } from "@/components/auth/use-fragment-token";
import { PasswordInput } from "@/components/common/password-input";
import { FullPageLoader } from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Spinner } from "@/components/ui/spinner";
import { ApiError } from "@/lib/api/client";
import { applyServerError, PASSWORD_MIN, passwordSchema } from "@/lib/forms";

const schema = z
  .object({ password: passwordSchema, confirm: z.string() })
  .refine((v) => v.password === v.confirm, { path: ["confirm"], message: "Passwords don't match" });
type Values = z.infer<typeof schema>;

function Notice({ icon, title, body, cta }: { icon: React.ReactNode; title: string; body: string; cta: React.ReactNode }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-6 text-center">
        <span className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary">{icon}</span>
        <h1 className="font-heading text-xl font-semibold">{title}</h1>
        <p className="text-sm text-muted-foreground">{body}</p>
        {cta}
      </CardContent>
    </Card>
  );
}

/**
 * Shared by /verify-email (new account: proves inbox ownership + sets the
 * first password) and /reset-password. Both take a one-time token from the
 * URL fragment.
 */
export function SetPasswordForm({
  title,
  description,
  submitLabel,
  successTitle,
  successBody,
  invalidLinkHref,
  invalidLinkLabel,
  submit,
}: {
  title: string;
  description: string;
  submitLabel: string;
  successTitle: string;
  successBody: string;
  invalidLinkHref: string;
  invalidLinkLabel: string;
  submit: (token: string, password: string) => Promise<void>;
}) {
  const { ready, token } = useFragmentToken();
  const [done, setDone] = useState(false);
  const [linkInvalid, setLinkInvalid] = useState(false);
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { password: "", confirm: "" } });
  const { errors, isSubmitting } = form.formState;

  if (!ready) return <FullPageLoader />;

  if (done)
    return (
      <Notice
        icon={<CheckCircle2Icon className="size-6" />}
        title={successTitle}
        body={successBody}
        cta={
          <Button className="mt-2" nativeButton={false} render={<Link href="/login" />}>
            Sign in
          </Button>
        }
      />
    );

  if (!token || linkInvalid)
    return (
      <Notice
        icon={<LinkIcon className="size-6" />}
        title="This link is invalid or has expired"
        body="Links are single-use and expire quickly. Request a new one to continue."
        cta={
          <Button variant="outline" className="mt-2" nativeButton={false} render={<Link href={invalidLinkHref} />}>
            {invalidLinkLabel}
          </Button>
        }
      />
    );

  async function onSubmit(v: Values) {
    try {
      await submit(token!, v.password);
      setDone(true);
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) return setLinkInvalid(true);
      // 422 carries the server's policy message (too short, breached, contains email...).
      if (err instanceof ApiError && err.status === 422)
        return form.setError("password", { type: "server", message: err.message });
      applyServerError(err, form.setError);
    }
  }

  return (
    <AuthCard title={title} description={description}>
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          {errors.root && (
            <Alert variant="destructive">
              <AlertDescription>{errors.root.message}</AlertDescription>
            </Alert>
          )}
          <Field data-invalid={!!errors.password}>
            <FieldLabel htmlFor="password">New password</FieldLabel>
            <PasswordInput id="password" autoComplete="new-password" autoFocus aria-invalid={!!errors.password} {...form.register("password")} />
            <FieldDescription>
              At least {PASSWORD_MIN} characters. A passphrase of a few unrelated words works well.
            </FieldDescription>
            <FieldError errors={[errors.password]} />
          </Field>
          <Field data-invalid={!!errors.confirm}>
            <FieldLabel htmlFor="confirm">Confirm password</FieldLabel>
            <PasswordInput id="confirm" autoComplete="new-password" aria-invalid={!!errors.confirm} {...form.register("confirm")} />
            <FieldError errors={[errors.confirm]} />
          </Field>
          <Button type="submit" size="lg" disabled={isSubmitting} className="w-full">
            {isSubmitting && <Spinner />} {submitLabel}
          </Button>
        </FieldGroup>
      </form>
    </AuthCard>
  );
}
