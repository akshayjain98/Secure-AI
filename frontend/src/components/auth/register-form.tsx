"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { AuthCard } from "@/components/auth/auth-card";
import { CheckInbox } from "@/components/auth/check-inbox";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { authApi } from "@/lib/api/endpoints";
import { applyServerError, emailSchema } from "@/lib/forms";

const schema = z.object({
  display_name: z.string().trim().min(1, "Enter your name").max(200),
  email: emailSchema,
});
type Values = z.infer<typeof schema>;

export function RegisterForm() {
  const [sent, setSent] = useState<{ email: string; message: string } | null>(null);
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { display_name: "", email: "" } });
  const { errors, isSubmitting } = form.formState;

  async function onSubmit(v: Values) {
    try {
      // Always 202 with the same body, whether or not the address is taken (no account enumeration).
      const res = await authApi.register(v.email, v.display_name);
      setSent({ email: v.email, message: res.detail });
    } catch (err) {
      applyServerError(err, form.setError, ["email", "display_name"]);
    }
  }

  if (sent) return <CheckInbox title="Check your inbox" message={sent.message} email={sent.email} />;

  return (
    <AuthCard
      title="Create your account"
      description="We'll email you a link to verify your address and set a password."
      footer={
        <span>
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-foreground underline-offset-4 hover:underline">
            Sign in
          </Link>
        </span>
      }
    >
      <form onSubmit={form.handleSubmit(onSubmit)} noValidate>
        <FieldGroup>
          {errors.root && (
            <Alert variant="destructive">
              <AlertDescription>{errors.root.message}</AlertDescription>
            </Alert>
          )}
          <Field data-invalid={!!errors.display_name}>
            <FieldLabel htmlFor="display_name">Full name</FieldLabel>
            <Input id="display_name" autoComplete="name" autoFocus aria-invalid={!!errors.display_name} {...form.register("display_name")} />
            <FieldError errors={[errors.display_name]} />
          </Field>
          <Field data-invalid={!!errors.email}>
            <FieldLabel htmlFor="email">Work email</FieldLabel>
            <Input id="email" type="email" autoComplete="email" aria-invalid={!!errors.email} {...form.register("email")} />
            <FieldDescription>To join an organization, use the address you were invited with.</FieldDescription>
            <FieldError errors={[errors.email]} />
          </Field>
          <Button type="submit" size="lg" disabled={isSubmitting} className="w-full">
            {isSubmitting && <Spinner />} Continue
          </Button>
        </FieldGroup>
      </form>
    </AuthCard>
  );
}
