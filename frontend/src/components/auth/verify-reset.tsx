"use client";

import { SetPasswordForm } from "@/components/auth/set-password-form";
import { authApi } from "@/lib/api/endpoints";

export function VerifyEmail() {
  return (
    <SetPasswordForm
      title="Finish creating your account"
      description="Your email is confirmed. Choose a password to activate your account."
      submitLabel="Create account"
      successTitle="Your account is ready"
      successBody="You can now sign in with your email and new password."
      invalidLinkHref="/register"
      invalidLinkLabel="Start over"
      submit={authApi.verifyEmail}
    />
  );
}

export function ResetPassword() {
  return (
    <SetPasswordForm
      title="Choose a new password"
      description="All your other sessions will be signed out."
      submitLabel="Update password"
      successTitle="Password updated"
      successBody="Sign in with your new password. Other devices have been signed out."
      invalidLinkHref="/forgot-password"
      invalidLinkLabel="Request a new link"
      submit={authApi.confirmPasswordReset}
    />
  );
}
