import type { Metadata } from "next";

import { ResetPassword } from "@/components/auth/verify-reset";

export const metadata: Metadata = { title: "Choose a new password" };

export default function ResetPasswordPage() {
  return <ResetPassword />;
}
