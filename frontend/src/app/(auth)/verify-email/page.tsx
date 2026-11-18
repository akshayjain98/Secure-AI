import type { Metadata } from "next";

import { VerifyEmail } from "@/components/auth/verify-reset";

export const metadata: Metadata = { title: "Verify email" };

export default function VerifyEmailPage() {
  return <VerifyEmail />;
}
