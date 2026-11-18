import type { Metadata } from "next";

import { InvitationsList } from "@/components/org/invitations-list";

export const metadata: Metadata = { title: "Invitations" };

export default function InvitationsPage() {
  return <InvitationsList />;
}
