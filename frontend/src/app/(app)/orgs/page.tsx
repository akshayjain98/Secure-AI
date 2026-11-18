import type { Metadata } from "next";

import { OrgPicker } from "@/components/org/org-picker";

export const metadata: Metadata = { title: "Organizations" };

export default function OrgsPage() {
  return <OrgPicker />;
}
