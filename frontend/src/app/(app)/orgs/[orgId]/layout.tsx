import { OrgGate } from "@/components/org/org-gate";

export default function OrgLayout({ children }: LayoutProps<"/orgs/[orgId]">) {
  return <OrgGate>{children}</OrgGate>;
}
