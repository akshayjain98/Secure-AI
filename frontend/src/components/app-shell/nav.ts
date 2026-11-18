import {
  CheckSquareIcon,
  FileTextIcon,
  FolderKanbanIcon,
  LayoutDashboardIcon,
  ScrollTextIcon,
  SettingsIcon,
  UsersIcon,
  type LucideIcon,
} from "lucide-react";

import type { Permission } from "@/lib/api/types";

export interface NavItem {
  label: string;
  href: (orgId: string) => string;
  icon: LucideIcon;
  /** Hidden unless the caller effectively holds this permission. */
  requires?: Permission;
  exact?: boolean;
}

export const ORG_NAV: NavItem[] = [
  { label: "Overview", href: (o) => `/orgs/${o}`, icon: LayoutDashboardIcon, exact: true },
  { label: "Projects", href: (o) => `/orgs/${o}/projects`, icon: FolderKanbanIcon, requires: "project.read" },
  { label: "Tasks", href: (o) => `/orgs/${o}/tasks`, icon: CheckSquareIcon, requires: "task.read" },
  { label: "Documents", href: (o) => `/orgs/${o}/documents`, icon: FileTextIcon, requires: "document.read" },
  { label: "Members", href: (o) => `/orgs/${o}/members`, icon: UsersIcon, requires: "user.read" },
  { label: "Audit log", href: (o) => `/orgs/${o}/audit`, icon: ScrollTextIcon, requires: "audit.read" },
  { label: "Settings", href: (o) => `/orgs/${o}/settings`, icon: SettingsIcon, requires: "organization.read" },
];
