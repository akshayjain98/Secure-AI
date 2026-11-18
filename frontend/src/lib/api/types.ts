// Mirrors the backend's Pydantic response models (app/api/*.py).
// Dates arrive as ISO strings; UUIDs as strings.

export type UUID = string;
export type ISODate = string;

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

// ---------------------------------------------------------------- auth / me
export interface TokenOut {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

export interface Message {
  detail: string;
}

export interface MeOrg {
  id: UUID;
  name: string;
  slug: string;
}

export interface CurrentOrg {
  id: UUID;
  role: RoleKey;
  permissions: Permission[];
}

export interface Me {
  id: UUID;
  email: string;
  display_name: string;
  organizations: MeOrg[];
  current_org: CurrentOrg | null;
}

export interface Invitation {
  organization_id: UUID;
  organization_name: string;
  role: RoleKey;
  invited_at: ISODate;
}

// ---------------------------------------------------------------- RBAC
export const PERMISSIONS = {
  "organization.read": "View organization profile and settings",
  "organization.update": "Change organization profile and settings",
  "user.read": "View the organization's member directory",
  "user.create": "Invite/add users to the organization",
  "user.update": "Change a member's role or status (rank-limited)",
  "user.delete": "Remove a member from the organization",
  "permission.manage": "Create/modify per-user permission overrides (rank-limited)",
  "project.create": "Create projects",
  "project.read": "View projects you own or are a member of",
  "project.read_all": "View all projects and project-visible content in the organization",
  "project.update": "Edit projects and manage project membership (owner/lead only)",
  "project.delete": "Delete projects you own",
  "task.create": "Create tasks in projects you participate in",
  "task.read": "View tasks you are entitled to see",
  "task.update": "Edit tasks you own, are assigned, or manage",
  "task.delete": "Delete tasks you own or manage",
  "document.read": "View documents you are entitled to see",
  "document.upload": "Upload documents",
  "document.update": "Edit metadata of documents you own",
  "document.delete": "Delete documents you own",
  "chatbot.use": "Use the AI assistant",
  "audit.read": "Read the organization's audit log",
} as const;
export type Permission = keyof typeof PERMISSIONS;

export type RoleKey = "super_admin" | "org_admin" | "manager" | "employee" | "viewer";
export const ROLES: Record<RoleKey, { name: string; rank: number; assignable: boolean }> = {
  super_admin: { name: "Super Admin", rank: 100, assignable: false },
  org_admin: { name: "Organization Admin", rank: 80, assignable: true },
  manager: { name: "Manager", rank: 60, assignable: true },
  employee: { name: "Employee", rank: 40, assignable: true },
  viewer: { name: "Viewer", rank: 20, assignable: true },
};

// ---------------------------------------------------------------- organization
export interface Org {
  id: UUID;
  name: string;
  slug: string;
  status: string;
  created_at: ISODate;
  updated_at: ISODate;
}

export type MemberStatus = "invited" | "active" | "suspended" | "removed";

export interface OrgMember {
  user_id: UUID;
  email: string | null;
  display_name: string | null;
  role: RoleKey;
  status: MemberStatus;
  invited_by: UUID | null;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface Override {
  permission: Permission;
  effect: "grant" | "deny";
  reason: string;
  expires_at: ISODate | null;
  active: boolean;
  created_by: UUID | null;
  created_at: ISODate;
}

// ---------------------------------------------------------------- projects
export type ProjectStatus = "active" | "archived";
export type ProjectRole = "lead" | "member";

export interface Project {
  id: UUID;
  owner_id: UUID;
  name: string;
  description: string | null;
  status: ProjectStatus;
  created_at: ISODate;
  updated_at: ISODate;
}

export interface ProjectMember {
  user_id: UUID;
  display_name: string | null;
  project_role: ProjectRole;
  created_at: ISODate;
}

// ---------------------------------------------------------------- tasks
export type TaskStatus = "todo" | "in_progress" | "blocked" | "done";
export type Priority = "low" | "medium" | "high" | "urgent";
export type TaskVisibility = "private" | "project";

export interface Task {
  id: UUID;
  project_id: UUID;
  owner_id: UUID;
  assignee_id: UUID | null;
  title: string;
  description: string | null;
  status: TaskStatus;
  priority: Priority;
  visibility: TaskVisibility;
  due_date: string | null; // YYYY-MM-DD
  created_at: ISODate;
  updated_at: ISODate;
}

// ---------------------------------------------------------------- documents
export type DocVisibility = "private" | "project" | "organization";
export const CONTENT_TYPES = {
  "application/pdf": "PDF",
  "text/plain": "Text",
  "text/markdown": "Markdown",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word",
} as const;
export type ContentType = keyof typeof CONTENT_TYPES;
export const MAX_DOC_SIZE = 50 * 1024 * 1024;

export interface Document {
  id: UUID;
  owner_id: UUID;
  project_id: UUID | null;
  title: string;
  content_type: ContentType;
  size_bytes: number;
  sha256: string;
  visibility: DocVisibility;
  created_at: ISODate;
  updated_at: ISODate;
}

// ---------------------------------------------------------------- audit
export type AuditOutcome = "success" | "denied" | "failure" | "error";

export interface AuditLog {
  id: UUID;
  occurred_at: ISODate;
  actor_user_id: UUID | null;
  action: string;
  outcome: AuditOutcome;
  resource_type: string | null;
  resource_id: UUID | null;
  request_id: string | null;
  ip_address: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown>;
}
