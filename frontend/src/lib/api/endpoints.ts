/** Typed wrappers for every backend endpoint. One function per route. */

import { api, CSRF_HEADER, request, tokenStore } from "./client";
import type {
  AuditLog,
  AuditOutcome,
  ContentType,
  Document,
  DocVisibility,
  Invitation,
  Me,
  MemberStatus,
  Message,
  Org,
  OrgMember,
  Override,
  Page,
  Priority,
  Project,
  ProjectMember,
  ProjectRole,
  ProjectStatus,
  Task,
  TaskStatus,
  TaskVisibility,
  TokenOut,
  UUID,
} from "./types";

export interface PageQuery {
  cursor?: string | null;
  limit?: number;
}

const enc = encodeURIComponent;

// ------------------------------------------------------------------ auth
export const authApi = {
  async login(email: string, password: string) {
    const token = await request<TokenOut>("/auth/login", {
      method: "POST",
      body: { email, password },
      auth: false,
    });
    tokenStore.set(token);
    return token;
  },
  async logout() {
    try {
      await request<void>("/auth/logout", {
        method: "POST",
        headers: { [CSRF_HEADER]: "1" },
        auth: false,
      });
    } finally {
      tokenStore.clear();
    }
  },
  register: (email: string, display_name: string) =>
    request<Message>("/auth/register", { method: "POST", body: { email, display_name }, auth: false }),
  verifyEmail: (token: string, password: string) =>
    request<void>("/auth/verify-email", { method: "POST", body: { token, password }, auth: false }),
  requestPasswordReset: (email: string) =>
    request<Message>("/auth/password-reset/request", { method: "POST", body: { email }, auth: false }),
  confirmPasswordReset: (token: string, new_password: string) =>
    request<void>("/auth/password-reset/confirm", {
      method: "POST",
      body: { token, new_password },
      auth: false,
    }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>("/auth/password/change", { method: "POST", body: { current_password, new_password } }),
};

// ------------------------------------------------------------------ me
export const meApi = {
  get: (orgId?: UUID | null) => api<Me>("/me", { headers: orgId ? { "X-Org-Id": orgId } : undefined }),
  invitations: () => api<Invitation[]>("/me/invitations"),
  acceptInvitation: (orgId: UUID) => api<void>(`/me/invitations/${enc(orgId)}/accept`, { method: "POST" }),
  declineInvitation: (orgId: UUID) => api<void>(`/me/invitations/${enc(orgId)}/decline`, { method: "POST" }),
};

// ------------------------------------------------------------------ org-scoped
export interface TaskInput {
  title: string;
  description?: string | null;
  status?: TaskStatus;
  priority?: Priority;
  visibility?: TaskVisibility;
  due_date?: string | null;
  assignee_id?: UUID | null;
}

export interface DocumentInput {
  title: string;
  content_type: ContentType;
  size_bytes: number;
  sha256: string;
  project_id?: UUID | null;
  visibility?: DocVisibility;
}

export function orgApi(orgId: UUID) {
  const base = `/orgs/${enc(orgId)}`;
  return {
    // organization
    get: () => api<Org>(base),
    update: (body: { name: string }) => api<Org>(base, { method: "PATCH", body }),

    // members
    members: (q: PageQuery & { status?: MemberStatus } = {}) => api<Page<OrgMember>>(`${base}/members`, { query: { ...q } }),
    member: (userId: UUID) => api<OrgMember>(`${base}/members/${enc(userId)}`),
    invite: (body: { email: string; role: string }) =>
      api<OrgMember>(`${base}/members`, { method: "POST", body }),
    updateMember: (userId: UUID, body: { role?: string; status?: "active" | "suspended" }) =>
      api<OrgMember>(`${base}/members/${enc(userId)}`, { method: "PATCH", body }),
    removeMember: (userId: UUID) => api<void>(`${base}/members/${enc(userId)}`, { method: "DELETE" }),

    // permission overrides
    overrides: (userId: UUID) => api<Override[]>(`${base}/members/${enc(userId)}/overrides`),
    setOverride: (
      userId: UUID,
      permission: string,
      body: { effect: "grant" | "deny"; reason: string; expires_at?: string | null },
    ) => api<Override>(`${base}/members/${enc(userId)}/overrides/${enc(permission)}`, { method: "PUT", body }),
    deleteOverride: (userId: UUID, permission: string) =>
      api<void>(`${base}/members/${enc(userId)}/overrides/${enc(permission)}`, { method: "DELETE" }),

    // projects
    projects: (q: PageQuery & { status?: ProjectStatus } = {}) => api<Page<Project>>(`${base}/projects`, { query: { ...q } }),
    project: (id: UUID) => api<Project>(`${base}/projects/${enc(id)}`),
    createProject: (body: { name: string; description?: string | null }) =>
      api<Project>(`${base}/projects`, { method: "POST", body }),
    updateProject: (id: UUID, body: Partial<Pick<Project, "name" | "description" | "status">>) =>
      api<Project>(`${base}/projects/${enc(id)}`, { method: "PATCH", body }),
    deleteProject: (id: UUID) => api<void>(`${base}/projects/${enc(id)}`, { method: "DELETE" }),
    projectMembers: (id: UUID) => api<ProjectMember[]>(`${base}/projects/${enc(id)}/members`),
    addProjectMember: (id: UUID, body: { user_id: UUID; project_role: ProjectRole }) =>
      api<ProjectMember>(`${base}/projects/${enc(id)}/members`, { method: "POST", body }),
    updateProjectMember: (id: UUID, userId: UUID, body: { project_role: ProjectRole }) =>
      api<ProjectMember>(`${base}/projects/${enc(id)}/members/${enc(userId)}`, { method: "PATCH", body }),
    removeProjectMember: (id: UUID, userId: UUID) =>
      api<void>(`${base}/projects/${enc(id)}/members/${enc(userId)}`, { method: "DELETE" }),

    // tasks
    tasks: (q: PageQuery & { project_id?: UUID; status?: TaskStatus; assigned_to_me?: boolean } = {}) =>
      api<Page<Task>>(`${base}/tasks`, { query: { ...q } }),
    task: (id: UUID) => api<Task>(`${base}/tasks/${enc(id)}`),
    createTask: (projectId: UUID, body: TaskInput) =>
      api<Task>(`${base}/projects/${enc(projectId)}/tasks`, { method: "POST", body }),
    updateTask: (id: UUID, body: Partial<TaskInput>) => api<Task>(`${base}/tasks/${enc(id)}`, { method: "PATCH", body }),
    deleteTask: (id: UUID) => api<void>(`${base}/tasks/${enc(id)}`, { method: "DELETE" }),

    // documents
    documents: (q: PageQuery & { project_id?: UUID; visibility?: DocVisibility; mine?: boolean } = {}) =>
      api<Page<Document>>(`${base}/documents`, { query: { ...q } }),
    document: (id: UUID) => api<Document>(`${base}/documents/${enc(id)}`),
    createDocument: (body: DocumentInput) => api<Document>(`${base}/documents`, { method: "POST", body }),
    updateDocument: (id: UUID, body: { title?: string; visibility?: DocVisibility; project_id?: UUID | null }) =>
      api<Document>(`${base}/documents/${enc(id)}`, { method: "PATCH", body }),
    deleteDocument: (id: UUID) => api<void>(`${base}/documents/${enc(id)}`, { method: "DELETE" }),

    // audit
    auditLogs: (
      q: PageQuery & {
        action?: string;
        actor_id?: UUID;
        resource_type?: string;
        resource_id?: UUID;
        outcome?: AuditOutcome;
      } = {},
    ) => api<Page<AuditLog>>(`${base}/audit-logs`, { query: { ...q } }),
  };
}

export type OrgApi = ReturnType<typeof orgApi>;
