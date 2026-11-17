"""RBAC reference data: permissions, system roles, role -> permission matrix.

This is production reference data (it ships to every environment), which is
why it is a migration and not part of the dev-only seed script.

Access is NEVER inferred from a role's name. Code and policies only ever ask
"does the caller effectively hold permission X?" via role_permissions plus
per-user overrides.

Revision ID: 0003_rbac_reference_data
Revises: 0002_security_layer
Create Date: 2026-11-17
"""

from alembic import op  # noqa: F401

from app.db.migration_utils import run_sql as _run

revision = "0003_rbac_reference_data"
down_revision = "0002_security_layer"
branch_labels = None
depends_on = None

PERMISSIONS: dict[str, str] = {
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
}

# key, name, rank, assignable via API, description
ROLES = [
    ("super_admin", "Super Admin", 100, False,
     "Platform operator. Assigned only by ops tooling, never through the API. "
     "Does NOT bypass tenant isolation: acts only inside orgs where it holds a membership."),
    ("org_admin", "Organization Admin", 80, True, "Full administration of one organization."),
    ("manager", "Manager", 60, True, "Runs projects and teams; no user administration."),
    ("employee", "Employee", 40, True, "Standard contributor."),
    ("viewer", "Viewer", 20, True, "Read-only access to shared content."),
]

ALL = set(PERMISSIONS)
ROLE_PERMISSIONS: dict[str, set[str]] = {
    "super_admin": ALL,
    "org_admin": ALL,
    "manager": {
        "organization.read", "user.read",
        "project.create", "project.read", "project.update", "project.delete",
        "task.create", "task.read", "task.update", "task.delete",
        "document.read", "document.upload", "document.update", "document.delete",
        "chatbot.use",
    },
    "employee": {
        "organization.read", "user.read",
        "project.read",
        "task.create", "task.read", "task.update",
        "document.read", "document.upload", "document.update", "document.delete",
        "chatbot.use",
    },
    "viewer": {
        "organization.read", "project.read", "task.read", "document.read",
    },
}


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    perm_rows = ",\n".join(f"({_q(c)}, {_q(d)})" for c, d in PERMISSIONS.items())
    _run(f"INSERT INTO secureai.permissions (code, description) VALUES\n{perm_rows};")

    role_rows = ",\n".join(
        f"({_q(k)}, {_q(n)}, {r}, {str(a).lower()}, {_q(d)})" for k, n, r, a, d in ROLES)
    _run(
        f"INSERT INTO secureai.roles (key, name, rank, assignable, description) VALUES\n{role_rows};")

    pairs = ",\n".join(
        f"({_q(role)}, {_q(code)})"
        for role, codes in ROLE_PERMISSIONS.items() for code in sorted(codes))
    _run(f"""
        INSERT INTO secureai.role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM (VALUES {pairs}) AS v(role_key, perm_code)
        JOIN secureai.roles r       ON r.key = v.role_key
        JOIN secureai.permissions p ON p.code = v.perm_code;
    """)


def downgrade() -> None:
    # Fails (FK RESTRICT) if any membership still references a role - by design:
    # a downgrade must not silently strip everyone's access.
    _run("""
        DELETE FROM secureai.role_permissions;
        DELETE FROM secureai.roles;
        DELETE FROM secureai.permissions;
    """)
