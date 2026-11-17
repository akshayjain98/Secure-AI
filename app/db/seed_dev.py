"""Development / test seed data. ALL DATA IS FICTIONAL.

Run:  uv run python -m app.db.seed_dev

* Connects as secureai_migrator (BYPASSRLS ops role) - seeding is a trusted
  maintenance operation, never something the application role can do.
* Refuses to run when SECUREAI_ENV=production.
* Passwords: taken from SECUREAI_SEED_PASSWORD, otherwise a random one is
  generated and printed once. Only Argon2id hashes are stored.
* IDs are deterministic (uuid5) so tests can reference rows by name.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import uuid
from dataclasses import dataclass

import psycopg
from argon2 import PasswordHasher

from app.db.dsn import psycopg_conninfo

_NAMESPACE = uuid.UUID("0b6c1f0e-5d7a-4b8e-9a31-5ec0a1d0c0de")


def _id(kind: str, key: str) -> uuid.UUID:
    return uuid.uuid5(_NAMESPACE, f"{kind}:{key}")


class ID:
    """Deterministic IDs for seeded rows, e.g. ID.user('priya')."""

    @staticmethod
    def org(key: str) -> uuid.UUID: return _id("org", key)
    @staticmethod
    def user(key: str) -> uuid.UUID: return _id("user", key)
    @staticmethod
    def project(key: str) -> uuid.UUID: return _id("project", key)
    @staticmethod
    def task(key: str) -> uuid.UUID: return _id("task", key)
    @staticmethod
    def document(key: str) -> uuid.UUID: return _id("document", key)
    @staticmethod
    def conversation(key: str) -> uuid.UUID: return _id("conversation", key)


ORGS = {
    "org_a": ("Asteria Labs", "asteria-labs"),
    "org_b": ("Borealis Systems", "borealis-systems"),
}

USERS = {
    "akshay": ("akshay@asteria.example", "Akshay"),
    "rahul": ("rahul@asteria.example", "Rahul"),
    "priya": ("priya@asteria.example", "Priya"),
    "john": ("john@borealis.example", "John"),
    "david": ("david@borealis.example", "David"),
    # Extra (not in the brief): a consultant in BOTH orgs, to prove that
    # isolation is per org *context*, not per user.
    "meera": ("meera@consulting.example", "Meera"),
}

MEMBERSHIPS = [  # (org, user, role_key)
    ("org_a", "akshay", "org_admin"),
    ("org_a", "rahul", "manager"),
    ("org_a", "priya", "employee"),
    ("org_a", "meera", "viewer"),
    ("org_b", "john", "org_admin"),
    ("org_b", "david", "employee"),
    ("org_b", "meera", "employee"),
]

PROJECTS = {  # key: (org, owner, name, [(member, project_role)])
    "apollo": ("org_a", "rahul", "Apollo Data Migration", [("rahul", "lead"), ("priya", "member")]),
    "atlas": ("org_a", "akshay", "Atlas Internal Tools", [("akshay", "lead"), ("rahul", "member")]),
    "helios": ("org_a", "akshay", "Helios Research", [("akshay", "lead")]),
    "polaris": ("org_b", "john", "Polaris Data Platform",
                [("john", "lead"), ("david", "member"), ("meera", "member")]),
}

# key: (org, project, owner, assignee, title, visibility)
TASKS = {
    # --- Org A / Apollo (Rahul's team: Rahul lead, Priya member)
    "rahul_cutover": ("org_a", "apollo", "rahul", "rahul", "Define Apollo cutover plan", "project"),
    "rahul_runbook": ("org_a", "apollo", "rahul", "priya", "Review migration runbook", "project"),
    "rahul_private": ("org_a", "apollo", "rahul", None, "Prepare retrospective notes", "private"),
    "priya_validation": ("org_a", "apollo", "priya", "priya", "Write data validation scripts", "project"),
    "priya_private_learning": ("org_a", "apollo", "priya", None, "Personal learning plan", "private"),
    "priya_private_review": ("org_a", "apollo", "priya", None, "Draft self-review", "private"),
    # --- Org A / Atlas + Helios (Akshay)
    "akshay_atlas_access": ("org_a", "atlas", "akshay", "rahul", "Provision tooling access", "project"),
    "akshay_vendor": ("org_a", "helios", "akshay", None, "Evaluate vendor shortlist", "project"),
    "akshay_budget": ("org_a", "helios", "akshay", None, "Budget planning notes", "private"),
    # --- Org B / Polaris
    "john_planning": ("org_b", "polaris", "john", None, "Quarterly planning", "private"),
    "david_ci": ("org_b", "polaris", "david", "david", "Set up CI pipeline", "project"),
    "david_onboarding": ("org_b", "polaris", "david", None, "Onboarding checklist", "private"),
    "meera_catalog": ("org_b", "polaris", "meera", None, "Data catalog review", "project"),
}

# key: (org, owner, project or None, title, visibility)
DOCUMENTS = {
    "a_handbook": ("org_a", "akshay", None, "Asteria employee handbook", "organization"),
    "a_comp_bands": ("org_a", "akshay", None, "Compensation bands (draft)", "private"),
    "a_apollo_arch": ("org_a", "rahul", "apollo", "Apollo architecture overview", "project"),
    "a_helios_research": ("org_a", "akshay", "helios", "Helios research notes", "project"),
    "a_priya_notes": ("org_a", "priya", None, "Priya's working notes", "private"),
    "b_security_policy": ("org_b", "john", None, "Borealis security policy", "organization"),
    "b_david_proposal": ("org_b", "david", None, "Draft tooling proposal", "private"),
}

# key: (org, user, title, [(role, content)])
CONVERSATIONS = {
    "priya_chat": ("org_a", "priya", "Validation script ideas", [
        ("user", "How should I structure row-count validation for a migration?"),
        ("assistant", "Compare per-table counts and checksums between source and target."),
    ]),
    "rahul_chat": ("org_a", "rahul", "Cutover checklist", [
        ("user", "Draft a cutover checklist outline."),
        ("assistant", "1. Freeze writes 2. Final sync 3. Validate 4. Switch traffic."),
    ]),
    "david_chat": ("org_b", "david", "CI caching", [
        ("user", "How do I cache dependencies in CI?"),
        ("assistant", "Key the cache on the lockfile hash."),
    ]),
}


@dataclass
class SeedResult:
    password: str
    generated: bool


def seed(conninfo: str | None = None, password: str | None = None) -> SeedResult:
    if os.environ.get("SECUREAI_ENV", "development").lower() == "production":
        raise RuntimeError("Refusing to load fictional seed data into production")

    generated = False
    if password is None:
        password = os.environ.get("SECUREAI_SEED_PASSWORD")
    if not password:
        password, generated = secrets.token_urlsafe(18), True

    hasher = PasswordHasher()  # Argon2id, RFC 9106 low-memory profile defaults
    conninfo = conninfo or psycopg_conninfo("migrator")

    with psycopg.connect(conninfo) as conn, conn.cursor() as cur:
        cur.execute("SELECT key, id FROM secureai.roles")
        role_ids = dict(cur.fetchall())

        for key, (name, slug) in ORGS.items():
            cur.execute(
                "INSERT INTO secureai.organizations (id, name, slug) VALUES (%s, %s, %s) "
                "ON CONFLICT (id) DO NOTHING", (ID.org(key), name, slug))

        for key, (email, display) in USERS.items():
            cur.execute(
                "INSERT INTO secureai.users (id, email, display_name, status, email_verified_at) "
                "VALUES (%s, %s, %s, 'active', now()) ON CONFLICT (id) DO NOTHING",
                (ID.user(key), email, display))
            cur.execute(
                "INSERT INTO secureai.user_credentials (user_id, password_hash) VALUES (%s, %s) "
                "ON CONFLICT (user_id) DO NOTHING", (ID.user(key), hasher.hash(password)))

        for org, user, role in MEMBERSHIPS:
            cur.execute(
                "INSERT INTO secureai.organization_memberships (organization_id, user_id, role_id, status) "
                "VALUES (%s, %s, %s, 'active') ON CONFLICT (organization_id, user_id) DO NOTHING",
                (ID.org(org), ID.user(user), role_ids[role]))

        for key, (org, owner, name, members) in PROJECTS.items():
            cur.execute(
                "INSERT INTO secureai.projects (id, organization_id, owner_id, name) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (ID.project(key), ID.org(org), ID.user(owner), name))
            for member, prole in members:
                cur.execute(
                    "INSERT INTO secureai.project_members "
                    "(organization_id, project_id, user_id, project_role, added_by) "
                    "VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                    (ID.org(org), ID.project(key), ID.user(member), prole, ID.user(owner)))

        for key, (org, project, owner, assignee, title, vis) in TASKS.items():
            cur.execute(
                "INSERT INTO secureai.tasks "
                "(id, organization_id, project_id, owner_id, assignee_id, title, visibility) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (ID.task(key), ID.org(org), ID.project(project), ID.user(owner),
                 ID.user(assignee) if assignee else None, title, vis))

        for key, (org, owner, project, title, vis) in DOCUMENTS.items():
            body = f"fictional content for {key}".encode()
            cur.execute(
                "INSERT INTO secureai.documents (id, organization_id, owner_id, project_id, title, "
                "storage_key, content_type, size_bytes, sha256, visibility) "
                "VALUES (%s, %s, %s, %s, %s, %s, 'text/plain', %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (ID.document(key), ID.org(org), ID.user(owner),
                 ID.project(project) if project else None, title,
                 f"orgs/{ID.org(org)}/documents/{ID.document(key)}", len(body),
                 hashlib.sha256(body).digest(), vis))

        for key, (org, user, title, msgs) in CONVERSATIONS.items():
            cur.execute(
                "INSERT INTO secureai.conversations (id, organization_id, user_id, title) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                (ID.conversation(key), ID.org(org), ID.user(user), title))
            cur.execute("SELECT count(*) FROM secureai.messages WHERE conversation_id = %s",
                        (ID.conversation(key),))
            if cur.fetchone()[0] == 0:
                for role, content in msgs:
                    cur.execute(
                        "INSERT INTO secureai.messages "
                        "(organization_id, conversation_id, user_id, role, content) "
                        "VALUES (%s, %s, %s, %s, %s)",
                        (ID.org(org), ID.conversation(key), ID.user(user), role, content))

        cur.execute("SELECT count(*) FROM secureai.audit_logs WHERE action = 'system.seed_loaded'")
        if cur.fetchone()[0] == 0:
            for org in ORGS:
                cur.execute(
                    "INSERT INTO secureai.audit_logs (organization_id, action, outcome, metadata) "
                    "VALUES (%s, 'system.seed_loaded', 'success', '{\"source\": \"seed_dev\"}')",
                    (ID.org(org),))
        conn.commit()

    return SeedResult(password=password, generated=generated)


if __name__ == "__main__":
    result = seed()
    print("Seed data loaded (fictional).")
    if result.generated:
        print("Generated dev password for ALL seed users (shown once, not stored):")
        print(f"  {result.password}")
