"""/me: the first endpoint that runs inside an RLS-bound transaction.

Every query here runs as secureai_app under set_context(), so it can return
only what Phase 1's policies allow. There's no hand-written
"WHERE user_id = :me" for safety; RLS supplies that.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.deps import RlsConn

router = APIRouter(tags=["me"])


class OrgOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str


class CurrentOrgOut(BaseModel):
    id: uuid.UUID
    role: str
    permissions: list[str]


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    organizations: list[OrgOut]
    current_org: CurrentOrgOut | None


@router.get("/me", response_model=MeOut)
def me(conn: RlsConn) -> MeOut:
    uid, email, display_name = conn.execute(
        "SELECT id, email, display_name FROM secureai.users "
        "WHERE id = secureai_rls.current_user_id()").fetchone()
    # organizations_select_member policy: only orgs with an active membership.
    orgs = [OrgOut(id=i, name=n, slug=s) for i, n, s in conn.execute(
        "SELECT id, name, slug FROM secureai.organizations ORDER BY name").fetchall()]

    current = None
    org_id = conn.execute("SELECT secureai_rls.current_org_id()").fetchone()[0]
    if org_id is not None:
        role = conn.execute(
            "SELECT r.key FROM secureai.organization_memberships m "
            "JOIN secureai.roles r ON r.id = m.role_id "
            "WHERE m.user_id = secureai_rls.current_user_id()").fetchone()[0]
        perms = [r[0] for r in conn.execute(
            "SELECT code FROM secureai.permissions "
            "WHERE secureai_rls.has_permission_id(id) ORDER BY code").fetchall()]
        current = CurrentOrgOut(id=org_id, role=role, permissions=perms)
    return MeOut(id=uid, email=email, display_name=display_name, organizations=orgs,
                 current_org=current)
