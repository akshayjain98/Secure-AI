"""Organization settings, members and permission overrides, under /orgs/{org_id}.

As in step 1, the database decides and the handlers only translate:
  org read     any active member (organizations_select_member)
  org rename   organization.update (organizations_update_admin), name only
  members      list/read: own row, or everyone with user.read
               invite:    user.create; role assignable and not above my rank;
                          status 'invited' only (memberships_insert)
               change:    user.update; target and new role not above my rank;
                          never my own row (memberships_update)
               remove:    the same, plus user.delete (status 'removed')
               the last active administrator can't be demoted/removed -> 409
               only the invitee activates a membership (transition trigger)
  overrides    permission.manage; never on myself; target not above my rank;
               a GRANT needs me to hold that permission (overrides_*)
Suspending or removing a member revokes their refresh sessions (trigger,
migration 0006); org access already ends on their next request.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Path, Query, Response, status
from psycopg import errors, sql
from psycopg.rows import dict_row
from pydantic import AwareDatetime, BaseModel, field_validator

from app.api.deps import Claims, OrgConn, State
from app.api.email import invitations_link
from app.api.models import StrictModel, patch_values, text
from app.api.pagination import Page, Paging, paginate
from app.api.rows import NOT_ALLOWED, fetch_one, not_found, write_or_404
from app.auth.service import EMAIL_RE

router = APIRouter(prefix="/orgs/{org_id}", tags=["organization"])

MemberStatus = Literal["invited", "active", "suspended", "removed"]
PermissionCode = Annotated[str, Path(max_length=100, pattern=r"^[a-z_]+(\.[a-z_]+)+$")]
INVITES_PER_HOUR = 30


# ------------------------------------------------------------------ organization
class OrgOut(BaseModel):
    id: uuid.UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime


class OrgUpdate(StrictModel):
    name: text(200)           # slug/status are not API-writable (no column grant)


ORG_COLS = "id, name, slug, status, created_at, updated_at"


@router.get("", response_model=OrgOut)
def get_org(conn: OrgConn) -> OrgOut:
    return OrgOut(**fetch_one(conn, f"SELECT {ORG_COLS} FROM secureai.organizations "
                                    "WHERE id = secureai_rls.current_org_id()", (), "Organization"))


@router.patch("", response_model=OrgOut)
def update_org(conn: OrgConn, org_id: uuid.UUID, body: OrgUpdate) -> OrgOut:
    # The org is always visible to a member, so 0 rows here means 403.
    return OrgOut(**write_or_404(
        conn, f"UPDATE secureai.organizations SET name = %s "
              f"WHERE id = secureai_rls.current_org_id() RETURNING {ORG_COLS}",
        (body.name,), table="organizations", row_id=org_id, what="Organization"))


# ------------------------------------------------------------------ members
class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str | None
    display_name: str | None   # None while invited (see MEMBER_SELECT)
    role: str
    status: MemberStatus
    invited_by: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class MemberInvite(StrictModel):
    email: text(320, min_length=3)
    role: text(64) = "employee"

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        v = v.lower()
        if not EMAIL_RE.fullmatch(v):
            raise ValueError("invalid email address")
        return v


class MemberUpdate(StrictModel):
    role: text(64) = None                          # explicit null -> 422
    # invited -> active is the invitee's decision (POST /me/invitations/...);
    # removal is DELETE. The DB enforces both; the type documents them.
    status: Literal["active", "suspended"] = None


# A derived table, so paginate() can append "(created_at, id) < ..." unambiguously.
# display_name is withheld while a membership is only 'invited'. Otherwise an
# existing account would show its real name and a fresh pending identity its
# email local part, which would tell the inviter whether the address already
# had an account.
MEMBER_SELECT = """SELECT * FROM (
    SELECT m.id, m.user_id, u.email,
           CASE WHEN m.status = 'invited' THEN NULL ELSE u.display_name END AS display_name,
           r.key AS role, m.status, m.invited_by, m.created_at, m.updated_at
    FROM secureai.organization_memberships m
    JOIN secureai.roles r ON r.id = m.role_id
    LEFT JOIN secureai.users u ON u.id = m.user_id) AS mm"""


def _member_out(row: dict[str, Any]) -> MemberOut:
    return MemberOut(**{k: v for k, v in row.items() if k != "id"})


def _member(conn, user_id: uuid.UUID) -> MemberOut:
    return _member_out(fetch_one(conn, MEMBER_SELECT + " WHERE user_id = %s", (user_id,), "Member"))


def _member_status(conn, user_id: uuid.UUID) -> str | None:
    """The member's status if the caller can see the row, else None."""
    row = conn.execute("SELECT status FROM secureai.organization_memberships WHERE user_id = %s",
                       (user_id,)).fetchone()
    return row[0] if row else None


def _role_id(conn, key: str) -> uuid.UUID:
    """The role catalogue is public reference data, so an unknown key can be a plain 422."""
    row = conn.execute("SELECT id FROM secureai.roles WHERE key = %s", (key,)).fetchone()
    if row is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "Unknown role")
    return row[0]


def _member_write(conn, query: Any, params: list[Any], user_id: uuid.UUID) -> None:
    """UPDATE ... RETURNING on a membership: 0 rows -> 403 if visible, else 404."""
    if conn.execute(query, params).fetchone() is not None:
        return
    if _member_status(conn, user_id) is not None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
    raise not_found("Member")


@router.get("/members", response_model=Page[MemberOut])
def list_members(conn: OrgConn, page: Paging,
                 status_: Annotated[MemberStatus | None, Query(alias="status")] = None):
    where, params = [], []
    if status_ is not None:
        where.append("status = %s")
        params.append(status_)
    return paginate(conn, MEMBER_SELECT, where, params, page, _member_out)


@router.get("/members/{user_id}", response_model=MemberOut)
def get_member(conn: OrgConn, user_id: uuid.UUID) -> MemberOut:
    return _member(conn, user_id)


@router.post("/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
def invite_member(conn: OrgConn, state: State, claims: Claims, body: MemberInvite) -> MemberOut:
    """Invite by email. Existing and unknown addresses get the same response."""
    state.limiter.hit("invite", str(claims.user_id), INVITES_PER_HOUR, 3600)
    role_id = _role_id(conn, body.role)
    # Raises 42501 (-> 403) without user.create. For an unknown address it creates a
    # pending identity inside THIS transaction, so a refused INSERT below rolls it back.
    user_id = conn.execute("SELECT secureai_auth.resolve_invitee(%s)", (body.email,)).fetchone()[0]
    try:
        with conn.transaction():   # savepoint: keep the transaction usable on conflict
            conn.execute(
                "INSERT INTO secureai.organization_memberships "
                "(organization_id, user_id, role_id, status, invited_by) VALUES "
                "(secureai_rls.current_org_id(), %s, %s, 'invited', secureai_rls.current_user_id())",
                (user_id, role_id))
    except errors.UniqueViolation:
        # Already has a membership row in this org. Only a removed member can
        # be invited again (memberships_update decides whether I may).
        if _member_status(conn, user_id) != "removed":
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "Already a member of this organization") from None
        _member_write(conn, "UPDATE secureai.organization_memberships "
                            "SET status = 'invited', role_id = %s WHERE user_id = %s RETURNING id",
                      [role_id, user_id], user_id)

    org_name = conn.execute("SELECT name FROM secureai.organizations "
                            "WHERE id = secureai_rls.current_org_id()").fetchone()[0]
    state.mailer.send_invitation(body.email, org_name, invitations_link(state.settings.public_url))
    return _member(conn, user_id)


@router.patch("/members/{user_id}", response_model=MemberOut)
def update_member(conn: OrgConn, user_id: uuid.UUID, body: MemberUpdate) -> MemberOut:
    values = patch_values(body)
    if "role" in values:
        values = {"role_id": _role_id(conn, values.pop("role")), **values}
    query = sql.SQL("UPDATE secureai.organization_memberships SET {} "
                    "WHERE user_id = %s RETURNING id").format(
        sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(k)) for k in values))
    _member_write(conn, query, [*values.values(), user_id], user_id)
    return _member(conn, user_id)


@router.delete("/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(conn: OrgConn, user_id: uuid.UUID) -> Response:
    # A status change, not a DELETE: the row anchors the member's tasks,
    # projects and documents (composite FKs) and the audit trail.
    _member_write(conn, "UPDATE secureai.organization_memberships SET status = 'removed' "
                        "WHERE user_id = %s RETURNING id", [user_id], user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ overrides
class OverrideOut(BaseModel):
    permission: str
    effect: Literal["grant", "deny"]
    reason: str
    expires_at: datetime | None
    active: bool
    created_by: uuid.UUID | None
    created_at: datetime


class OverrideSet(StrictModel):
    effect: Literal["grant", "deny"]
    reason: text(500, min_length=3)
    expires_at: AwareDatetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _future(cls, v: datetime | None) -> datetime | None:
        if v is not None and v <= datetime.now(UTC):
            raise ValueError("expires_at must be in the future")
        return v


OVERRIDE_SELECT = (
    "SELECT p.code AS permission, o.effect, o.reason, o.expires_at, "
    "(o.expires_at IS NULL OR o.expires_at > now()) AS active, o.created_by, o.created_at "
    "FROM secureai.user_permission_overrides o "
    "JOIN secureai.permissions p ON p.id = o.permission_id ")


def _permission_id(conn, code: str) -> uuid.UUID:
    row = conn.execute("SELECT id FROM secureai.permissions WHERE code = %s", (code,)).fetchone()
    if row is None:
        raise not_found("Permission")
    return row[0]


def _require_visible_member(conn, user_id: uuid.UUID) -> None:
    if _member_status(conn, user_id) is None:
        raise not_found("Member")


@router.get("/members/{user_id}/overrides", response_model=list[OverrideOut])
def list_overrides(conn: OrgConn, user_id: uuid.UUID) -> list[OverrideOut]:
    """Without permission.manage this is empty for anyone but yourself (overrides_select)."""
    _require_visible_member(conn, user_id)
    rows = conn.cursor(row_factory=dict_row).execute(
        OVERRIDE_SELECT + "WHERE o.user_id = %s ORDER BY p.code", (user_id,)).fetchall()
    return [OverrideOut(**r) for r in rows]


@router.put("/members/{user_id}/overrides/{permission}", response_model=OverrideOut)
def set_override(conn: OrgConn, user_id: uuid.UUID, permission: PermissionCode,
                 body: OverrideSet) -> OverrideOut:
    """Create or replace. Insert and update are both checked by RLS, including
    "a grant needs the grantor to hold the permission"; a refusal raises 42501 -> 403."""
    _require_visible_member(conn, user_id)
    perm_id = _permission_id(conn, permission)
    conn.execute(
        "INSERT INTO secureai.user_permission_overrides "
        "(organization_id, user_id, permission_id, effect, reason, created_by, expires_at) "
        "VALUES (secureai_rls.current_org_id(), %s, %s, %s, %s, secureai_rls.current_user_id(), %s) "
        "ON CONFLICT (organization_id, user_id, permission_id) DO UPDATE "
        "SET effect = EXCLUDED.effect, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at",
        (user_id, perm_id, body.effect, body.reason, body.expires_at))
    return OverrideOut(**fetch_one(
        conn, OVERRIDE_SELECT + "WHERE o.user_id = %s AND o.permission_id = %s",
        (user_id, perm_id), "Override"))


@router.delete("/members/{user_id}/overrides/{permission}", status_code=status.HTTP_204_NO_CONTENT)
def delete_override(conn: OrgConn, user_id: uuid.UUID, permission: PermissionCode) -> Response:
    _require_visible_member(conn, user_id)
    perm_id = _permission_id(conn, permission)
    if conn.execute("DELETE FROM secureai.user_permission_overrides "
                    "WHERE user_id = %s AND permission_id = %s RETURNING id",
                    (user_id, perm_id)).fetchone() is None:
        visible = conn.execute(
            "SELECT EXISTS (SELECT 1 FROM secureai.user_permission_overrides "
            "WHERE user_id = %s AND permission_id = %s)", (user_id, perm_id)).fetchone()[0]
        if visible:
            raise HTTPException(status.HTTP_403_FORBIDDEN, NOT_ALLOWED)
        raise not_found("Override")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
