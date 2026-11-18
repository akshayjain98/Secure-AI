"""Projects and project membership, under /orgs/{org_id}.

No authorization logic lives here. The handlers issue plain SQL, and Phase 1's
policies decide:
  read   project.read  AND (owner OR member OR project.read_all)
  create project.create AND owner = me
  update project.update AND I manage it (owner or lead)
  delete project.delete AND I own it; RESTRICT FKs refuse a non-empty project
  members: managers add/change/remove; leads can't touch their own row;
           anyone may leave.
The handlers only turn the outcome into the right status code.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Response, status
from psycopg import errors, sql
from psycopg.rows import dict_row
from pydantic import BaseModel

from app.api.deps import OrgConn
from app.api.models import StrictModel, patch_values, text
from app.api.pagination import Page, Paging, paginate
from app.api.rows import fetch_one, not_found, write_or_404

router = APIRouter(prefix="/orgs/{org_id}/projects", tags=["projects"])

ProjectStatus = Literal["active", "archived"]
ProjectRole = Literal["lead", "member"]
Name = text(200)
Description = text(5000, min_length=0)

PROJECT_COLS = "id, owner_id, name, description, status, created_at, updated_at"


class ProjectOut(BaseModel):
    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    description: str | None
    status: ProjectStatus
    created_at: datetime
    updated_at: datetime


class ProjectCreate(StrictModel):
    name: Name
    description: Description | None = None


class ProjectUpdate(StrictModel):
    name: Name = None              # explicit null -> 422 (see app/api/models.py)
    description: Description | None = None
    status: ProjectStatus = None


class MemberOut(BaseModel):
    user_id: uuid.UUID
    display_name: str | None      # None when the caller lacks user.read (directory hidden)
    project_role: ProjectRole
    created_at: datetime


class MemberAdd(StrictModel):
    user_id: uuid.UUID
    project_role: ProjectRole = "member"


class MemberUpdate(StrictModel):
    project_role: ProjectRole


def _project(row: dict[str, Any]) -> ProjectOut:
    return ProjectOut(**row)


def require_visible_project(conn, project_id: uuid.UUID) -> None:
    """404 unless the caller can see the project (exists in this org AND passes RLS)."""
    fetch_one(conn, "SELECT id FROM secureai.projects WHERE id = %s", (project_id,), "Project")


# ------------------------------------------------------------------ projects
@router.get("", response_model=Page[ProjectOut])
def list_projects(conn: OrgConn, page: Paging,
                  status_: Annotated[ProjectStatus | None, Query(alias="status")] = None):
    where, params = [], []
    if status_ is not None:
        where.append("status = %s")
        params.append(status_)
    return paginate(conn, f"SELECT {PROJECT_COLS} FROM secureai.projects", where, params,
                    page, _project)


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(conn: OrgConn, body: ProjectCreate) -> ProjectOut:
    # Tenant and owner come from the RLS context, never from the request.
    row = conn.cursor(row_factory=dict_row).execute(
        "INSERT INTO secureai.projects (organization_id, owner_id, name, description) "
        "VALUES (secureai_rls.current_org_id(), secureai_rls.current_user_id(), %s, %s) "
        f"RETURNING {PROJECT_COLS}", (body.name, body.description)).fetchone()
    return _project(row)


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(conn: OrgConn, project_id: uuid.UUID) -> ProjectOut:
    return _project(fetch_one(conn, f"SELECT {PROJECT_COLS} FROM secureai.projects WHERE id = %s",
                              (project_id,), "Project"))


@router.patch("/{project_id}", response_model=ProjectOut)
def update_project(conn: OrgConn, project_id: uuid.UUID, body: ProjectUpdate) -> ProjectOut:
    values = patch_values(body)
    query = sql.SQL("UPDATE secureai.projects SET {} WHERE id = %s RETURNING {}").format(
        sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(k)) for k in values),
        sql.SQL(PROJECT_COLS))
    return _project(write_or_404(conn, query, [*values.values(), project_id],
                                 table="projects", row_id=project_id, what="Project"))


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(conn: OrgConn, project_id: uuid.UUID) -> Response:
    try:
        write_or_404(conn, "DELETE FROM secureai.projects WHERE id = %s RETURNING id",
                     (project_id,), table="projects", row_id=project_id, what="Project")
    except errors.ForeignKeyViolation:
        # Tasks/documents reference it (ON DELETE RESTRICT). Note: this also
        # counts rows the caller can't see; FK checks don't apply RLS. The owner
        # learns only "something still references my project", not what.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Project still has tasks or documents; archive it instead") from None
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------------------------------ members
MEMBER_SELECT = (
    "SELECT pm.user_id, u.display_name, pm.project_role, pm.created_at "
    "FROM secureai.project_members pm "
    # LEFT JOIN: users' RLS hides the directory from callers without user.read.
    "LEFT JOIN secureai.users u ON u.id = pm.user_id "
)


@router.get("/{project_id}/members", response_model=list[MemberOut])
def list_members(conn: OrgConn, project_id: uuid.UUID) -> list[MemberOut]:
    require_visible_project(conn, project_id)
    rows = conn.cursor(row_factory=dict_row).execute(
        MEMBER_SELECT + "WHERE pm.project_id = %s ORDER BY pm.created_at, pm.user_id",
        (project_id,)).fetchall()
    return [MemberOut(**r) for r in rows]


def _member(conn, project_id: uuid.UUID, user_id: uuid.UUID) -> MemberOut:
    return MemberOut(**fetch_one(conn, MEMBER_SELECT + "WHERE pm.project_id = %s AND pm.user_id = %s",
                                 (project_id, user_id), "Member"))


@router.post("/{project_id}/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
def add_member(conn: OrgConn, project_id: uuid.UUID, body: MemberAdd) -> MemberOut:
    require_visible_project(conn, project_id)
    try:
        # A savepoint, so a failed insert leaves the transaction usable for the
        # follow-up read. Errors are still turned into responses below.
        with conn.transaction():
            conn.execute(
                "INSERT INTO secureai.project_members "
                "(organization_id, project_id, user_id, project_role, added_by) "
                "VALUES (secureai_rls.current_org_id(), %s, %s, %s, secureai_rls.current_user_id())",
                (project_id, body.user_id, body.project_role))
    except errors.ForeignKeyViolation:
        # Reached only after the WITH CHECK passed, i.e. by a project manager.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT,
                            "User is not a member of this organization") from None
    except errors.UniqueViolation:
        raise HTTPException(status.HTTP_409_CONFLICT, "Already a project member") from None
    return _member(conn, project_id, body.user_id)


def _member_write(conn, query: str, project_id: uuid.UUID, user_id: uuid.UUID,
                  extra: tuple = ()) -> None:
    require_visible_project(conn, project_id)
    if conn.execute(query, (*extra, project_id, user_id)).fetchone() is not None:
        return
    exists = conn.execute(
        "SELECT EXISTS (SELECT 1 FROM secureai.project_members WHERE project_id = %s AND user_id = %s)",
        (project_id, user_id)).fetchone()[0]
    if exists:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed")
    raise not_found("Member")


@router.patch("/{project_id}/members/{user_id}", response_model=MemberOut)
def update_member(conn: OrgConn, project_id: uuid.UUID, user_id: uuid.UUID,
                  body: MemberUpdate) -> MemberOut:
    _member_write(conn, "UPDATE secureai.project_members SET project_role = %s "
                        "WHERE project_id = %s AND user_id = %s RETURNING user_id",
                  project_id, user_id, (body.project_role,))
    return _member(conn, project_id, user_id)


@router.delete("/{project_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(conn: OrgConn, project_id: uuid.UUID, user_id: uuid.UUID) -> Response:
    _member_write(conn, "DELETE FROM secureai.project_members "
                        "WHERE project_id = %s AND user_id = %s RETURNING user_id",
                  project_id, user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
