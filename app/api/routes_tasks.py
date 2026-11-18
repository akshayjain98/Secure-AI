"""Tasks, under /orgs/{org_id}.

Visibility rules come from Phase 1 RLS and the tasks_enforce_update_rules
trigger, not from this file:
  private  -> owner and assignee only (not managers, not admins)
  project  -> also project participants and holders of project.read_all
  only the owner may change visibility; only the owner or a project manager
  may reassign; the assignee must participate in the project.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Query, Response, status
from psycopg import sql
from psycopg.rows import dict_row
from pydantic import BaseModel

from app.api.deps import OrgConn
from app.api.models import StrictModel, patch_values, text
from app.api.pagination import Page, Paging, paginate
from app.api.routes_projects import require_visible_project
from app.api.rows import fetch_one, write_or_404

router = APIRouter(prefix="/orgs/{org_id}", tags=["tasks"])

TaskStatus = Literal["todo", "in_progress", "blocked", "done"]
Priority = Literal["low", "medium", "high", "urgent"]
Visibility = Literal["private", "project"]
Title = text(300)
Description = text(10000, min_length=0)

TASK_COLS = ("id, project_id, owner_id, assignee_id, title, description, status, priority, "
             "visibility, due_date, created_at, updated_at")


class TaskOut(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    owner_id: uuid.UUID
    assignee_id: uuid.UUID | None
    title: str
    description: str | None
    status: TaskStatus
    priority: Priority
    visibility: Visibility
    due_date: date | None
    created_at: datetime
    updated_at: datetime


class TaskCreate(StrictModel):
    title: Title
    description: Description | None = None
    status: TaskStatus = "todo"
    priority: Priority = "medium"
    visibility: Visibility = "private"   # secure default, same as the column default
    due_date: date | None = None
    assignee_id: uuid.UUID | None = None


class TaskUpdate(StrictModel):
    title: Title = None                  # explicit null -> 422 (see app/api/models.py)
    description: Description | None = None
    status: TaskStatus = None
    priority: Priority = None
    visibility: Visibility = None
    due_date: date | None = None
    assignee_id: uuid.UUID | None = None


def _task(row: dict[str, Any]) -> TaskOut:
    return TaskOut(**row)


@router.get("/tasks", response_model=Page[TaskOut])
def list_tasks(
    conn: OrgConn, page: Paging,
    project_id: uuid.UUID | None = None,
    status_: Annotated[TaskStatus | None, Query(alias="status")] = None,
    assigned_to_me: bool = False,
):
    # Filters only NARROW the RLS-filtered set; none of them can widen it.
    where, params = [], []
    if project_id is not None:
        where.append("project_id = %s")
        params.append(project_id)
    if status_ is not None:
        where.append("status = %s")
        params.append(status_)
    if assigned_to_me:
        where.append("assignee_id = secureai_rls.current_user_id()")
    return paginate(conn, f"SELECT {TASK_COLS} FROM secureai.tasks", where, params, page, _task)


@router.post("/projects/{project_id}/tasks", response_model=TaskOut,
             status_code=status.HTTP_201_CREATED)
def create_task(conn: OrgConn, project_id: uuid.UUID, body: TaskCreate) -> TaskOut:
    # 404 for a project the caller can't see (incl. another tenant's id);
    # after that, a WITH CHECK refusal (not a participant, no task.create,
    # assignee outside the project) is a 403.
    require_visible_project(conn, project_id)
    row = conn.cursor(row_factory=dict_row).execute(
        "INSERT INTO secureai.tasks (organization_id, project_id, owner_id, assignee_id, title, "
        "description, status, priority, visibility, due_date) "
        "VALUES (secureai_rls.current_org_id(), %s, secureai_rls.current_user_id(), "
        "%s, %s, %s, %s, %s, %s, %s) "
        f"RETURNING {TASK_COLS}",
        (project_id, body.assignee_id, body.title, body.description, body.status,
         body.priority, body.visibility, body.due_date)).fetchone()
    return _task(row)


@router.get("/tasks/{task_id}", response_model=TaskOut)
def get_task(conn: OrgConn, task_id: uuid.UUID) -> TaskOut:
    return _task(fetch_one(conn, f"SELECT {TASK_COLS} FROM secureai.tasks WHERE id = %s",
                           (task_id,), "Task"))


@router.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(conn: OrgConn, task_id: uuid.UUID, body: TaskUpdate) -> TaskOut:
    values = patch_values(body)
    query = sql.SQL("UPDATE secureai.tasks SET {} WHERE id = %s RETURNING {}").format(
        sql.SQL(", ").join(sql.SQL("{} = %s").format(sql.Identifier(k)) for k in values),
        sql.SQL(TASK_COLS))
    return _task(write_or_404(conn, query, [*values.values(), task_id],
                              table="tasks", row_id=task_id, what="Task"))


@router.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(conn: OrgConn, task_id: uuid.UUID) -> Response:
    write_or_404(conn, "DELETE FROM secureai.tasks WHERE id = %s RETURNING id", (task_id,),
                 table="tasks", row_id=task_id, what="Task")
    return Response(status_code=status.HTTP_204_NO_CONTENT)
