"""GET /orgs/{org_id}/audit-logs: the organization's audit trail.

RLS (audit_logs_select) returns only rows of the context org, and only to
holders of audit.read. Auth events that have no org (logins, password
resets) are never listed here.

The has_permission() probe below only picks the status code. Without it a
caller lacking audit.read gets an empty page, which looks like "nothing
happened" rather than "you may not look". Removing the probe can't leak
anything: RLS still filters every row.

Rows are written by the database (migration 0007 triggers and the auth
definer functions), never by an API endpoint. There is no write route, and
the table is append-only even for BYPASSRLS roles.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from app.api.deps import OrgConn
from app.api.pagination import Page, Paging, paginate

router = APIRouter(prefix="/orgs/{org_id}/audit-logs", tags=["audit"])

Outcome = Literal["success", "denied", "failure", "error"]

AUDIT_COLS = ("id, occurred_at, actor_user_id, action, outcome, resource_type, resource_id, "
              "request_id, host(ip_address) AS ip_address, user_agent, metadata")


class AuditOut(BaseModel):
    id: uuid.UUID
    occurred_at: datetime
    actor_user_id: uuid.UUID | None
    action: str
    outcome: Outcome
    resource_type: str | None
    resource_id: uuid.UUID | None
    request_id: str | None
    ip_address: str | None
    user_agent: str | None
    metadata: dict[str, Any]


@router.get("", response_model=Page[AuditOut])
def list_audit_logs(
    conn: OrgConn, page: Paging,
    action: Annotated[str | None, Query(max_length=100, pattern=r"^[a-z_]+(\.[a-z_]+)*$")] = None,
    actor_id: uuid.UUID | None = None,
    resource_type: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_]+$")] = None,
    resource_id: uuid.UUID | None = None,
    outcome: Outcome | None = None,
):
    if not conn.execute("SELECT secureai_rls.has_permission('audit.read')").fetchone()[0]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed")
    where, params = [], []
    if action is not None:
        # "task" matches every task.* action; "task.update" matches exactly.
        where.append("(action = %s OR action LIKE %s)")
        params += [action, action.replace("_", r"\_") + ".%"]
    for col, val in (("actor_user_id", actor_id), ("resource_type", resource_type),
                     ("resource_id", resource_id), ("outcome", outcome)):
        if val is not None:
            where.append(f"{col} = %s")
            params.append(val)
    return paginate(conn, f"SELECT {AUDIT_COLS} FROM secureai.audit_logs", where, params, page,
                    lambda r: AuditOut(**r), ts="occurred_at")
