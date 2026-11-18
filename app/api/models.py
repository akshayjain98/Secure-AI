"""Request-model conventions shared by every resource endpoint.

* ``extra="forbid"``: unknown fields are a 422, not silently ignored. Mass
  assignment (sending ``owner_id``, ``organization_id``, ``project_id`` or
  ``role`` in a body and hoping the server copies it through) fails loudly.
  The column grants would refuse most of those anyway; this layer makes the
  refusal explicit and testable.
* Ownership and tenancy are never request fields. The server takes them from
  the RLS context: ``secureai_rls.current_user_id()`` and ``current_org_id()``.
* PATCH models type non-nullable fields WITHOUT ``| None`` but default them to
  None. Pydantic doesn't validate defaults, so an omitted field stays None and
  is skipped (``exclude_unset``), while an explicit ``null`` is a 422.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import HTTPException, status
from pydantic import BaseModel, ConfigDict, StringConstraints


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def text(max_length: int, min_length: int = 1) -> Any:
    return Annotated[str, StringConstraints(strip_whitespace=True, min_length=min_length,
                                            max_length=max_length)]


def patch_values(body: BaseModel) -> dict[str, Any]:
    values = body.model_dump(exclude_unset=True)
    if not values:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "No fields to update")
    return values
