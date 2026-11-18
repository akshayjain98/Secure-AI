"""Organization settings, members, invitations and permission overrides over HTTP.

Writes commit; tests/api/conftest.py restores seed memberships, roles, org
names and removes every override after each test.
Seed org A: akshay org_admin, rahul manager, priya employee, meera viewer.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.db.seed_dev import ID
from tests.api.conftest import CSRF, REFRESH_COOKIE, login

A, B = ID.org("org_a"), ID.org("org_b")
SEED_A = {"akshay": "org_admin", "rahul": "manager", "priya": "employee", "meera": "viewer"}


def org(o=A) -> str:
    return f"/orgs/{o}"


def member(user: str | uuid.UUID, o=A) -> str:
    uid = ID.user(user) if isinstance(user, str) else user
    return f"{org(o)}/members/{uid}"


def override(user: str, perm: str) -> str:
    return f"{member(user)}/overrides/{perm}"


def set_role(admin_conn, user: str, role: str, o=A) -> None:
    admin_conn.execute(
        "UPDATE secureai.organization_memberships SET role_id = (SELECT id FROM secureai.roles "
        "WHERE key = %s) WHERE organization_id = %s AND user_id = %s", (role, o, ID.user(user)))


def fresh_email() -> str:
    return f"invitee-{uuid.uuid4().hex[:12]}@invite.example"


def perms(client, headers) -> set[str]:
    r = client.get("/me", headers={**headers, "X-Org-Id": str(A)})
    assert r.status_code == 200, r.text
    return set(r.json()["current_org"]["permissions"])


# ------------------------------------------------------------------ organization
def test_every_member_reads_the_org(client, auth_as):
    for user in SEED_A:
        r = client.get(org(), headers=auth_as(user))
        assert r.status_code == 200, (user, r.text)
        assert r.json()["slug"] == "asteria-labs"
    assert client.get(org(B), headers=auth_as("priya")).status_code == 403


def test_only_organization_update_may_rename(client, auth_as):
    r = client.patch(org(), headers=auth_as("akshay"), json={"name": "Asteria Labs Ltd"})
    assert r.status_code == 200 and r.json()["name"] == "Asteria Labs Ltd"
    for user in ("rahul", "priya", "meera"):
        r = client.patch(org(), headers=auth_as(user), json={"name": "Hijacked"})
        assert r.status_code == 403 and r.json() == {"detail": "Not allowed"}, user
    assert client.get(org(), headers=auth_as("priya")).json()["name"] == "Asteria Labs Ltd"


@pytest.mark.parametrize("body", [{"slug": "new-slug"}, {"status": "suspended"},
                                  {"name": "x", "id": str(B)}, {"name": ""}, {}])
def test_org_patch_is_name_only(client, auth_as, body):
    assert client.patch(org(), headers=auth_as("akshay"), json=body).status_code == 422


def test_admin_cannot_rename_another_tenant(client, auth_as):
    assert client.patch(org(B), headers=auth_as("akshay"), json={"name": "Mine"}).status_code == 403


# ------------------------------------------------------------------ member listing
def roles_listed(client, headers) -> dict[str, str]:
    r = client.get(f"{org()}/members", headers=headers, params={"limit": 100})
    assert r.status_code == 200, r.text
    return {i["user_id"]: i["role"] for i in r.json()["items"]}


def test_directory_is_exactly_what_rls_allows(client, auth_as):
    everyone = {str(ID.user(u)): role for u, role in SEED_A.items()}
    assert roles_listed(client, auth_as("akshay")) == everyone
    assert roles_listed(client, auth_as("priya")) == everyone            # user.read
    # A viewer has no user.read: only their own row.
    assert roles_listed(client, auth_as("meera")) == {str(ID.user("meera")): "viewer"}


def test_hidden_and_foreign_members_are_404(client, auth_as):
    meera = auth_as("meera")
    assert client.get(member("priya"), headers=meera).status_code == 404
    assert client.get(member("meera"), headers=meera).status_code == 200
    akshay = auth_as("akshay")
    assert client.get(member("john"), headers=akshay).status_code == 404     # other tenant
    assert client.get(member(uuid.uuid4()), headers=akshay).status_code == 404


def test_member_pagination_and_status_filter(client, auth_as):
    akshay, seen, cursor = auth_as("akshay"), set(), None
    for _ in range(10):
        r = client.get(f"{org()}/members", headers=akshay,
                       params={"limit": 1, **({"cursor": cursor} if cursor else {})})
        seen |= {i["user_id"] for i in r.json()["items"]}
        if not (cursor := r.json()["next_cursor"]):
            break
    assert seen == {str(ID.user(u)) for u in SEED_A}
    r = client.get(f"{org()}/members", headers=akshay, params={"status": "invited"})
    assert r.json()["items"] == []


# ------------------------------------------------------------------ invitations
def invite(client, headers, email, role="employee"):
    return client.post(f"{org()}/members", headers=headers, json={"email": email, "role": role})


def test_invite_existing_user_then_accept(client, auth_as, outbox):
    """David (org B) is invited to org A; he has no access until he accepts."""
    akshay, david = auth_as("akshay"), auth_as("david")
    r = invite(client, akshay, "David@Borealis.example")
    assert r.status_code == 201, r.text
    assert r.json() | {"created_at": None, "updated_at": None} == {
        "user_id": str(ID.user("david")), "email": "david@borealis.example", "display_name": None,
        "role": "employee", "status": "invited", "invited_by": str(ID.user("akshay")),
        "created_at": None, "updated_at": None}
    assert outbox.sent[-1] == ("invite", "david@borealis.example", "https://app.example/invitations")

    assert client.get(f"{org()}/projects", headers=david).status_code == 403
    inv = client.get("/me/invitations", headers=david).json()
    assert [(i["organization_id"], i["organization_name"], i["role"]) for i in inv] == [
        (str(A), "Asteria Labs", "employee")]

    assert client.post(f"/me/invitations/{A}/accept", headers=david).status_code == 204
    assert client.get(f"{org()}/projects", headers=david).status_code == 200
    assert client.get(member("david"), headers=akshay).json()["display_name"] == "David"
    assert client.get("/me/invitations", headers=david).json() == []
    assert client.post(f"/me/invitations/{A}/accept", headers=david).status_code == 404


def test_existing_and_unknown_addresses_get_the_same_answer(client, auth_as, admin_conn):
    """No account enumeration through invites: same status, same shape, no name."""
    akshay = auth_as("akshay")
    known = invite(client, akshay, "john@borealis.example")
    unknown_email = fresh_email()
    unknown = invite(client, akshay, unknown_email)
    assert known.status_code == unknown.status_code == 201
    strip = lambda j: {k: v for k, v in j.items() if k not in ("user_id", "email", "created_at", "updated_at")}  # noqa: E731
    assert strip(known.json()) == strip(unknown.json())
    # The unknown address became a pending, passwordless identity.
    row = admin_conn.execute(
        "SELECT u.status, c.user_id IS NULL FROM secureai.users u "
        "LEFT JOIN secureai.user_credentials c ON c.user_id = u.id WHERE u.email = %s",
        (unknown_email,)).fetchone()
    assert row == ("pending", True)


def test_invited_new_user_registers_then_accepts(client, auth_as, outbox):
    email = fresh_email()
    assert invite(client, auth_as("akshay"), email, role="viewer").status_code == 201
    # The address owner sets the password through the normal verify flow.
    assert client.post("/auth/register", json={"email": email, "display_name": "New Person"}
                       ).status_code == 202
    kind, to, link = outbox.sent[-1]
    assert (kind, to) == ("verify", email)
    password = "an-invitee-long-passphrase"
    assert client.post("/auth/verify-email", json={"token": link.split("#token=")[1],
                                                   "password": password}).status_code == 204
    headers = login(client, email, password)
    assert client.post(f"/me/invitations/{A}/accept", headers=headers).status_code == 204
    me = client.get("/me", headers={**headers, "X-Org-Id": str(A)}).json()
    assert me["current_org"]["role"] == "viewer"


def test_decline_then_invite_again(client, auth_as):
    akshay, david = auth_as("akshay"), auth_as("david")
    assert invite(client, akshay, "david@borealis.example").status_code == 201
    assert client.post(f"/me/invitations/{A}/decline", headers=david).status_code == 204
    assert client.get(member("david"), headers=akshay).json()["status"] == "removed"
    again = invite(client, akshay, "david@borealis.example", role="viewer")
    assert again.status_code == 201 and again.json()["status"] == "invited"
    assert again.json()["role"] == "viewer"


def test_cannot_accept_someone_elses_invitation(client, auth_as):
    assert invite(client, auth_as("akshay"), "david@borealis.example").status_code == 201
    # Meera is in org A already; John has no invitation; neither can touch David's.
    assert client.post(f"/me/invitations/{A}/accept", headers=auth_as("john")).status_code == 404
    assert client.post(f"/me/invitations/{B}/accept", headers=auth_as("meera")).status_code == 404
    assert client.get("/me/invitations", headers=auth_as("john")).json() == []


def test_admin_cannot_activate_an_invite_or_a_removed_member(client, auth_as):
    """Consent: only the invitee turns 'invited' into 'active'."""
    akshay = auth_as("akshay")
    assert invite(client, akshay, "david@borealis.example").status_code == 201
    r = client.patch(member("david"), headers=akshay, json={"status": "active"})
    assert r.status_code == 403
    assert r.json() == {"detail": "Membership status cannot change from invited to active"}

    assert client.delete(member("priya"), headers=akshay).status_code == 204
    r = client.patch(member("priya"), headers=akshay, json={"status": "active"})
    assert r.status_code == 403 and "removed to active" in r.json()["detail"]


@pytest.mark.parametrize("user", ["rahul", "priya", "meera"])
def test_invite_needs_user_create(client, auth_as, admin_conn, user):
    email = fresh_email()
    r = invite(client, auth_as(user), email)
    assert r.status_code == 403 and r.json() == {"detail": "Not allowed to invite members"}
    assert admin_conn.execute("SELECT count(*) FROM secureai.users WHERE email = %s",
                              (email,)).fetchone()[0] == 0


def test_refused_invite_rolls_back_the_pending_identity(client, auth_as, admin_conn):
    """resolve_invitee creates the pending user, then RLS refuses super_admin
    (not assignable). The whole transaction, user included, must roll back."""
    email = fresh_email()
    r = invite(client, auth_as("akshay"), email, role="super_admin")
    assert r.status_code == 403 and r.json() == {"detail": "Not allowed"}
    assert admin_conn.execute("SELECT count(*) FROM secureai.users WHERE email = %s",
                              (email,)).fetchone()[0] == 0


def test_invite_conflicts_and_validation(client, auth_as):
    akshay = auth_as("akshay")
    r = invite(client, akshay, "priya@asteria.example")
    assert r.status_code == 409 and r.json() == {"detail": "Already a member of this organization"}
    assert invite(client, akshay, fresh_email(), role="overlord").status_code == 422
    assert invite(client, akshay, "not-an-email").status_code == 422
    for extra in ({"status": "active"}, {"user_id": str(ID.user("john"))},
                  {"organization_id": str(B)}, {"invited_by": str(ID.user("priya"))}):
        r = client.post(f"{org()}/members", headers=akshay,
                        json={"email": fresh_email(), "role": "employee", **extra})
        assert r.status_code == 422, extra


# ------------------------------------------------------------------ roles, rank, self
def test_admin_changes_role_and_it_applies_on_the_next_request(client, auth_as):
    akshay, priya = auth_as("akshay"), auth_as("priya")
    assert "project.create" not in perms(client, priya)
    r = client.patch(member("priya"), headers=akshay, json={"role": "manager"})
    assert r.status_code == 200 and r.json()["role"] == "manager"
    assert "project.create" in perms(client, priya)


def test_non_admins_cannot_change_members(client, auth_as):
    for user in ("rahul", "priya"):     # both can see the directory
        r = client.patch(member("meera"), headers=auth_as(user), json={"role": "employee"})
        assert r.status_code == 403, user
        assert client.delete(member("meera"), headers=auth_as(user)).status_code == 403
    # Meera can't see Priya's row at all.
    assert client.patch(member("priya"), headers=auth_as("meera"),
                        json={"role": "viewer"}).status_code == 404


def test_nobody_edits_their_own_membership(client, auth_as):
    for user, role in (("akshay", "super_admin"), ("akshay", "viewer"), ("priya", "org_admin")):
        r = client.patch(member(user), headers=auth_as(user), json={"role": role})
        assert r.status_code == 403, (user, role)
    assert client.delete(member("akshay"), headers=auth_as("akshay")).status_code == 403


def test_rank_rules(client, auth_as, admin_conn):
    akshay = auth_as("akshay")
    # Can't hand out a role above your own, nor the non-assignable super_admin.
    assert client.patch(member("priya"), headers=akshay, json={"role": "super_admin"}).status_code == 403
    # Can't touch a member who outranks you.
    set_role(admin_conn, "meera", "super_admin")
    for call in (lambda: client.patch(member("meera"), headers=akshay, json={"role": "viewer"}),
                 lambda: client.patch(member("meera"), headers=akshay, json={"status": "suspended"}),
                 lambda: client.delete(member("meera"), headers=akshay)):
        assert call().status_code == 403


def test_member_patch_validation(client, auth_as):
    akshay = auth_as("akshay")
    for body in ({}, {"role": None}, {"status": "removed"}, {"status": "invited"},
                 {"role": "employee", "user_id": str(ID.user("akshay"))},
                 {"organization_id": str(B)}):
        assert client.patch(member("priya"), headers=akshay, json=body).status_code == 422, body


# ------------------------------------------------------------------ last admin
@pytest.mark.parametrize("api_action", ["demote", "remove"])
def test_racing_admins_cannot_leave_zero_admins(client, auth_as, admin_conn, new_app_conn,
                                                api_action):
    """Two admins remove each other at the same moment. Each passes RLS (each
    still sees itself as admin); the last-admin trigger serialises them and the
    API maps the loser to 409. Sequentially this can't happen at all: the
    policy forbids self-edits and the first change strips the second actor."""
    set_role(admin_conn, "rahul", "org_admin")

    side = new_app_conn(autocommit=False)        # Rahul demotes Akshay, holds the org lock
    side.execute("SELECT secureai_rls.set_context(%s, %s)", (ID.user("rahul"), A))
    assert side.execute(
        "UPDATE secureai.organization_memberships SET role_id = (SELECT id FROM secureai.roles "
        "WHERE key = 'employee') WHERE user_id = %s", (ID.user("akshay"),)).rowcount == 1

    akshay, result = auth_as("akshay"), {}

    def akshay_acts():
        if api_action == "demote":
            result["r"] = client.patch(member("rahul"), headers=akshay, json={"role": "manager"})
        else:
            result["r"] = client.delete(member("rahul"), headers=akshay)

    t = threading.Thread(target=akshay_acts)
    t.start()
    deadline = time.monotonic() + 5
    while not admin_conn.execute("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE NOT granted "
                                 "AND locktype = 'advisory')").fetchone()[0]:
        assert time.monotonic() < deadline, "API request never waited for the org lock"
        time.sleep(0.02)
    side.commit()
    t.join(timeout=10)

    r = result["r"]
    assert r.status_code == 409
    assert r.json() == {"detail": "An organization must keep at least one active administrator"}
    assert roles_listed(client, auth_as("rahul"))[str(ID.user("rahul"))] == "org_admin"


# ------------------------------------------------------------------ logout on removal
def refresh(c) -> int:
    return c.post("/auth/refresh", headers=CSRF).status_code


def session_state(admin_conn, user: str, since: datetime) -> tuple[int, set[str | None]]:
    """(active sessions overall, revoke reasons of sessions created since `since`)."""
    active = admin_conn.execute(
        "SELECT count(*) FROM secureai.refresh_token_sessions WHERE user_id = %s "
        "AND status = 'active'", (ID.user(user),)).fetchone()[0]
    reasons = {r[0] for r in admin_conn.execute(
        "SELECT revoked_reason FROM secureai.refresh_token_sessions WHERE user_id = %s "
        "AND created_at >= %s", (ID.user(user), since)).fetchall()}
    return active, reasons


@pytest.mark.parametrize("action", ["remove", "suspend"])
def test_removal_or_suspension_ends_the_members_sessions(new_client, auth_as, admin_conn, action):
    admin, victim = new_client(), new_client()
    since = admin_conn.execute("SELECT now()").fetchone()[0]
    priya = login(victim, "priya@asteria.example")
    assert victim.cookies.get(REFRESH_COOKIE)
    assert victim.get(f"{org()}/projects", headers=priya).status_code == 200

    akshay = auth_as("akshay")
    if action == "remove":
        assert admin.delete(member("priya"), headers=akshay).status_code == 204
    else:
        assert admin.patch(member("priya"), headers=akshay,
                           json={"status": "suspended"}).status_code == 200

    # Org access ends on the very next request (set_context), the refresh
    # session is revoked, and nothing is left active.
    r = victim.get(f"{org()}/projects", headers=priya)
    assert r.status_code == 403 and r.json() == {"detail": "No access to this organization"}
    assert refresh(victim) == 401
    assert session_state(admin_conn, "priya", since) == (0, {"membership_revoked"})


def test_role_change_keeps_sessions_and_reinstatement_works(new_client, auth_as, admin_conn):
    admin, victim = new_client(), new_client()
    login(victim, "priya@asteria.example")
    akshay = auth_as("akshay")
    assert admin.patch(member("priya"), headers=akshay, json={"role": "viewer"}).status_code == 200
    assert refresh(victim) == 200            # permissions are live; no logout needed

    assert admin.patch(member("priya"), headers=akshay, json={"status": "suspended"}).status_code == 200
    assert refresh(victim) == 401
    assert admin.patch(member("priya"), headers=akshay, json={"status": "active"}).status_code == 200
    priya = login(victim, "priya@asteria.example")
    assert victim.get(f"{org()}/projects", headers=priya).status_code == 200


# ------------------------------------------------------------------ overrides
def put_override(client, headers, user, perm, effect="grant", **extra):
    return client.put(override(user, perm), headers=headers,
                      json={"effect": effect, "reason": "test override", **extra})


def test_grant_and_deny_take_effect_on_the_next_request(client, auth_as):
    akshay, priya = auth_as("akshay"), auth_as("priya")
    assert "audit.read" not in perms(client, priya)
    r = put_override(client, akshay, "priya", "audit.read")
    assert r.status_code == 200 and r.json()["active"] is True
    assert "audit.read" in perms(client, priya)

    assert put_override(client, akshay, "priya", "task.read", "deny").status_code == 200
    assert "task.read" not in perms(client, priya)
    assert client.get(f"{org()}/tasks", headers=priya).json()["items"] == []

    assert client.delete(override("priya", "task.read"), headers=akshay).status_code == 204
    assert client.get(f"{org()}/tasks", headers=priya).json()["items"] != []
    assert client.delete(override("priya", "task.read"), headers=akshay).status_code == 404


def test_put_replaces_an_existing_override(client, auth_as):
    akshay = auth_as("akshay")
    put_override(client, akshay, "priya", "audit.read")
    r = put_override(client, akshay, "priya", "audit.read", "deny")
    assert r.status_code == 200 and r.json()["effect"] == "deny"
    listed = client.get(f"{member('priya')}/overrides", headers=akshay).json()
    assert [(o["permission"], o["effect"]) for o in listed] == [("audit.read", "deny")]


def test_override_visibility(client, auth_as):
    put_override(client, auth_as("akshay"), "priya", "audit.read")
    url = f"{member('priya')}/overrides"
    assert len(client.get(url, headers=auth_as("priya")).json()) == 1     # own overrides
    assert client.get(url, headers=auth_as("rahul")).json() == []        # no permission.manage
    assert client.get(url, headers=auth_as("meera")).status_code == 404   # member hidden
    # Rahul can't delete what he can't see.
    assert client.delete(override("priya", "audit.read"), headers=auth_as("rahul")).status_code == 404


def test_you_cannot_delegate_what_you_do_not_hold(client, auth_as, admin_conn):
    """Rahul (manager) is given permission.manage. He may grant what he holds,
    deny anything to lower ranks, but not grant audit.read, which he lacks."""
    assert put_override(client, auth_as("akshay"), "rahul", "permission.manage").status_code == 200
    rahul = auth_as("rahul")
    assert put_override(client, rahul, "priya", "project.create").status_code == 200
    assert put_override(client, rahul, "priya", "audit.read").status_code == 403
    assert put_override(client, rahul, "priya", "audit.read", "deny").status_code == 200
    # Upgrading that deny to a grant is the same delegation, so also refused.
    assert put_override(client, rahul, "priya", "audit.read", "grant").status_code == 403
    # Rank: Akshay outranks Rahul.
    assert put_override(client, rahul, "akshay", "task.read", "deny").status_code == 403


def test_override_refusals(client, auth_as):
    assert put_override(client, auth_as("akshay"), "akshay", "audit.read").status_code == 403   # self
    assert put_override(client, auth_as("priya"), "meera", "task.read").status_code == 403      # no perm
    akshay = auth_as("akshay")
    assert put_override(client, akshay, "john", "task.read").status_code == 404           # other tenant
    assert put_override(client, akshay, "priya", "task.reed").status_code == 404          # unknown perm
    assert put_override(client, akshay, "priya", "DROP TABLE").status_code == 422


@pytest.mark.parametrize("body", [
    {"effect": "grant", "reason": "ok reason", "expires_at": "2020-01-01T00:00:00Z"},     # past
    {"effect": "grant", "reason": "ok reason", "expires_at": "2099-01-01T00:00:00"},      # naive
    {"effect": "allow", "reason": "ok reason"},
    {"effect": "grant", "reason": "no"},
    {"effect": "grant", "reason": "ok reason", "created_by": str(ID.user("priya"))},
    {"effect": "grant", "reason": "ok reason", "user_id": str(ID.user("meera"))},
])
def test_override_body_validation(client, auth_as, body):
    assert client.put(override("priya", "audit.read"), headers=auth_as("akshay"),
                      json=body).status_code == 422


def test_override_expiry(client, auth_as, admin_conn):
    akshay, priya = auth_as("akshay"), auth_as("priya")
    soon = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    r = put_override(client, akshay, "priya", "audit.read", expires_at=soon)
    assert r.status_code == 200 and r.json()["active"] is True
    assert "audit.read" in perms(client, priya)
    # Let it lapse (backdate as ops; the API refuses past expiry times).
    admin_conn.execute(
        "UPDATE secureai.user_permission_overrides SET created_at = now() - interval '2 hours', "
        "expires_at = now() - interval '1 second' WHERE user_id = %s", (ID.user("priya"),))
    assert "audit.read" not in perms(client, priya)
    listed = client.get(f"{member('priya')}/overrides", headers=akshay).json()
    assert [(o["permission"], o["active"]) for o in listed] == [("audit.read", False)]
