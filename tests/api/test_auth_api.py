"""HTTP-level tests for /auth and /me."""

from __future__ import annotations

import time
import uuid
from dataclasses import replace

import jwt
import pytest

from app.api.main import SECURITY_HEADERS
from app.auth.jwt_tokens import AccessTokenCodec
from app.db.seed_dev import ID
from tests.api.conftest import CSRF, JWT_KEYS, REFRESH_COOKIE, login

EMAIL = {k: f"{k}@{d}" for k, d in [
    ("akshay", "asteria.example"), ("priya", "asteria.example"),
    ("david", "borealis.example"), ("meera", "consulting.example")]}
GENERIC_LOGIN_ERROR = {"detail": "Invalid email or password"}


def claims_payload(**over):
    now = int(time.time())
    base = {"iss": "secureai", "aud": "secureai-api", "sub": str(ID.user("priya")),
            "sid": str(uuid.uuid4()), "iat": now, "nbf": now, "exp": now + 600, "jti": "x"}
    base.update(over)
    return base


def forge(payload=None, key=JWT_KEYS["k2"], headers=None, alg="HS256"):
    hdr = {"kid": "k2", "typ": "at+jwt"} if headers is None else headers
    return jwt.encode(payload or claims_payload(), key, algorithm=alg, headers=hdr)


# ------------------------------------------------------------------ login
def test_login_sets_hardened_refresh_cookie_and_security_headers(client):
    r = client.post("/auth/login", json={"email": EMAIL["priya"], "password": "test-only-password"})
    assert r.status_code == 200
    body = r.json()
    assert body["token_type"] == "Bearer" and body["expires_in"] == 600
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{REFRESH_COOKIE}=sart_")
    for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/auth"):
        assert attr.lower() in cookie.lower()
    assert "refresh" not in body  # never in the body, so JS can't read it
    for k, v in SECURITY_HEADERS.items():
        assert r.headers[k] == v


def test_all_login_failures_look_identical(client, make_user, admin_conn):
    locked = make_user()
    admin_conn.execute("UPDATE secureai.user_credentials SET failed_login_count = 5, "
                       "locked_until = now() + interval '10 minutes' WHERE user_id = %s", (locked.id,))
    disabled = make_user(status="disabled")
    attempts = [
        (EMAIL["priya"], "wrong-password-123"),
        ("nobody@nowhere.example", "whatever-password"),
        (locked.email, locked.password),        # correct password, but locked
        (disabled.email, disabled.password),    # correct password, but disabled
    ]
    for email, pw in attempts:
        r = client.post("/auth/login", json={"email": email, "password": pw})
        assert (r.status_code, r.json()) == (401, GENERIC_LOGIN_ERROR), email
        assert "set-cookie" not in r.headers


def test_login_rejects_unknown_fields(client):
    r = client.post("/auth/login", json={"email": EMAIL["priya"], "password": "x", "is_admin": True})
    assert r.status_code == 422


def test_login_is_rate_limited_per_ip(make_app, settings, new_client):
    c = new_client(make_app(replace(settings, login_per_ip=(3, 60))))
    codes = [c.post("/auth/login", json={"email": "x@y.example", "password": "pw"}).status_code
             for _ in range(4)]
    assert codes == [401, 401, 401, 429]
    r = c.post("/auth/login", json={"email": "x@y.example", "password": "pw"})
    assert int(r.headers["Retry-After"]) > 0


# -------------------------------------------------------------- /me + JWT
def test_me_requires_bearer_token(client):
    r = client.get("/me")
    assert r.status_code == 401 and r.headers["WWW-Authenticate"] == "Bearer"


def test_me_without_org_lists_only_own_orgs(client):
    r = client.get("/me", headers=login(client, EMAIL["meera"]))
    assert r.status_code == 200
    body = r.json()
    assert body["email"] == EMAIL["meera"] and body["current_org"] is None
    assert {o["slug"] for o in body["organizations"]} == {"asteria-labs", "borealis-systems"}

    r = client.get("/me", headers=login(client, EMAIL["priya"]))
    assert {o["slug"] for o in r.json()["organizations"]} == {"asteria-labs"}


def test_me_with_org_returns_live_role_and_permissions(client):
    auth = login(client, EMAIL["priya"])
    r = client.get("/me", headers={**auth, "X-Org-Id": str(ID.org("org_a"))})
    cur = r.json()["current_org"]
    assert cur["role"] == "employee"
    assert "task.create" in cur["permissions"] and "audit.read" not in cur["permissions"]


def test_permission_revocation_applies_to_the_next_request_with_same_jwt(client, admin_conn):
    auth = {**login(client, EMAIL["priya"]), "X-Org-Id": str(ID.org("org_a"))}
    perm_id = admin_conn.execute(
        "SELECT id FROM secureai.permissions WHERE code = 'chatbot.use'").fetchone()[0]
    admin_conn.execute(
        "INSERT INTO secureai.user_permission_overrides "
        "(organization_id, user_id, permission_id, effect, reason) VALUES (%s, %s, %s, 'deny', 'test')",
        (ID.org("org_a"), ID.user("priya"), perm_id))
    try:
        assert "chatbot.use" not in client.get("/me", headers=auth).json()["current_org"]["permissions"]
    finally:
        admin_conn.execute("DELETE FROM secureai.user_permission_overrides WHERE user_id = %s "
                           "AND permission_id = %s", (ID.user("priya"), perm_id))


def test_foreign_org_header_is_rejected_by_the_database(client):
    auth = login(client, EMAIL["david"])  # Org B only
    r = client.get("/me", headers={**auth, "X-Org-Id": str(ID.org("org_a"))})
    assert (r.status_code, r.json()) == (403, {"detail": "No access to this organization"})
    assert client.get("/me", headers={**auth, "X-Org-Id": "not-a-uuid"}).status_code == 422


def test_disabled_user_is_rejected_even_with_a_valid_jwt(client, make_user, admin_conn):
    u = make_user()
    auth = login(client, u.email, u.password)
    assert client.get("/me", headers=auth).status_code == 200
    admin_conn.execute("UPDATE secureai.users SET status = 'disabled' WHERE id = %s", (u.id,))
    assert client.get("/me", headers=auth).status_code == 401


@pytest.mark.parametrize("token", [
    pytest.param(lambda: forge(alg="none", key=None, headers={"kid": "k2", "typ": "at+jwt"}), id="alg-none"),
    pytest.param(lambda: forge(key=b"\x09" * 32), id="wrong-key"),
    pytest.param(lambda: forge(headers={"kid": "k9", "typ": "at+jwt"}), id="unknown-kid"),
    pytest.param(lambda: forge(headers={"kid": "k2", "typ": "JWT"}), id="wrong-typ"),
    pytest.param(lambda: forge(headers={"typ": "at+jwt"}), id="no-kid"),
    pytest.param(lambda: forge(claims_payload(exp=int(time.time()) - 120)), id="expired"),
    pytest.param(lambda: forge(claims_payload(aud="other-api")), id="wrong-aud"),
    pytest.param(lambda: forge(claims_payload(iss="evil")), id="wrong-iss"),
    pytest.param(lambda: forge({k: v for k, v in claims_payload().items() if k != "sid"}), id="missing-sid"),
    pytest.param(lambda: forge(claims_payload(sub="not-a-uuid")), id="bad-sub"),
    pytest.param(lambda: "a.b.c", id="garbage"),
])
def test_tampered_or_invalid_access_tokens_are_rejected(client, token):
    assert client.get("/me", headers={"Authorization": f"Bearer {token()}"}).status_code == 401


def test_a_correctly_forged_token_would_work_proving_the_negative_tests_are_meaningful(client):
    assert client.get("/me", headers={"Authorization": f"Bearer {forge()}"}).status_code == 200


def test_key_rotation_old_kid_verifies_until_removed(make_app, settings, new_client):
    old_codec = AccessTokenCodec({"k1": JWT_KEYS["k1"]}, "secureai", "secureai-api", settings.access_ttl)
    token, _ = old_codec.issue(ID.user("priya"), uuid.uuid4())
    hdr = {"Authorization": f"Bearer {token}"}
    assert new_client().get("/me", headers=hdr).status_code == 200
    retired = make_app(replace(settings, jwt_keys={"k2": JWT_KEYS["k2"]}))
    assert new_client(retired).get("/me", headers=hdr).status_code == 401


# ---------------------------------------------------------------- refresh
def test_refresh_requires_csrf_header_and_cookie(client, new_client):
    login(client, EMAIL["priya"])
    assert client.post("/auth/refresh").status_code == 403
    assert new_client().post("/auth/refresh", headers=CSRF).status_code == 401


def test_refresh_rotates_cookie_and_issues_working_access_token(client):
    login(client, EMAIL["priya"])
    old = client.cookies.get(REFRESH_COOKIE)
    r = client.post("/auth/refresh", headers=CSRF)
    assert r.status_code == 200
    assert client.cookies.get(REFRESH_COOKIE) != old
    me = client.get("/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.json()["email"] == EMAIL["priya"]


def test_stolen_refresh_cookie_replay_logs_everyone_out(client, new_client, make_user):
    u = make_user()
    login(client, u.email, u.password)
    stolen = client.cookies.get(REFRESH_COOKIE)
    assert client.post("/auth/refresh", headers=CSRF).status_code == 200  # victim rotates

    attacker = new_client()
    r = attacker.post("/auth/refresh", headers={**CSRF, "Cookie": f"{REFRESH_COOKIE}={stolen}"})
    assert r.status_code == 401
    assert f'{REFRESH_COOKIE}=""' in r.headers["set-cookie"] or "Max-Age=0" in r.headers["set-cookie"]
    assert client.post("/auth/refresh", headers=CSRF).status_code == 401  # victim's family revoked


def test_logout_revokes_and_clears_cookie(client):
    login(client, EMAIL["priya"])
    token = client.cookies.get(REFRESH_COOKIE)
    assert client.post("/auth/logout").status_code == 403
    r = client.post("/auth/logout", headers=CSRF)
    assert r.status_code == 204 and "Max-Age=0" in r.headers["set-cookie"]
    replay = client.post("/auth/refresh", headers={**CSRF, "Cookie": f"{REFRESH_COOKIE}={token}"})
    assert replay.status_code == 401


# --------------------------------------------------------- password reset
def test_reset_request_response_is_identical_for_known_and_unknown_email(client, outbox, make_user):
    u = make_user()
    known = client.post("/auth/password-reset/request", json={"email": u.email})
    unknown = client.post("/auth/password-reset/request", json={"email": "ghost@nowhere.example"})
    assert (known.status_code, known.json()) == (unknown.status_code, unknown.json())
    assert known.status_code == 202
    assert [to for to, _ in outbox.sent] == [u.email]
    link = outbox.sent[0][1]
    assert link.startswith("https://app.example/reset-password#token=sapr_")  # fragment, not query


def test_reset_confirm_flow(client, new_client, outbox, make_user):
    u = make_user()
    login(client, u.email, u.password)
    client.post("/auth/password-reset/request", json={"email": u.email})
    token = outbox.sent[-1][1].split("#token=", 1)[1]

    weak = client.post("/auth/password-reset/confirm", json={"token": token, "new_password": "short"})
    assert weak.status_code == 422 and "at least" in weak.json()["detail"]

    ok = client.post("/auth/password-reset/confirm",
                     json={"token": token, "new_password": "fresh-long-passphrase"})
    assert ok.status_code == 204
    again = client.post("/auth/password-reset/confirm",
                        json={"token": token, "new_password": "fresh-long-passphrase"})
    assert (again.status_code, again.json()) == (400, {"detail": "Invalid or expired reset link"})

    assert client.post("/auth/refresh", headers=CSRF).status_code == 401  # sessions revoked
    login(new_client(), u.email, "fresh-long-passphrase")


# -------------------------------------------------------- password change
def test_change_password_keeps_current_device_only(client, new_client, make_user):
    u = make_user()
    auth = login(client, u.email, u.password)
    other_device = new_client()
    login(other_device, u.email, u.password)

    wrong = client.post("/auth/password/change", headers=auth,
                        json={"current_password": "nope-nope-nope", "new_password": "next-long-passphrase"})
    assert wrong.status_code == 403
    assert client.post("/auth/password/change", json={
        "current_password": u.password, "new_password": "next-long-passphrase"}).status_code == 401

    ok = client.post("/auth/password/change", headers=auth,
                     json={"current_password": u.password, "new_password": "next-long-passphrase"})
    assert ok.status_code == 204
    assert client.post("/auth/refresh", headers=CSRF).status_code == 200
    assert other_device.post("/auth/refresh", headers=CSRF).status_code == 401


# ------------------------------------------------------------- production
def test_production_hides_api_docs(make_app, settings, new_client):
    c = new_client(make_app(replace(settings, env="production")))
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404
