"""HTTP tests for registration, breach checking, request ids and security alerts."""

from __future__ import annotations

import logging
import uuid

from app.auth.breach import BreachChecker
from tests.api.conftest import CSRF, REFRESH_COOKIE, login

ACCEPTED = {"detail": "Check your inbox to finish creating your account."}


def fresh_email() -> str:
    return f"reg-{uuid.uuid4().hex[:12]}@test.example"


def register(client, email, name="New Person"):
    return client.post("/auth/register", json={"email": email, "display_name": name})


def token_from(link: str) -> str:
    return link.split("#token=", 1)[1]


def test_register_responses_are_identical_and_emails_go_to_the_owner(client, outbox):
    new, existing = fresh_email(), "priya@asteria.example"
    r_new, r_existing = register(client, new), register(client, existing)
    assert (r_new.status_code, r_new.json()) == (r_existing.status_code, r_existing.json()) == (202, ACCEPTED)
    assert [(k, to) for k, to, _ in outbox.sent] == [("verify", new), ("exists", existing)]
    assert outbox.sent[0][2].startswith("https://app.example/verify-email#token=save_")


def test_malformed_registration_is_422(client):
    assert register(client, "not-an-email").status_code == 422
    assert register(client, fresh_email(), name="   ").status_code == 422
    r = client.post("/auth/register", json={"email": fresh_email(), "display_name": "x", "password": "p"})
    assert r.status_code == 422  # registration never accepts a password


def test_verify_then_login(client, new_client, outbox):
    email = fresh_email()
    register(client, email)
    token = token_from(outbox.sent[-1][2])

    assert client.post("/auth/verify-email", json={"token": token, "password": "short"}).status_code == 422
    assert client.post("/auth/verify-email",
                       json={"token": token, "password": "my-own-long-passphrase"}).status_code == 204
    again = client.post("/auth/verify-email", json={"token": token, "password": "my-own-long-passphrase"})
    assert (again.status_code, again.json()) == (400, {"detail": "Invalid or expired verification link"})

    auth = login(new_client(), email, "my-own-long-passphrase")
    assert client.get("/me", headers=auth).json()["organizations"] == []


class _AlwaysBreached(BreachChecker):
    def is_breached(self, password: str) -> bool:
        return True


def test_breached_passwords_are_rejected_on_every_set_password_path(
        make_app, settings, pool, outbox, new_client, make_user):
    from app.api.main import create_app
    c = new_client(create_app(settings, pool=pool, mailer=outbox, breach_checker=_AlwaysBreached()))
    email = fresh_email()
    register(c, email)
    r = c.post("/auth/verify-email", json={"token": token_from(outbox.sent[-1][2]),
                                           "password": "password-from-a-breach"})
    assert r.status_code == 422 and "breach" in r.json()["detail"]

    u = make_user()
    c.post("/auth/password-reset/request", json={"email": u.email})
    r = c.post("/auth/password-reset/confirm", json={"token": token_from(outbox.sent[-1][2]),
                                                     "new_password": "password-from-a-breach"})
    assert r.status_code == 422 and "breach" in r.json()["detail"]


def test_every_response_has_a_request_id_that_lands_in_the_audit_log(client, admin_conn):
    r = client.post("/auth/login", json={"email": "nobody@nowhere.example", "password": "whatever-pw"})
    rid = r.headers["X-Request-ID"]
    assert len(rid) == 32
    assert admin_conn.execute(
        "SELECT action, outcome FROM secureai.audit_logs WHERE request_id = %s", (rid,)).fetchall() == [
        ("auth.login", "failure")]


def test_client_cannot_choose_the_request_id(client):
    r = client.get("/me", headers={"X-Request-ID": "attacker-chosen"})
    assert r.headers["X-Request-ID"] != "attacker-chosen"


def test_refresh_token_reuse_raises_a_structured_security_alert(client, new_client, make_user, caplog):
    u = make_user()
    login(client, u.email, u.password)
    stolen = client.cookies.get(REFRESH_COOKIE)
    client.post("/auth/refresh", headers=CSRF)
    with caplog.at_level(logging.WARNING, logger="secureai.auth"):
        new_client().post("/auth/refresh", headers={**CSRF, "Cookie": f"{REFRESH_COOKIE}={stolen}"})
    alerts = [r for r in caplog.records if getattr(r, "event", None) == "refresh_token_reuse"]
    assert len(alerts) == 1 and alerts[0].user_id == str(u.id) and alerts[0].request_id
