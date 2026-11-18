"""Outbound email: password reset, email verification, account notices, invitations.

The reset link carries the token in the URL *fragment* (``#token=``).
Browsers never send fragments to servers, so the token stays out of web
server access logs, proxies and the ``Referer`` header.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Protocol

log = logging.getLogger("secureai.email")


class EmailSender(Protocol):
    def send_password_reset(self, to: str, link: str) -> None: ...
    def send_email_verification(self, to: str, link: str) -> None: ...
    def send_account_exists(self, to: str, reset_page: str) -> None: ...
    def send_invitation(self, to: str, org_name: str, link: str) -> None: ...


class ConsoleEmailSender:
    """Development only: prints the link. Refuses to exist in production."""

    def __init__(self, is_production: bool):
        if is_production:
            raise RuntimeError("ConsoleEmailSender must not be used in production")

    def send_password_reset(self, to: str, link: str) -> None:
        log.warning("[dev email] password reset for %s: %s", to, link)

    def send_email_verification(self, to: str, link: str) -> None:
        log.warning("[dev email] verify email for %s: %s", to, link)

    def send_account_exists(self, to: str, reset_page: str) -> None:
        log.warning("[dev email] %s already has an account; reset at %s", to, reset_page)

    def send_invitation(self, to: str, org_name: str, link: str) -> None:
        log.warning("[dev email] %s invited to %r: %s", to, org_name, link)


@dataclass
class OutboxEmailSender:
    """Collects (kind, to, link) in memory (tests)."""
    sent: list[tuple[str, str, str]] = field(default_factory=list)

    def send_password_reset(self, to: str, link: str) -> None:
        self.sent.append(("reset", to, link))

    def send_email_verification(self, to: str, link: str) -> None:
        self.sent.append(("verify", to, link))

    def send_account_exists(self, to: str, reset_page: str) -> None:
        self.sent.append(("exists", to, reset_page))

    def send_invitation(self, to: str, org_name: str, link: str) -> None:
        self.sent.append(("invite", to, link))


def reset_link(public_url: str, token: str) -> str:
    return f"{public_url}/reset-password#token={token}"


def verify_link(public_url: str, token: str) -> str:
    return f"{public_url}/verify-email#token={token}"


def invitations_link(public_url: str) -> str:
    # No token: accepting requires signing in as the invited address, so a
    # forwarded or leaked email grants nothing.
    return f"{public_url}/invitations"
