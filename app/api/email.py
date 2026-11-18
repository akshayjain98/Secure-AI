"""Outbound email. Only password-reset mail exists so far.

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


class ConsoleEmailSender:
    """Development only: prints the link. Refuses to exist in production."""

    def __init__(self, is_production: bool):
        if is_production:
            raise RuntimeError("ConsoleEmailSender must not be used in production")

    def send_password_reset(self, to: str, link: str) -> None:
        log.warning("[dev email] password reset for %s: %s", to, link)


@dataclass
class OutboxEmailSender:
    """Collects messages in memory (tests)."""
    sent: list[tuple[str, str]] = field(default_factory=list)

    def send_password_reset(self, to: str, link: str) -> None:
        self.sent.append((to, link))


def reset_link(public_url: str, token: str) -> str:
    return f"{public_url}/reset-password#token={token}"
