"""Breached-password check (NIST SP 800-63B §5.1.1.2: "passwords obtained from
previous breach corpuses" must be rejected).

HibpChecker uses the Have I Been Pwned *range* API with k-anonymity: only the
first 5 hex characters of SHA-1(password) leave this process, so the service
can't learn the password or its full hash. ``Add-Padding`` makes every
response roughly the same size, so a network observer can't infer the prefix
from the response length.

Fail-open by design: if the API is slow or down, registration and resets
still work, and the failure is logged. Availability of an optional external
check must not become an outage.
"""

from __future__ import annotations

import hashlib
import logging
import unicodedata
from typing import Protocol

import httpx

log = logging.getLogger("secureai.breach")

HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/"


class BreachChecker(Protocol):
    def is_breached(self, password: str) -> bool: ...


class NoBreachCheck:
    def is_breached(self, password: str) -> bool:
        return False


class HibpChecker:
    def __init__(self, client: httpx.Client | None = None, timeout: float = 2.0):
        self._client = client or httpx.Client(
            timeout=timeout,
            headers={"User-Agent": "secureai-workspace-breach-check", "Add-Padding": "true"})

    def is_breached(self, password: str) -> bool:
        digest = hashlib.sha1(unicodedata.normalize("NFKC", password).encode()).hexdigest().upper()  # noqa: S324 - HIBP protocol
        prefix, suffix = digest[:5], digest[5:]
        try:
            resp = self._client.get(HIBP_RANGE_URL + prefix)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("breach check unavailable, failing open: %s", type(exc).__name__)
            return False
        for line in resp.text.splitlines():
            candidate, _, count = line.strip().partition(":")
            # Padding rows have count 0 and must not count as a hit.
            if candidate == suffix and count.strip().isdigit() and int(count) > 0:
                return True
        return False
