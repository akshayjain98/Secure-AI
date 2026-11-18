"""HibpChecker against a mocked transport: no real network in tests."""

from __future__ import annotations

import hashlib

import httpx

from app.auth.breach import HibpChecker

PASSWORD = "correct horse battery staple"
SHA1 = hashlib.sha1(PASSWORD.encode()).hexdigest().upper()  # noqa: S324


def checker(handler) -> tuple[HibpChecker, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)
    return HibpChecker(httpx.Client(transport=httpx.MockTransport(wrapped))), seen


def test_hit_is_detected_and_only_the_5_char_prefix_leaves_the_process():
    c, seen = checker(lambda r: httpx.Response(200, text=f"0000000000000000000000000000000000A:3\r\n{SHA1[5:]}:42\r\n"))
    assert c.is_breached(PASSWORD)
    assert str(seen[0].url).endswith("/range/" + SHA1[:5])
    assert SHA1[5:] not in str(seen[0].url) and PASSWORD not in str(seen[0].url)


def test_padding_rows_with_zero_count_are_not_hits():
    c, _ = checker(lambda r: httpx.Response(200, text=f"{SHA1[5:]}:0\n"))
    assert not c.is_breached(PASSWORD)


def test_miss():
    c, _ = checker(lambda r: httpx.Response(200, text="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:9\n"))
    assert not c.is_breached(PASSWORD)


def test_fails_open_on_outage_and_on_errors():
    def boom(request):
        raise httpx.ConnectTimeout("down")
    assert not checker(boom)[0].is_breached(PASSWORD)
    assert not checker(lambda r: httpx.Response(503))[0].is_breached(PASSWORD)
