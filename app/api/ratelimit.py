"""In-process fixed-window rate limiter.

Good enough for one process and for tests. Running more than one worker or
replica needs a shared store (Redis INCR + EXPIRE) behind the same interface,
otherwise each process enforces its own copy of the limit.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable


class RateLimited(Exception):
    def __init__(self, retry_after: int):
        super().__init__(f"retry after {retry_after}s")
        self.retry_after = retry_after


class RateLimiter:
    _MAX_KEYS = 50_000

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._lock = threading.Lock()
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}

    def hit(self, bucket: str, key: str | None, limit: int, window_seconds: int) -> None:
        """Count one request; raise RateLimited once `limit` is exceeded in the window."""
        now = self._clock()
        k = (bucket, key or "-")
        with self._lock:
            if len(self._windows) > self._MAX_KEYS:
                self._evict(now)
            start, count = self._windows.get(k, (now, 0))
            if now - start >= window_seconds:
                start, count = now, 0
            count += 1
            self._windows[k] = (start, count)
            if count > limit:
                raise RateLimited(max(1, math.ceil(window_seconds - (now - start))))

    def _evict(self, now: float) -> None:
        # Drop windows older than the longest window we use (1 hour).
        self._windows = {k: v for k, v in self._windows.items() if now - v[0] < 3600}
