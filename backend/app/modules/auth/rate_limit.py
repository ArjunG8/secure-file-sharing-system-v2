"""Sliding-window rate limiting for authentication endpoints.

In-memory and per process: limits reset on restart and are not shared between several
backend processes. That is enough for this project's single-process deployment; a
multi-process deployment would need a shared store (e.g. Redis) or nginx limit_req.
"""

import math
import threading
import time
from collections import deque

from fastapi import Request

from app.core.config import get_settings
from app.core.errors import AppError
from app.modules.auth import MODULE_INFO


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int, window_seconds: float) -> None:
        """Record one attempt for `key`; raise 429 if the window already holds `limit`."""
        now = time.monotonic()
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= now - window_seconds:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = max(1, math.ceil(hits[0] + window_seconds - now))
                raise AppError(
                    429,
                    "Too many attempts. Please wait before trying again.",
                    module=MODULE_INFO.code,
                    headers={"Retry-After": str(retry_after)},
                )
            hits.append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def _client_ip(request: Request) -> str:
    # request.client is the proxy-resolved address when uvicorn runs with --proxy-headers
    # and a trusted --forwarded-allow-ips list (M10); never parse X-Forwarded-For here.
    return request.client.host if request.client else "unknown"


def _limit(request: Request, bucket: str, limit: int, window: float) -> None:
    if get_settings().rate_limit_enabled:
        limiter.hit(f"{bucket}:{_client_ip(request)}", limit, window)


def limit_login(request: Request) -> None:
    _limit(request, "login", get_settings().rate_limit_login_per_minute, 60)


def limit_register(request: Request) -> None:
    _limit(request, "register", get_settings().rate_limit_register_per_hour, 3600)


def limit_refresh(request: Request) -> None:
    _limit(request, "refresh", get_settings().rate_limit_refresh_per_minute, 60)
