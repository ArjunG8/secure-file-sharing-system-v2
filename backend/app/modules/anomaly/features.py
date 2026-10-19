"""Security-event feature extraction: one feature vector per (user, 1-hour UTC window).

Only events with an actor are used (anonymous failed logins have no user to attribute
them to). Malformed events (missing type or time, non-dict details, non-numeric sizes)
are skipped or treated as zero rather than crashing the pipeline.
"""

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

WINDOW = timedelta(hours=1)
OFF_HOURS_UTC = range(0, 6)  # 00:00-05:59 UTC counts as off-hours

# Order matters: it is the column order of the model's input matrix.
FEATURES = (
    "events_total",
    "logins_ok",
    "logins_failed",
    "access_denied",
    "integrity_failures",
    "uploads",
    "downloads",
    "shares_created",
    "distinct_ips",
    "mb_downloaded",
    "off_hours",
)


@dataclass
class Window:
    user_id: uuid.UUID
    window_start: datetime
    counts: dict[str, float] = field(default_factory=lambda: dict.fromkeys(FEATURES, 0.0))
    ips: set[str] = field(default_factory=set)
    last_event_id: int | None = None

    @property
    def window_end(self) -> datetime:
        return self.window_start + WINDOW

    def vector(self) -> list[float]:
        return [self.counts[name] for name in FEATURES]


def _utc(value: Any) -> datetime | None:
    if not isinstance(value, datetime):
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _size(details: Any) -> float:
    if not isinstance(details, dict):
        return 0.0
    value = details.get("size_bytes")
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        return 0.0
    return float(value)


_COUNTERS = {
    "auth.login": "logins_ok",
    "auth.login_failed": "logins_failed",
    "share.access_denied": "access_denied",
    "file.integrity_failure": "integrity_failures",
    "file.upload": "uploads",
    "file.download": "downloads",
    "share.create": "shares_created",
}


def extract_windows(events: list[Any]) -> list[Window]:
    """`events`: AuditLog rows or objects with the same attributes."""
    windows: dict[tuple[uuid.UUID, datetime], Window] = {}
    for event in events:
        when = _utc(getattr(event, "occurred_at", None))
        actor = getattr(event, "actor_user_id", None)
        event_type = getattr(event, "event_type", None)
        if when is None or actor is None or not isinstance(event_type, str):
            continue
        start = when.replace(minute=0, second=0, microsecond=0)
        w = windows.setdefault((actor, start), Window(user_id=actor, window_start=start))
        w.counts["events_total"] += 1
        if counter := _COUNTERS.get(event_type):
            w.counts[counter] += 1
        if event_type == "file.download":
            w.counts["mb_downloaded"] += _size(getattr(event, "details", None)) / 1_000_000
        ip = getattr(event, "ip_address", None)
        if isinstance(ip, str) and ip:
            w.ips.add(ip)
        event_id = getattr(event, "id", None)
        if isinstance(event_id, int):
            w.last_event_id = max(event_id, w.last_event_id or event_id)
    for w in windows.values():
        w.counts["distinct_ips"] = float(len(w.ips))
        w.counts["off_hours"] = 1.0 if w.window_start.hour in OFF_HOURS_UTC else 0.0
    return sorted(windows.values(), key=lambda w: (w.window_start, str(w.user_id)))


def extract_features(events: list[Any]) -> list[dict[str, float]]:
    """Interface form: one {feature: value} dict per window."""
    return [dict(w.counts) for w in extract_windows(events)]

