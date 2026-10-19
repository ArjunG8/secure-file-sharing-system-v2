"""Synthetic security events for testing and evaluating the detector.

SYNTHETIC DATA ONLY. The behaviour profiles below are assumptions chosen to be
plausible, not measurements of real users, so results on this data say nothing about
real-world detection accuracy.

normal user-hour: 1-3 logins, rare failed login, a few uploads/downloads, one IP,
                  mostly office hours
attack user-hour: one of
  - credential stuffing: many failed logins from several IPs
  - exfiltration: many downloads / megabytes, often off-hours
  - probing: many access denials (IDOR enumeration) and integrity failures
"""

import random
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta


@dataclass
class Event:
    occurred_at: datetime
    actor_user_id: uuid.UUID
    event_type: str
    ip_address: str
    details: dict = field(default_factory=dict)
    id: int | None = None
    outcome: str = "success"


def _events(rng, user, start, count, event_type, ips, size=None, outcome="success"):
    out = []
    for _ in range(count):
        details = {"size_bytes": size(rng)} if size else {}
        out.append(Event(start + timedelta(seconds=rng.randint(0, 3599)), user, event_type,
                         rng.choice(ips), details, outcome=outcome))
    return out


def normal_hour(rng: random.Random, user: uuid.UUID, start: datetime) -> list[Event]:
    ip = f"10.0.{rng.randint(0, 9)}.{rng.randint(1, 254)}"
    events = _events(rng, user, start, rng.randint(1, 3), "auth.login", [ip])
    events += _events(rng, user, start, rng.choice([0, 0, 0, 1]), "auth.login_failed", [ip],
                      outcome="failure")
    events += _events(rng, user, start, rng.randint(0, 2), "file.upload", [ip])
    events += _events(rng, user, start, rng.randint(0, 4), "file.download", [ip],
                      size=lambda r: r.randint(10_000, 2_000_000))
    events += _events(rng, user, start, rng.choice([0, 0, 1]), "share.create", [ip])
    return events


def attack_hour(rng: random.Random, user: uuid.UUID, start: datetime) -> list[Event]:
    ips = [f"203.0.113.{rng.randint(1, 254)}" for _ in range(rng.randint(3, 8))]
    kind = rng.choice(["stuffing", "exfiltration", "probing"])
    if kind == "stuffing":
        return (_events(rng, user, start, rng.randint(25, 60), "auth.login_failed", ips,
                        outcome="failure")
                + _events(rng, user, start, 1, "auth.login", ips))
    if kind == "exfiltration":
        return (_events(rng, user, start, rng.randint(1, 2), "auth.login", ips[:1])
                + _events(rng, user, start, rng.randint(40, 120), "file.download", ips[:2],
                          size=lambda r: r.randint(5_000_000, 20_000_000)))
    return (_events(rng, user, start, 1, "auth.login", ips[:1])
            + _events(rng, user, start, rng.randint(15, 40), "share.access_denied", ips,
                      outcome="denied")
            + _events(rng, user, start, rng.randint(1, 5), "file.integrity_failure", ips,
                      outcome="failure"))


def dataset(seed: int, users: int = 30, hours: int = 24, attacks: int = 15
            ) -> tuple[list[Event], set[tuple[uuid.UUID, datetime]]]:
    """Return (events, labels) where labels holds the (user, window_start) of every attack.

    Normal hours are office hours (08-18 UTC); attacks get random hours, so off-hours
    activity is a signal but not the only one.
    """
    rng = random.Random(seed)  # noqa: S311 - seeded synthetic data, not cryptography
    base = datetime(2026, 3, 2, tzinfo=UTC)
    user_ids = [uuid.UUID(int=rng.getrandbits(128)) for _ in range(users)]
    events: list[Event] = []
    for user in user_ids:
        for h in rng.sample(range(8, 19), k=min(hours, 11)):
            events += normal_hour(rng, user, base + timedelta(hours=h))
    labels = set()
    for _ in range(attacks):
        user = rng.choice(user_ids)
        start = base + timedelta(days=1, hours=rng.randint(0, 23))
        events += attack_hour(rng, user, start)
        labels.add((user, start))
    for i, event in enumerate(sorted(events, key=lambda e: e.occurred_at), start=1):
        event.id = i
    return events, labels
