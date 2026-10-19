"""Redaction before anything leaves the server.

- actor/resource ids -> keyed pseudonyms (HMAC with a key derived from AUDIT_HMAC_KEY),
  stable within the deployment so the model can correlate events, not reversible by it
- IPv4 -> /24, IPv6 -> /48 network
- user agents dropped
- details: only allowlisted keys with scalar values; emails/UUIDs/long tokens in strings
  are replaced. Passwords, keys, tokens and file contents are never in audit details,
  and anything unexpected is dropped rather than forwarded.
"""

import base64
import hashlib
import hmac
import ipaddress
import re
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import get_settings

ALLOWED_DETAIL_KEYS = {
    "reason", "check", "required", "purpose", "algorithm", "valid", "size_bytes",
    "max_downloads", "windows", "anomalies", "events", "score", "checked_entries",
}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}\b"
)
_TOKENISH = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")


def _key() -> bytes:
    secret = base64.b64decode(get_settings().audit_hmac_key.get_secret_value())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sfs-llm-pseudonyms-v1").derive(secret)


def pseudonym(kind: str, value: Any) -> str | None:
    if value is None:
        return None
    digest = hmac.new(_key(), f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()
    return f"{kind}-{digest[:12]}"


def truncate_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def scrub(text: str) -> str:
    text = _EMAIL.sub("[email]", text)
    text = _UUID.sub("[id]", text)
    return _TOKENISH.sub("[token]", text)[:200]


def _details(details: Any) -> dict[str, Any]:
    if not isinstance(details, dict):
        return {}
    out = {}
    for key, value in details.items():
        if key not in ALLOWED_DETAIL_KEYS:
            continue
        if isinstance(value, bool | int | float) or value is None:
            out[key] = value
        elif isinstance(value, str):
            out[key] = scrub(value)
    return out


def redact(event: dict[str, Any]) -> dict[str, Any]:
    """Map an audit event (as a dict of AuditLog columns) to what may be sent out."""
    return {
        "id": event.get("id"),
        "occurred_at": str(event.get("occurred_at")),
        "event_type": scrub(str(event.get("event_type", ""))),
        "outcome": event.get("outcome"),
        "actor": pseudonym("user", event.get("actor_user_id")),
        "resource_type": event.get("resource_type"),
        "resource": pseudonym("res", event.get("resource_id")),
        "network": truncate_ip(event.get("ip_address")),
        "details": _details(event.get("details")),
    }
