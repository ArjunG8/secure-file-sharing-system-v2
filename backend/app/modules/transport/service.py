"""M10 public interface. Implementation notes: docs/security-design.md, section M10.

TLS itself is terminated by nginx (infra/nginx). This module adds the application-side
controls: security headers on every response, HTTPS enforcement, and status reporting.
"""

import logging

from fastapi import FastAPI, Request

from app.core.config import Settings
from app.modules.transport.middleware import HTTPSRequiredMiddleware, SecurityHeadersMiddleware
from app.modules.transport.schemas import TransportStatus

logger = logging.getLogger(__name__)


def install_transport_security(app: FastAPI, settings: Settings) -> None:
    """Register the middleware. Called by main.create_app after CORS, so these wrap it:
    every response (including CORS preflights and error envelopes) gets the headers."""
    if settings.https_required:
        app.add_middleware(HTTPSRequiredMiddleware)
    else:
        logger.info("HTTPS is not enforced (development). Set ENFORCE_HTTPS=true or "
                    "ENVIRONMENT=production to require it.")
    app.add_middleware(SecurityHeadersMiddleware, hsts_max_age=settings.hsts_max_age_seconds)


def transport_status(request: Request, settings: Settings) -> TransportStatus:
    """How THIS request reached the backend. tls_version is what nginx reported in
    X-TLS-Protocol, and is only shown when the request is HTTPS via a trusted proxy."""
    scheme = "https" if request.url.scheme == "https" else "http"
    behind_proxy = "x-forwarded-for" in request.headers
    tls = request.headers.get("x-tls-protocol") if scheme == "https" and behind_proxy else None
    return TransportStatus(
        scheme=scheme,
        behind_proxy=behind_proxy,
        hsts_enabled=scheme == "https" and settings.hsts_max_age_seconds > 0,
        https_enforced=settings.https_required,
        tls_version=tls if tls in ("TLSv1.2", "TLSv1.3") else None,
    )
