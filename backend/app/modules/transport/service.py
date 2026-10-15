"""M10 public interface. Implementation notes: docs/security-design.md, section M10.

TLS itself is terminated by nginx (infra/nginx). This module adds the
application-side controls: security headers, HTTPS enforcement, status reporting.
"""

import logging

from fastapi import FastAPI, Request

from app.core.config import Settings
from app.core.errors import NotImplementedFeature
from app.modules.transport import MODULE_INFO
from app.modules.transport.schemas import TransportStatus

logger = logging.getLogger(__name__)


def install_transport_security(app: FastAPI, settings: Settings) -> None:
    """Register security-header and HTTPS-enforcement middleware on the app.

    STUB BEHAVIOUR (until M10 implements it): installs nothing and logs a warning.
    """
    logger.warning(
        "Transport security middleware not implemented (M10): "
        "no security headers or HTTPS enforcement are active."
    )


def transport_status(request: Request, settings: Settings) -> TransportStatus:
    raise NotImplementedFeature(MODULE_INFO, "Transport status")
