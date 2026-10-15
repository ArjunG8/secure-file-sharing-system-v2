from typing import Literal

from pydantic import BaseModel


class TransportStatus(BaseModel):
    scheme: Literal["http", "https"]
    behind_proxy: bool
    hsts_enabled: bool
    https_enforced: bool
    tls_version: str | None = None
