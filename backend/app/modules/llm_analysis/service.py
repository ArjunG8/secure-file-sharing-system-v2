"""M8 public interface. Implementation notes: docs/security-design.md, section M8.

The provider is configured with LLM_PROVIDER / LLM_API_KEY / LLM_MODEL. When it is
"disabled" (the default) analysis must return 503 - never fabricate output.
"""

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.errors import NotImplementedFeature
from app.models import SecurityAnalysis
from app.modules.llm_analysis import MODULE_INFO
from app.modules.llm_analysis.schemas import AnalysisRequest


def redact(event: dict[str, Any]) -> dict[str, Any]:
    """Pseudonymise emails/UUIDs, truncate IPs, drop user agents before sending to an LLM."""
    raise NotImplementedFeature(MODULE_INFO, "Event redaction")


def analyze(db: Session, requested_by: uuid.UUID, request: AnalysisRequest) -> SecurityAnalysis:
    raise NotImplementedFeature(MODULE_INFO, "LLM security analysis")
