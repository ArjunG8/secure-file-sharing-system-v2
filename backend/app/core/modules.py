"""Registry of the ten security modules and their honest implementation status."""

import importlib
from dataclasses import dataclass

# Order defines module numbers 1..10. Package names live under app.modules.
MODULE_PACKAGES = (
    "auth",
    "encryption",
    "keys",
    "signatures",
    "sharing",
    "audit",
    "anomaly",
    "llm_analysis",
    "verification",
    "transport",
)


@dataclass(frozen=True)
class ModuleInfo:
    number: int
    key: str
    name: str
    # Flip to True only when every endpoint of the module works and is tested.
    implemented: bool = False

    @property
    def code(self) -> str:
        return f"M{self.number}"


def all_modules() -> list[ModuleInfo]:
    return [
        importlib.import_module(f"app.modules.{pkg}").MODULE_INFO for pkg in MODULE_PACKAGES
    ]
