"""Unimplemented endpoints must answer an honest 501, attributed to the right module.

WHEN YOU IMPLEMENT AN ENDPOINT: delete its line from YOUR module's block below (and
only yours: the blocks are separated so ten people can edit this file without merge
conflicts), then add real tests in tests/modules/. test_implemented_flags_are_honest
enforces that a module is not marked implemented while any of its endpoints are stubbed.
"""

import uuid

import pytest

from app.core.modules import all_modules

FID = str(uuid.uuid4())
LATER = {"since": "2026-01-01T00:00:00Z", "until": "2026-01-02T00:00:00Z"}

# module code -> [(method, path, request kwargs)]
STUBBED: dict[str, list[tuple[str, str, dict]]] = {}

# ---------------------------------------------------------------- M1 (owner: M1)
STUBBED["M1"] = []  # implemented: see tests/modules/test_auth.py

# ---------------------------------------------------------------- M2 (owner: M2)
STUBBED["M2"] = []  # implemented: see tests/modules/test_encryption.py

# ---------------------------------------------------------------- M3 (owner: M3)
STUBBED["M3"] = []  # implemented: see tests/modules/test_keys.py

# ---------------------------------------------------------------- M4 (owner: M4)
STUBBED["M4"] = []  # implemented: see tests/modules/test_signatures.py

# ---------------------------------------------------------------- M5 (owner: M5)
STUBBED["M5"] = []  # implemented: see tests/modules/test_sharing.py




# ---------------------------------------------------------------- M8 (owner: M8)
STUBBED["M8"] = []  # implemented: see tests/modules/test_llm_analysis.py

# ---------------------------------------------------------------- M9 (owner: M9)
STUBBED["M9"] = []  # implemented: see tests/modules/test_verification.py

# ---------------------------------------------------------------- M10 (owner: M10)
STUBBED["M10"] = []  # implemented: see tests/modules/test_transport.py

# ---------------------------------------------------------------- end of module blocks

STUBBED_ENDPOINTS = [
    (module, method, path, kwargs)
    for module, endpoints in STUBBED.items()
    for method, path, kwargs in endpoints
]

@pytest.fixture
def admin_client(client_as, create_user):
    # Persist the admin so audit events can reference a valid user.
    return client_as(create_user(role="admin"))


@pytest.mark.parametrize(
    ("module", "method", "path", "kwargs"),
    STUBBED_ENDPOINTS,
    ids=[f"{m}-{verb.upper()} {p}" for m, verb, p, _ in STUBBED_ENDPOINTS],
)
def test_stub_returns_honest_501(admin_client, module, method, path, kwargs):
    r = admin_client.request(method.upper(), path, **kwargs)
    assert r.status_code == 501, r.text
    error = r.json()["error"]
    assert error["code"] == "not_implemented"
    assert error["module"] == module


def test_protected_endpoints_do_not_bypass_auth(client):
    """Without the override, the M1 auth dependency runs (currently: honest 501)."""
    r = client.get("/api/v1/files")
    assert r.status_code in (401, 501)
    assert r.status_code != 200


def test_implemented_flags_are_honest():
    stubbed_modules = {module for module, endpoints in STUBBED.items() if endpoints}
    for info in all_modules():
        if info.implemented:
            assert info.code not in stubbed_modules, (
                f"{info.code} is marked implemented but still has stubbed endpoints"
            )
