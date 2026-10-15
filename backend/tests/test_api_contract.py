"""Every endpoint in docs/api-contracts.md must exist. Update both together."""

import pytest

DOCUMENTED_ENDPOINTS = [
    ("get", "/api/v1/health"),
    ("get", "/api/v1/modules"),
    # M1
    ("post", "/api/v1/auth/register"),
    ("post", "/api/v1/auth/login"),
    ("post", "/api/v1/auth/refresh"),
    ("post", "/api/v1/auth/logout"),
    ("get", "/api/v1/auth/me"),
    ("post", "/api/v1/auth/change-password"),
    # M2
    ("post", "/api/v1/files"),
    ("get", "/api/v1/files"),
    ("get", "/api/v1/files/{file_id}"),
    ("get", "/api/v1/files/{file_id}/download"),
    ("delete", "/api/v1/files/{file_id}"),
    # M3
    ("get", "/api/v1/keys/me"),
    ("post", "/api/v1/keys/rotate"),
    ("get", "/api/v1/keys/users/{user_id}/public"),
    # M4
    ("get", "/api/v1/signatures/files/{file_id}"),
    ("post", "/api/v1/signatures/files/{file_id}/verify"),
    # M5
    ("post", "/api/v1/shares"),
    ("get", "/api/v1/shares/outgoing"),
    ("get", "/api/v1/shares/incoming"),
    ("delete", "/api/v1/shares/{grant_id}"),
    # M6
    ("get", "/api/v1/audit/logs"),
    ("get", "/api/v1/audit/verify"),
    # M7
    ("post", "/api/v1/anomaly/train"),
    ("post", "/api/v1/anomaly/score"),
    ("get", "/api/v1/anomaly/detections"),
    # M8
    ("post", "/api/v1/analysis"),
    ("get", "/api/v1/analysis"),
    ("get", "/api/v1/analysis/{analysis_id}"),
    # M9
    ("post", "/api/v1/verification/files/{file_id}"),
    ("post", "/api/v1/verification/audit-chain"),
    ("get", "/api/v1/verification/runs"),
    # M10
    ("get", "/api/v1/transport/status"),
]


@pytest.fixture(scope="module")
def openapi(app):
    return app.openapi()


@pytest.fixture(scope="module")
def app():
    from app.main import create_app

    return create_app()


@pytest.mark.parametrize(("method", "path"), DOCUMENTED_ENDPOINTS)
def test_documented_endpoint_exists(openapi, method, path):
    assert path in openapi["paths"], f"{path} missing from API"
    assert method in openapi["paths"][path], f"{method.upper()} {path} missing"


def test_no_undocumented_endpoints(openapi):
    documented = set(DOCUMENTED_ENDPOINTS)
    actual = {(m, p) for p, ops in openapi["paths"].items() for m in ops}
    assert actual - documented == set(), "Add new endpoints to docs/api-contracts.md and here"


def test_no_response_schema_exposes_private_keys(openapi):
    schemas = openapi["components"]["schemas"]
    for name, schema in schemas.items():
        props = schema.get("properties", {})
        for forbidden in ("encrypted_private_key", "private_key", "password_hash", "file_key"):
            assert forbidden not in props, f"{name} exposes {forbidden}"
