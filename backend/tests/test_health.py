from app.core.config import APP_VERSION


def test_health_reports_ok_and_database(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "version": APP_VERSION, "database": "ok"}


def test_modules_endpoint_lists_all_ten_modules(client):
    r = client.get("/api/v1/modules")
    assert r.status_code == 200
    modules = r.json()
    assert [m["number"] for m in modules] == list(range(1, 11))
    assert [m["code"] for m in modules] == [f"M{i}" for i in range(1, 11)]
    for m in modules:
        assert isinstance(m["implemented"], bool)
        assert m["name"]


def test_unknown_route_uses_error_envelope(client):
    r = client.get("/api/v1/does-not-exist")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_openapi_docs_are_served(client):
    assert client.get("/api/openapi.json").status_code == 200
