"""M10: security headers, HTTPS enforcement, transport status, CORS, proxy/TLS config.

The last group checks the nginx/Docker configuration FILES statically. That proves what
the config says, not that a running nginx negotiates TLS correctly; the live
`docker compose --profile tls up` check is still required (see docs/security-design.md).
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app

REPO = Path(__file__).resolve().parents[3]


def client(https=False, **settings):
    for key, value in settings.items():
        setattr(get_settings(), key, value)
    return TestClient(create_app(), base_url="https://testserver" if https else "http://testserver")


@pytest.fixture(autouse=True)
def _restore(monkeypatch):
    s = get_settings()
    for key in ("enforce_https", "environment", "hsts_max_age_seconds", "cors_origins"):
        monkeypatch.setattr(s, key, getattr(s, key))


# --- headers -----------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/api/v1/health", "/api/v1/does-not-exist", "/api/v1/auth/me"])
def test_security_headers_on_success_and_error_responses(path):
    r = client().get(path)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "camera=()" in r.headers["permissions-policy"]
    assert r.headers["content-security-policy"].startswith("default-src 'none'")


def test_hsts_only_over_https():
    assert "strict-transport-security" not in client().get("/api/v1/health").headers
    hsts = client(https=True).get("/api/v1/health").headers["strict-transport-security"]
    assert hsts == "max-age=31536000; includeSubDomains"


def test_api_docs_are_exempt_from_the_strict_csp():
    r = client().get("/api/docs")
    assert r.status_code == 200 and "content-security-policy" not in r.headers
    assert r.headers["x-frame-options"] == "DENY"


# --- HTTPS enforcement -------------------------------------------------------------------


def test_development_allows_plain_http():
    assert client().get("/api/v1/modules").status_code == 200


def test_enforced_https_redirects_get_and_rejects_writes():
    c = client(enforce_https=True)
    r = c.get("/api/v1/modules?x=1", follow_redirects=False)
    assert r.status_code == 308 and r.headers["location"] == "https://testserver/api/v1/modules?x=1"
    w = c.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "x"})
    assert w.status_code == 400 and w.json()["error"]["code"] == "https_required"
    assert w.headers["x-content-type-options"] == "nosniff"  # headers on rejections too


def test_https_passes_and_health_is_exempt():
    assert client(https=True, enforce_https=True).get("/api/v1/modules").status_code == 200
    assert client(enforce_https=True).get("/api/v1/health").status_code == 200


def test_client_cannot_fake_https_with_a_forwarded_header():
    """Only uvicorn (trusting FORWARDED_ALLOW_IPS) may turn X-Forwarded-Proto into https."""
    r = client(enforce_https=True).post(
        "/api/v1/auth/login", headers={"X-Forwarded-Proto": "https"},
        json={"email": "a@example.com", "password": "x"})
    assert r.status_code == 400


def test_production_always_requires_https():
    s = get_settings()
    s.environment = "production"
    s.enforce_https = False
    assert s.https_required
    assert client().post("/api/v1/auth/logout").status_code == 400


# --- status and CORS ---------------------------------------------------------------------


def test_transport_status_reports_this_request():
    plain = client().get("/api/v1/transport/status").json()
    assert plain == {"scheme": "http", "behind_proxy": False, "hsts_enabled": False,
                     "https_enforced": False, "tls_version": None}
    proxied = client(https=True).get("/api/v1/transport/status",
                                     headers={"X-Forwarded-For": "203.0.113.5",
                                              "X-TLS-Protocol": "TLSv1.3"}).json()
    assert proxied["scheme"] == "https" and proxied["tls_version"] == "TLSv1.3"
    junk = client(https=True).get("/api/v1/transport/status",
                                  headers={"X-Forwarded-For": "x", "X-TLS-Protocol": "SSLv3"})
    assert junk.json()["tls_version"] is None  # only known-good values are echoed


def test_cors_only_for_configured_origins():
    c = client(cors_origins="https://app.example.com")
    ok = c.options("/api/v1/health", headers={"Origin": "https://app.example.com",
                                             "Access-Control-Request-Method": "GET"})
    assert ok.headers.get("access-control-allow-origin") == "https://app.example.com"
    bad = c.options("/api/v1/health", headers={"Origin": "https://evil.example",
                                              "Access-Control-Request-Method": "GET"})
    assert "access-control-allow-origin" not in bad.headers


# --- configuration files (static checks) -------------------------------------------------


@pytest.fixture(scope="module")
def nginx():
    return (REPO / "infra/nginx/nginx.conf").read_text(encoding="utf-8")


def test_nginx_allows_only_tls_1_2_and_1_3(nginx):
    protocols = re.findall(r"^\s*ssl_protocols\s+([^;]+);", nginx, re.M)
    assert protocols == ["TLSv1.2 TLSv1.3"]
    ciphers = re.search(r"ssl_ciphers\s+([^;]+);", nginx).group(1).split(":")
    assert all(c.startswith("ECDHE-") and ("GCM" in c or "CHACHA20" in c) for c in ciphers)


def test_nginx_redirects_http_and_sets_hsts(nginx):
    assert re.search(r"listen 80;\s+listen \[::\]:80;\s+return 301 https://", nginx)
    assert 'Strict-Transport-Security "max-age=31536000; includeSubDomains" always' in nginx
    assert "server_tokens off;" in nginx


def test_nginx_overwrites_forwarding_headers_and_limits_bodies(nginx):
    assert "proxy_set_header X-Forwarded-For $remote_addr;" in nginx
    assert "$proxy_add_x_forwarded_for" not in nginx  # would keep client-forged values
    assert "client_max_body_size 26m;" in nginx and "limit_req zone=auth" in nginx


def test_tls_profile_serves_the_production_build(nginx):
    dockerfile = (REPO / "infra/nginx/Dockerfile").read_text(encoding="utf-8")
    assert "npm run build" in dockerfile and "/usr/share/nginx/html" in dockerfile
    assert "5173" not in nginx  # no Vite dev server behind the TLS proxy
    assert "script-src 'self'" in nginx and "frame-ancestors 'none'" in nginx


def test_backend_trusts_forwarded_headers_only_from_the_proxy():
    dockerfile = (REPO / "backend/Dockerfile").read_text(encoding="utf-8")
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "--forwarded-allow-ips='*'" not in dockerfile + compose
    assert 'FORWARDED_ALLOW_IPS: "172.28.0.10"' in compose and "ipv4_address: 172.28.0.10" in compose


def test_dev_certificate_script_and_secrets_hygiene():
    script = (REPO / "scripts/gen-dev-certs.sh").read_text(encoding="utf-8")
    assert "rsa:3072" in script and "chmod 600" in script
    assert "infra/nginx/certs" in (REPO / ".gitignore").read_text(encoding="utf-8")
    ignore = (REPO / ".dockerignore").read_text(encoding="utf-8").split()
    assert ".env" in ignore and "infra/nginx/certs" in ignore
