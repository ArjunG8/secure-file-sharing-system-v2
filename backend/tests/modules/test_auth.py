"""M1: registration, Argon2id, login, lockout, JWT, sessions, refresh/CSRF, rate limits."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import get_settings
from app.models import AuditLog, AuthSession, User
from app.modules.audit import service as audit_service
from app.modules.auth import password as passwords
from app.modules.auth.rate_limit import limiter
from app.modules.auth.router import CSRF_COOKIE, CSRF_HEADER, REFRESH_COOKIE
from tests.helpers import fake_append_entries

PASSWORD = "correct horse battery staple"


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    limiter.reset()
    yield
    limiter.reset()


@pytest.fixture
def c(app):
    # https base URL: the Secure refresh/CSRF cookies are only sent over HTTPS.
    with TestClient(app, base_url="https://testserver") as client:
        yield client


def register(c, email="alice@example.com", username="alice", password=PASSWORD):
    return c.post("/api/v1/auth/register",
                  json={"email": email, "username": username, "password": password})


def login(c, email="alice@example.com", password=PASSWORD):
    return c.post("/api/v1/auth/login", json={"email": email, "password": password})


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def signed_in(c, **kw):
    assert register(c, **kw).status_code == 201
    r = login(c, kw.get("email", "alice@example.com"))
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


# --- registration and Argon2id -----------------------------------------------------------


def test_register_stores_only_an_argon2id_hash(c, db):
    r = register(c, email="  Alice@Example.COM ")
    assert r.status_code == 201
    body = r.json()
    assert body["email"] == "alice@example.com" and body["role"] == "user"
    assert "password" not in body and "password_hash" not in body
    user = db.scalar(select(User).where(User.email == "alice@example.com"))
    s = get_settings()
    assert user.password_hash.startswith(
        f"$argon2id$v=19$m={s.argon2_memory_cost_kib},t={s.argon2_time_cost},p={s.argon2_parallelism}$"
    )
    assert PASSWORD not in user.password_hash


def test_duplicate_email_or_username_is_rejected_case_insensitively(c):
    assert register(c).status_code == 201
    assert register(c, email="ALICE@example.com", username="other").status_code == 409
    assert register(c, email="new@example.com", username="ALICE").status_code == 409


@pytest.mark.parametrize(
    ("password", "status"),
    [("Zq9#pw", 422), ("alice-is-great-123", 422), ("alice@example.com", 422)],
)
def test_password_policy(c, password, status):
    r = register(c, password=password)
    assert r.status_code == status
    assert password not in r.text  # submitted values are never echoed back


# --- login, enumeration, lockout ---------------------------------------------------------


def test_login_sets_hardened_cookies_and_token_works(c):
    token = signed_in(c)
    cookies = login(c).headers.get_list("set-cookie")
    refresh = next(h for h in cookies if h.startswith(f"{REFRESH_COOKIE}="))
    csrf = next(h for h in cookies if h.startswith(f"{CSRF_COOKIE}="))
    for flag in ("HttpOnly", "Secure", "SameSite=strict", "Path=/api/v1/auth"):
        assert flag.lower() in refresh.lower()
    assert "httponly" not in csrf.lower() and "secure" in csrf.lower()
    me = c.get("/api/v1/auth/me", headers=bearer(token))
    assert me.status_code == 200 and me.json()["username"] == "alice"


def test_wrong_password_and_unknown_email_look_identical(c, monkeypatch):
    assert register(c).status_code == 201
    calls = []
    real_verify = passwords.verify_password
    monkeypatch.setattr(passwords, "verify_password",
                        lambda pw, h: calls.append(h) or real_verify(pw, h))
    from app.modules.auth import service
    monkeypatch.setattr(service, "verify_password", passwords.verify_password)

    wrong = login(c, password="wrong password!!")
    unknown = login(c, email="nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json()["error"]["message"] == unknown.json()["error"]["message"]
    assert len(calls) == 2  # the unknown email still paid for an Argon2id verification


def test_lockout_persists_and_blocks_even_the_right_password(c, db):
    assert register(c).status_code == 201
    max_failed = get_settings().max_failed_logins
    for _ in range(max_failed):
        assert login(c, password="wrong password!!").status_code == 401
    r = login(c)  # correct password, but locked
    assert r.status_code == 423
    db.expire_all()
    user = db.scalar(select(User).where(User.email == "alice@example.com"))
    assert user.locked_until is not None  # survived the request rollback

    user.locked_until = datetime.now(UTC) - timedelta(seconds=1)  # lock expired
    db.commit()
    assert login(c).status_code == 200
    db.expire_all()
    assert db.get(User, user.id).failed_login_count == 0


def test_failed_attempts_below_threshold_are_counted(c, db):
    assert register(c).status_code == 201
    login(c, password="wrong password!!")
    login(c, password="wrong password!!")
    db.expire_all()
    assert db.scalar(select(User.failed_login_count)) == 2


def test_inactive_user_cannot_log_in_and_existing_token_stops_working(c, db):
    token = signed_in(c)
    user = db.scalar(select(User))
    user.is_active = False
    db.commit()
    assert login(c).status_code == 401
    assert c.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_weaker_stored_hash_is_upgraded_on_login(c, db):
    assert register(c).status_code == 201
    user = db.scalar(select(User))
    user.password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(PASSWORD)
    db.commit()
    assert login(c).status_code == 200
    db.expire_all()
    assert ",t=1," not in db.get(User, user.id).password_hash


@pytest.mark.parametrize("email", ["' OR '1'='1", "admin'--@x.com", "a@b.com'; DROP TABLE users;--"])
def test_sql_injection_strings_are_harmless(c, db, email):
    assert register(c).status_code == 201
    r = login(c, email=email, password="' OR '1'='1")
    assert r.status_code in (401, 422)
    assert db.scalar(select(func.count()).select_from(User)) == 1


# --- access tokens -----------------------------------------------------------------------


def _claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def test_missing_token_is_401_with_www_authenticate(c):
    r = c.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"


def test_alg_none_token_is_rejected(c):
    token = signed_in(c)
    forged = jwt.encode(_claims(token), key=None, algorithm="none")
    assert c.get("/api/v1/auth/me", headers=bearer(forged)).status_code == 401


def test_token_signed_with_another_secret_is_rejected(c):
    token = signed_in(c)
    forged = jwt.encode(_claims(token), "x" * 48, algorithm="HS256")
    assert c.get("/api/v1/auth/me", headers=bearer(forged)).status_code == 401


def test_expired_token_is_rejected(c):
    token = signed_in(c)
    claims = _claims(token) | {"exp": int((datetime.now(UTC) - timedelta(minutes=1)).timestamp())}
    expired = jwt.encode(claims, get_settings().jwt_secret_key.get_secret_value(), "HS256")
    assert c.get("/api/v1/auth/me", headers=bearer(expired)).status_code == 401


def test_token_for_another_user_id_is_rejected(c):
    token = signed_in(c)
    claims = _claims(token) | {"sub": str(uuid.uuid4())}
    other = jwt.encode(claims, get_settings().jwt_secret_key.get_secret_value(), "HS256")
    assert c.get("/api/v1/auth/me", headers=bearer(other)).status_code == 401


# --- refresh, CSRF, logout, password change ----------------------------------------------


def _refresh(c, csrf=True):
    headers = {CSRF_HEADER: c.cookies.get(CSRF_COOKIE)} if csrf else {}
    return c.post("/api/v1/auth/refresh", headers=headers)


def test_refresh_requires_matching_csrf_header(c):
    signed_in(c)
    assert _refresh(c, csrf=False).status_code == 403
    assert c.post("/api/v1/auth/refresh", headers={CSRF_HEADER: "forged"}).status_code == 403


def test_refresh_rotates_tokens_and_old_access_token_ends(c):
    old_access = signed_in(c)
    old_refresh = c.cookies.get(REFRESH_COOKIE)
    r = _refresh(c)
    assert r.status_code == 200
    new_access = r.json()["access_token"]
    assert c.cookies.get(REFRESH_COOKIE) != old_refresh
    assert c.get("/api/v1/auth/me", headers=bearer(new_access)).status_code == 200
    assert c.get("/api/v1/auth/me", headers=bearer(old_access)).status_code == 401


def test_reused_refresh_token_revokes_every_session(c, db):
    signed_in(c)
    stolen = c.cookies.get(REFRESH_COOKIE)
    new_access = _refresh(c).json()["access_token"]

    attacker = TestClient(c.app, base_url="https://testserver")
    attacker.cookies.set(REFRESH_COOKIE, stolen)
    attacker.cookies.set(CSRF_COOKIE, "t")
    r = attacker.post("/api/v1/auth/refresh", headers={CSRF_HEADER: "t"})
    assert r.status_code == 401
    db.expire_all()
    active = db.scalar(
        select(func.count()).select_from(AuthSession).where(AuthSession.revoked_at.is_(None))
    )
    assert active == 0
    assert c.get("/api/v1/auth/me", headers=bearer(new_access)).status_code == 401


def test_logout_revokes_the_session_and_clears_cookies(c):
    token = signed_in(c)
    r = c.post("/api/v1/auth/logout", headers=bearer(token))
    assert r.status_code == 204
    assert any(h.startswith(f"{REFRESH_COOKIE}=") and "max-age=0" in h.lower()
               for h in r.headers.get_list("set-cookie"))
    assert c.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_change_password(c):
    token = signed_in(c)
    url = "/api/v1/auth/change-password"
    new = "an entirely new passphrase"
    wrong = c.post(url, headers=bearer(token),
                   json={"current_password": "not it at all", "new_password": new})
    assert wrong.status_code == 403
    ok = c.post(url, headers=bearer(token), json={"current_password": PASSWORD, "new_password": new})
    assert ok.status_code == 204
    assert c.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401  # sessions ended
    assert login(c).status_code == 401
    assert login(c, password=new).status_code == 200


# --- rate limiting -----------------------------------------------------------------------


def test_login_is_rate_limited_per_client(c):
    limit = get_settings().rate_limit_login_per_minute
    for _ in range(limit):
        assert login(c, email="nobody@example.com").status_code == 401
    r = login(c, email="nobody@example.com")
    assert r.status_code == 429
    assert int(r.headers["retry-after"]) >= 1


def test_register_is_rate_limited(c):
    limit = get_settings().rate_limit_register_per_hour
    for i in range(limit):
        register(c, email=f"user{i}@example.com", username=f"user{i}", password="x" * 5)
    r = register(c, email="last@example.com", username="lastuser")
    assert r.status_code == 429


# --- audit -------------------------------------------------------------------------------


def test_failed_logins_are_audited_even_though_the_request_rolls_back(c, db, monkeypatch):
    monkeypatch.setattr(audit_service, "append_entries", fake_append_entries)
    assert register(c).status_code == 201
    login(c, password="wrong password!!")
    login(c, email="nobody@example.com")
    login(c)
    rows = db.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert [(r.event_type, r.outcome) for r in rows] == [
        ("auth.register", "success"),
        ("auth.login_failed", "failure"),
        ("auth.login_failed", "failure"),
        ("auth.login", "success"),
    ]
    assert all(PASSWORD not in str(r.details) for r in rows)
