"""M7: feature extraction, Isolation Forest train/score, model integrity, API.

Detection-quality assertions use SYNTHETIC data (app/modules/anomaly/synthetic.py) and
only guard against regressions of the pipeline; they say nothing about real-world accuracy.
"""

import json
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.models import AnomalyDetection, AuditLog
from app.modules.anomaly import model_store
from app.modules.anomaly.evaluate import evaluate
from app.modules.anomaly.features import FEATURES, extract_features, extract_windows
from app.modules.anomaly.service import fit, score_windows
from app.modules.anomaly.synthetic import attack_hour, dataset, normal_hour

T0 = datetime(2026, 3, 2, 10, 0, tzinfo=UTC)


def ev(event_type, minute=0, user=None, ip="10.0.0.1", details=None, when=None):
    return SimpleNamespace(event_type=event_type, actor_user_id=user or USER, ip_address=ip,
                           details=details or {}, id=None,
                           occurred_at=when if when is not None else T0 + timedelta(minutes=minute))


USER = uuid.uuid4()


# --- features ----------------------------------------------------------------------------


def test_features_count_one_user_hour_exactly():
    events = [ev("auth.login"), ev("auth.login_failed", 1), ev("auth.login_failed", 2, ip="1.2.3.4"),
              ev("file.download", 3, details={"size_bytes": 2_500_000}), ev("file.upload", 4),
              ev("share.access_denied", 5), ev("share.create", 6), ev("file.integrity_failure", 7)]
    [features] = extract_features(events)
    assert list(features) == list(FEATURES)
    assert features == {
        "events_total": 8, "logins_ok": 1, "logins_failed": 2, "access_denied": 1,
        "integrity_failures": 1, "uploads": 1, "downloads": 1, "shares_created": 1,
        "distinct_ips": 2, "mb_downloaded": 2.5, "off_hours": 0,
    }


def test_windows_split_by_user_and_hour_and_flag_off_hours():
    other = uuid.uuid4()
    night = datetime(2026, 3, 2, 3, 30, tzinfo=UTC)
    windows = extract_windows([ev("auth.login"), ev("auth.login", 61), ev("auth.login", user=other),
                               ev("auth.login", when=night)])
    assert len(windows) == 4
    assert [w.counts["off_hours"] for w in windows] == [1.0, 0.0, 0.0, 0.0]


@pytest.mark.parametrize("bad", [
    {"event_type": None}, {"occurred_at": "yesterday"}, {"actor_user_id": None},
])
def test_malformed_events_are_skipped(bad):
    event = ev("auth.login")
    for key, value in bad.items():
        setattr(event, key, value)
    assert extract_features([event]) == []


@pytest.mark.parametrize("details", ["not a dict", {"size_bytes": -5}, {"size_bytes": "big"},
                                     {"size_bytes": True}, None])
def test_malformed_sizes_count_as_zero(details):
    event = ev("file.download")
    event.details = details
    [features] = extract_features([event])
    assert features["downloads"] == 1 and features["mb_downloaded"] == 0


def test_naive_timestamps_are_treated_as_utc():
    [a] = extract_windows([ev("auth.login", when=datetime(2026, 3, 2, 10, 5))])
    assert a.window_start == datetime(2026, 3, 2, 10, 0, tzinfo=UTC)


# --- model -------------------------------------------------------------------------------


def test_synthetic_evaluation_separates_attacks_from_normal_hours():
    m = evaluate(train_seed=1, test_seed=2)
    assert m["attacks"] == 15
    assert m["recall"] >= 0.9  # measured 1.000 (synthetic)
    assert m["false_positive_rate"] <= 0.05  # measured 0.015 (synthetic)


def test_purely_normal_activity_is_rarely_flagged():
    events, _ = dataset(seed=7, attacks=0)
    model = fit(extract_windows(events), contamination=0.05)
    import random
    rng = random.Random(8)  # noqa: S311 - reproducible test data
    fresh = []
    for i in range(40):
        fresh += normal_hour(rng, uuid.uuid4(), T0 + timedelta(hours=i % 8))
    flags = [f for _, f in score_windows(model, extract_windows(fresh))]
    assert sum(flags) / len(flags) <= 0.15


def test_each_attack_profile_scores_below_normal():
    import random
    events, _ = dataset(seed=3, attacks=0)
    model = fit(extract_windows(events), contamination=0.05)
    rng = random.Random(4)  # noqa: S311 - reproducible test data
    normal = score_windows(model, extract_windows(normal_hour(rng, uuid.uuid4(), T0)))
    attacks = [score_windows(model, extract_windows(attack_hour(rng, uuid.uuid4(), T0)))[0]
               for _ in range(12)]
    assert all(flagged for _, flagged in attacks)
    assert max(s for s, _ in attacks) < normal[0][0]


def _trained():
    events, _ = dataset(seed=1)
    windows = extract_windows(events)
    return model_store.save(fit(windows, 0.05), {
        "model_version": "iforest-test", "features": list(FEATURES),
        "trained_on_windows": len(windows), "trained_on_events": len(events),
        "contamination": 0.05})


def test_model_round_trips_through_storage():
    meta = _trained()
    model, loaded = model_store.load_latest()
    assert loaded == meta and model.n_estimators == 200


def test_tampered_model_file_is_never_unpickled():
    _trained()
    path = get_settings().model_dir / "iforest-test.joblib"
    data = bytearray(path.read_bytes())
    data[-10] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(model_store.ModelIntegrityError):
        model_store.load_latest()


def test_model_tag_from_another_master_key_is_rejected(monkeypatch):
    import base64
    import os

    from pydantic import SecretStr

    _trained()
    monkeypatch.setattr(get_settings(), "master_key_encryption_key",
                        SecretStr(base64.b64encode(os.urandom(32)).decode()))
    with pytest.raises(model_store.ModelIntegrityError):
        model_store.load_latest()


def test_latest_pointer_cannot_escape_the_model_dir():
    _trained()
    (get_settings().model_dir / "latest.json").write_text(json.dumps({"model_version": "../x"}))
    with pytest.raises(model_store.ModelIntegrityError):
        model_store.load_latest()


# --- API ---------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _fresh_model_dir():
    for path in get_settings().model_dir.glob("*"):
        path.unlink()
    yield


def insert_synthetic(db, create_user, seed=1, **kw):
    """Store a synthetic dataset as audit_logs rows, mapping synthetic users to real ones."""
    events, labels = dataset(seed, **kw)
    users = {}
    for i, e in enumerate(events):
        if e.actor_user_id not in users:
            users[e.actor_user_id] = create_user().id
        db.add(AuditLog(occurred_at=e.occurred_at, actor_user_id=users[e.actor_user_id],
                        event_type=e.event_type, outcome=e.outcome, ip_address=e.ip_address,
                        details=e.details, prev_hash="0" * 64, entry_hash=f"{i:064x}"))
    db.commit()
    return {(users[u], start) for u, start in labels}


def test_training_needs_enough_activity(client_as, create_user):
    admin = create_user(role="admin")
    r = client_as(admin).post("/api/v1/anomaly/train", json={})
    assert r.status_code == 422 and "Not enough activity" in r.json()["error"]["message"]


def test_scoring_before_training_is_409(client_as, create_user):
    admin = create_user(role="admin")
    assert client_as(admin).post("/api/v1/anomaly/score", json={}).status_code == 409


def test_train_score_and_list(client_as, create_user, db):
    admin = create_user(role="admin")
    labels = insert_synthetic(db, create_user)
    c = client_as(admin)
    info = c.post("/api/v1/anomaly/train", json={}).json()
    assert info["features"] == list(FEATURES) and info["trained_on_windows"] > 300

    since = datetime(2026, 3, 1, tzinfo=UTC).isoformat()
    scored = c.post("/api/v1/anomaly/score", json={"since": since})
    assert scored.status_code == 200
    flagged = {(uuid.UUID(d["user_id"]), datetime.fromisoformat(d["window_start"]).astimezone(UTC))
               for d in scored.json() if d["is_anomaly"]}
    assert len(labels & flagged) / len(labels) >= 0.9  # synthetic attacks found

    listed = c.get("/api/v1/anomaly/detections?only_anomalies=true").json()
    assert listed["total"] == len(flagged) and all(d["is_anomaly"] for d in listed["items"])
    everything = c.get("/api/v1/anomaly/detections?only_anomalies=false").json()
    assert everything["total"] == len(scored.json())
    assert db.scalar(select(AnomalyDetection.model_version)) == info["model_version"]


def test_anomaly_endpoints_are_admin_only(client_as, create_user):
    user = create_user()
    c = client_as(user)
    assert c.post("/api/v1/anomaly/train", json={}).status_code == 403
    assert c.post("/api/v1/anomaly/score", json={}).status_code == 403
    assert c.get("/api/v1/anomaly/detections").status_code == 403


def test_tampered_model_makes_scoring_fail_closed(client_as, create_user, db):
    admin = create_user(role="admin")
    insert_synthetic(db, create_user)
    c = client_as(admin)
    version = c.post("/api/v1/anomaly/train", json={}).json()["model_version"]
    path = get_settings().model_dir / f"{version}.joblib"
    path.write_bytes(path.read_bytes() + b"tampered")
    r = c.post("/api/v1/anomaly/score", json={})
    assert r.status_code == 500 and "integrity" in r.json()["error"]["message"]
