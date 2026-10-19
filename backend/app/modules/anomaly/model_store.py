"""Isolation Forest persistence with an integrity check BEFORE unpickling.

joblib files are pickles: loading one can execute code. Each saved model therefore gets
an HMAC-SHA256 tag (key derived from MASTER_KEY_ENCRYPTION_KEY with HKDF) in its metadata
file, and load() refuses any model whose bytes don't match - e.g. a file dropped into
MODEL_DIR by someone without the master key.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

import joblib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sklearn.ensemble import IsolationForest

from app.core.config import get_settings

LATEST = "latest.json"


class ModelIntegrityError(Exception):
    pass


@dataclass(frozen=True)
class ModelMeta:
    model_version: str
    features: list[str]
    trained_on_windows: int
    trained_on_events: int
    contamination: float
    hmac_sha256: str


def _dir() -> Path:
    path = get_settings().model_dir.resolve()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def _integrity_key() -> bytes:
    master = base64.b64decode(get_settings().master_key_encryption_key.get_secret_value())
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sfs-model-integrity-v1").derive(master)


def _tag(data: bytes) -> str:
    return hmac.new(_integrity_key(), data, hashlib.sha256).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".model-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def save(model: IsolationForest, meta_without_tag: dict) -> ModelMeta:
    buffer = io.BytesIO()
    joblib.dump(model, buffer)
    data = buffer.getvalue()
    meta = ModelMeta(**meta_without_tag, hmac_sha256=_tag(data))
    directory = _dir()
    _atomic_write(directory / f"{meta.model_version}.joblib", data)
    _atomic_write(directory / f"{meta.model_version}.json", json.dumps(asdict(meta)).encode())
    _atomic_write(directory / LATEST, json.dumps({"model_version": meta.model_version}).encode())
    return meta


def load_latest() -> tuple[IsolationForest, ModelMeta] | None:
    directory = _dir()
    pointer = directory / LATEST
    if not pointer.exists():
        return None
    version = json.loads(pointer.read_text())["model_version"]
    if Path(version).name != version:
        raise ModelIntegrityError("invalid model version name")
    meta = ModelMeta(**json.loads((directory / f"{version}.json").read_text()))
    data = (directory / f"{version}.joblib").read_bytes()
    if not hmac.compare_digest(meta.hmac_sha256, _tag(data)):
        raise ModelIntegrityError("model file failed its integrity check")
    model = joblib.load(io.BytesIO(data))  # only after the HMAC matched
    if not isinstance(model, IsolationForest):
        raise ModelIntegrityError("unexpected model type")
    return model, meta
