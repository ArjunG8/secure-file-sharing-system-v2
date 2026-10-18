"""Encrypted blob storage under STORAGE_DIR.

On-disk names are always "<file uuid>.bin": user-supplied filenames are metadata only,
so they can never choose a path. Writes go to a temporary file in the same directory,
are fsync'ed, then atomically renamed.
"""

import os
import tempfile
import uuid
from pathlib import Path

from app.core.config import get_settings


class StorageError(Exception):
    pass


def storage_root() -> Path:
    root = get_settings().storage_dir.resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def blob_name(file_id: uuid.UUID) -> str:
    return f"{file_id}.bin"


def resolve(name: str) -> Path:
    """Map a stored name back to a path, refusing anything outside the storage root."""
    root = storage_root()
    if not name or Path(name).name != name:
        raise StorageError("invalid blob name")
    path = (root / name).resolve()
    if path.parent != root:
        raise StorageError("blob path escapes the storage directory")
    return path


def write(file_id: uuid.UUID, data: bytes) -> str:
    name = blob_name(file_id)
    target = resolve(name)
    fd, tmp = tempfile.mkstemp(prefix=".upload-", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return name


def read(name: str) -> bytes:
    try:
        return resolve(name).read_bytes()
    except FileNotFoundError as exc:
        raise StorageError("blob missing") from exc


def delete(name: str) -> None:
    try:
        resolve(name).unlink(missing_ok=True)
    except StorageError:
        pass
