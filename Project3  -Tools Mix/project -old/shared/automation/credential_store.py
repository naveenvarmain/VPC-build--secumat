"""Encrypted storage for integration credentials."""
import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken


REPO_ROOT = Path(__file__).resolve().parents[1]
SETTINGS_PATH = REPO_ROOT / "data" / "manual_api_integrations.json"
KEY_ENV = "INTEGRATION_ENCRYPTION_KEY"


def _fernet() -> Fernet:
    key = str(os.environ.get(KEY_ENV) or "").strip()
    if not key:
        raise RuntimeError(f"{KEY_ENV} must be set before saving or reading encrypted credentials.")
    try:
        return Fernet(key.encode("ascii"))
    except Exception as exc:
        raise RuntimeError(f"{KEY_ENV} must contain a valid Fernet key.") from exc


def _read_records() -> list[Dict[str, Any]]:
    if not SETTINGS_PATH.exists():
        return []
    try:
        records = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return [item for item in records if isinstance(item, dict)] if isinstance(records, list) else []
    except (OSError, ValueError):
        return []


def _write_records(records: list[Dict[str, Any]]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(records, indent=2), encoding="utf-8")


def save_integration_token(slug: str, token: str) -> None:
    token = str(token or "").strip()
    if not token:
        raise ValueError("api_token is required")
    records = _read_records()
    record = next((item for item in records if item.get("slug") == slug), None)
    if record is None:
        record = {"slug": slug}
        records.append(record)
    record["encrypted_api_token"] = _fernet().encrypt(token.encode("utf-8")).decode("ascii")
    _write_records(records)


def load_integration_token(slug: str) -> Optional[str]:
    record = next((item for item in _read_records() if item.get("slug") == slug), None)
    encrypted = str((record or {}).get("encrypted_api_token") or "").strip()
    if not encrypted:
        return None
    try:
        return _fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise RuntimeError(f"Encrypted credential for {slug} cannot be decrypted.") from exc


def token_saved(slug: str) -> bool:
    return any(
        item.get("slug") == slug and bool(str(item.get("encrypted_api_token") or "").strip())
        for item in _read_records()
    )
