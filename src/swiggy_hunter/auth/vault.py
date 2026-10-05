"""
SessionVault — encrypted-at-rest storage for authenticated sessions.

Every persisted identity (phone, cookies, headers, fingerprint id) is
stored in a single encrypted file. The vault key comes from
SWIGGY_SESSION_VAULT_KEY in .env (Fernet base64 key). If unset, a fresh
key is generated on first boot and written to data/.vault_key (0600).

Public API:
    vault = SessionVault(data_dir, key=None)
    vault.save(session_info)
    vault.load(name) -> SessionInfo | None
    vault.list_names() -> list[str]
    vault.delete(name) -> bool
"""
from __future__ import annotations

import base64
import json
import os
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from ..logging_setup import get_logger
from ..state.schemas import SessionInfo

log = get_logger(__name__)


KEY_FILE_NAME = ".vault_key"
VAULT_FILE_NAME = "sessions.vault"


class SessionVault:
    def __init__(self, data_dir: str | Path, key: str | None = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_path = self.data_dir / KEY_FILE_NAME
        self.vault_path = self.data_dir / VAULT_FILE_NAME
        self._fernet = Fernet(self._resolve_key(key))

    # ------------------------------------------------------------------
    # key management
    # ------------------------------------------------------------------

    def _resolve_key(self, provided: str | None) -> bytes:
        if provided:
            try:
                return provided.encode() if isinstance(provided, str) else provided
            except Exception:
                pass
        env_key = os.environ.get("SWIGGY_SESSION_VAULT_KEY")
        if env_key:
            return env_key.encode()
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        # generate + persist with tight permissions
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        try:
            os.chmod(self.key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except Exception:
            pass
        log.warning("vault.key_generated", path=str(self.key_path))
        return key

    # ------------------------------------------------------------------
    # internal io
    # ------------------------------------------------------------------

    def _read_all(self) -> dict[str, dict[str, Any]]:
        if not self.vault_path.exists():
            return {}
        try:
            blob = self.vault_path.read_bytes()
            plain = self._fernet.decrypt(blob)
            return json.loads(plain.decode("utf-8"))
        except InvalidToken:
            log.error("vault.invalid_token")
            return {}
        except Exception:
            log.exception("vault.read_failed")
            return {}

    def _write_all(self, data: dict[str, dict[str, Any]]) -> None:
        plain = json.dumps(data, indent=2).encode("utf-8")
        blob = self._fernet.encrypt(plain)
        tmp = self.vault_path.with_suffix(".vault.tmp")
        tmp.write_bytes(blob)
        tmp.replace(self.vault_path)
        try:
            os.chmod(self.vault_path, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # public api
    # ------------------------------------------------------------------

    def save(self, session: SessionInfo) -> None:
        data = self._read_all()
        session.updated_at = time.time()
        data[session.name] = session.model_dump(mode="json")
        self._write_all(data)
        log.info("vault.save", name=session.name)

    def load(self, name: str) -> SessionInfo | None:
        data = self._read_all()
        raw = data.get(name)
        if not raw:
            return None
        try:
            return SessionInfo(**raw)
        except Exception:
            log.exception("vault.load_failed", name=name)
            return None

    def list_names(self) -> list[str]:
        return sorted(self._read_all().keys())

    def list_all(self) -> list[SessionInfo]:
        out: list[SessionInfo] = []
        for name in self.list_names():
            s = self.load(name)
            if s:
                out.append(s)
        return out

    def delete(self, name: str) -> bool:
        data = self._read_all()
        if name not in data:
            return False
        del data[name]
        self._write_all(data)
        log.info("vault.delete", name=name)
        return True

    def purge_expired(self) -> int:
        now = time.time()
        data = self._read_all()
        removed = 0
        for name, raw in list(data.items()):
            exp = raw.get("expires_at")
            if exp and exp < now:
                del data[name]
                removed += 1
        if removed:
            self._write_all(data)
            log.info("vault.purge_expired", removed=removed)
        return removed
