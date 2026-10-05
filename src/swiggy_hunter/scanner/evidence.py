"""
EvidenceCollector — per-finding folder on disk.

data/evidence/<finding_id>/
  meta.json
  notes.md
  requests.log
  capture_*.json      (raw request/response captures)
  exploit.py          (if attacker wrote one)
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger

log = get_logger(__name__)

_SAFE = re.compile(r"[^a-zA-Z0-9_\-\.]")


def _safe(name: str, max_len: int = 60) -> str:
    return (_SAFE.sub("_", name)[:max_len]) or "unnamed"


class EvidenceCollector:
    def __init__(self, data_dir: str | Path = "./data"):
        self.root = Path(data_dir) / "evidence"
        self.root.mkdir(parents=True, exist_ok=True)

    def _folder(self, finding_id: str) -> Path:
        p = self.root / _safe(finding_id)
        p.mkdir(parents=True, exist_ok=True)
        return p

    def save_meta(self, finding_id: str, meta: dict[str, Any]) -> None:
        folder = self._folder(finding_id)
        (folder / "meta.json").write_text(
            json.dumps(meta, indent=2, default=str), encoding="utf-8"
        )

    def note(self, finding_id: str, text: str) -> None:
        folder = self._folder(finding_id)
        with (folder / "notes.md").open("a", encoding="utf-8") as fh:
            fh.write(f"\n## {time.strftime('%Y-%m-%d %H:%M:%S')}\n{text}\n")

    def collect(self, finding_id: str, capture: dict[str, Any],
                label: str = "") -> Path:
        folder = self._folder(finding_id)
        ts = int(time.time() * 1000)
        tag = _safe(label) if label else f"capture_{ts}"
        path = folder / f"{ts}_{tag}.json"
        try:
            path.write_text(
                json.dumps(capture, indent=2, default=str), encoding="utf-8"
            )
            req = capture.get("request") or {}
            resp = capture.get("response") or {}
            with (folder / "requests.log").open("a", encoding="utf-8") as fh:
                fh.write(
                    f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
                    f"{req.get('method','?')} {req.get('url','?')} "
                    f"-> {resp.get('status','?')} "
                    f"({resp.get('elapsed_ms','?')}ms) file={path.name}\n"
                )
            return path
        except Exception:
            log.exception("evidence.collect_failed", finding_id=finding_id)
            return folder

    def save_exploit(self, finding_id: str, code: str) -> Path:
        folder = self._folder(finding_id)
        path = folder / "exploit.py"
        path.write_text(code, encoding="utf-8")
        path.chmod(0o755)
        return path

    def list_evidence(self, finding_id: str) -> list[Path]:
        return sorted(self._folder(finding_id).glob("*"))
