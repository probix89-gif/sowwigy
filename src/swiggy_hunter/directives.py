"""
DirectiveQueue — operator messages that must reach the decision-maker.

Append-only JSONL file. Survives restarts. Consumed in bulk each
decision cycle, with the assistant's operator_reply attached.

Kinds:
  chat      — free text (default; plain telegram message)
  task      — force-create a task (/inject)
  note      — append to plan notes (/note)
  priority  — bump priority (reserved; not fully wired)
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal

from .logging_setup import get_logger

log = get_logger(__name__)


DirectiveKind = Literal["chat", "task", "note", "priority"]


@dataclass
class Directive:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:10])
    at: float = field(default_factory=time.time)
    text: str = ""
    kind: DirectiveKind = "chat"
    consumed: bool = False
    consumed_at: float | None = None
    response: str | None = None
    meta: dict = field(default_factory=dict)

    def to_line(self) -> str:
        return json.dumps(asdict(self))


class DirectiveQueue:
    def __init__(self, path: str | Path = "./data/directives.jsonl"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self.path.touch()

    def push(self, text: str, kind: DirectiveKind = "chat",
             meta: dict | None = None) -> Directive:
        d = Directive(text=text.strip(), kind=kind, meta=meta or {})
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(d.to_line() + "\n")
        log.info("directive.push", id=d.id, kind=kind, len=len(text))
        return d

    def _read_all(self) -> list[Directive]:
        out: list[Directive] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                out.append(Directive(**obj))
            except Exception:
                continue
        return out

    def pending(self, limit: int = 20) -> list[Directive]:
        return [d for d in self._read_all() if not d.consumed][:limit]

    def mark_consumed(self, ids: list[str], response: str | None = None) -> None:
        wanted = set(ids)
        entries = self._read_all()
        now = time.time()
        for d in entries:
            if d.id in wanted:
                d.consumed = True
                d.consumed_at = now
                if response is not None:
                    d.response = response
        tmp = self.path.with_suffix(".jsonl.tmp")
        tmp.write_text("\n".join(d.to_line() for d in entries) + "\n", encoding="utf-8")
        tmp.replace(self.path)

    def recent(self, limit: int = 20) -> list[Directive]:
        return list(reversed(self._read_all()))[:limit]
