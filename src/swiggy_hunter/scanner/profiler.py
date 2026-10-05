"""
TargetProfiler — cached model of hosts/endpoints/technologies/flows.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..logging_setup import get_logger

log = get_logger(__name__)


@dataclass
class Host:
    hostname: str
    first_seen: float = field(default_factory=time.time)
    technologies: list[str] = field(default_factory=list)
    endpoints: dict[str, dict[str, Any]] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class TargetProfiler:
    def __init__(self, data_dir: str | Path = "./data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "profile.json"
        self.hosts: dict[str, Host] = {}
        self.flows: list[dict[str, Any]] = []
        self.load()

    def note_host(self, hostname: str) -> Host:
        h = self.hosts.get(hostname)
        if h is None:
            h = Host(hostname=hostname)
            self.hosts[hostname] = h
        return h

    def note_technology(self, hostname: str, tech: str) -> None:
        h = self.note_host(hostname)
        if tech not in h.technologies:
            h.technologies.append(tech)
        self.flush()

    def note_endpoint(self, hostname: str, method: str, path: str,
                      status: int | None = None, notes: str | None = None) -> None:
        h = self.note_host(hostname)
        key = f"{method.upper()} {path}"
        e = h.endpoints.setdefault(key, {
            "method": method.upper(), "path": path,
            "first_seen": time.time(), "status_samples": [], "notes": [],
        })
        if status is not None and status not in e["status_samples"]:
            e["status_samples"].append(status)
        if notes:
            e["notes"].append(notes)
        self.flush()

    def note_flow(self, name: str, steps: list[str], notes: str = "") -> None:
        self.flows.append({
            "name": name, "steps": steps, "notes": notes,
            "recorded_at": time.time(),
        })
        self.flush()

    def summary(self) -> dict[str, Any]:
        return {
            "hosts": {
                n: {
                    "technologies": h.technologies,
                    "endpoint_count": len(h.endpoints),
                    "notes": h.notes[-5:],
                }
                for n, h in self.hosts.items()
            },
            "flows": [{"name": f["name"], "steps": f["steps"]} for f in self.flows],
        }

    def flush(self) -> None:
        try:
            payload = {
                "hosts": {
                    n: {
                        "hostname": h.hostname, "first_seen": h.first_seen,
                        "technologies": h.technologies,
                        "endpoints": h.endpoints, "notes": h.notes,
                    }
                    for n, h in self.hosts.items()
                },
                "flows": self.flows,
                "saved_at": time.time(),
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            tmp.replace(self.path)
        except Exception:
            log.exception("profiler.flush_failed")

    def load(self) -> None:
        if not self.path.exists():
            return
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for name, hv in (data.get("hosts") or {}).items():
                h = Host(hostname=hv.get("hostname", name),
                         first_seen=hv.get("first_seen") or time.time())
                h.technologies = list(hv.get("technologies") or [])
                h.endpoints = dict(hv.get("endpoints") or {})
                h.notes = list(hv.get("notes") or [])
                self.hosts[name] = h
            self.flows = list(data.get("flows") or [])
        except Exception:
            log.exception("profiler.load_failed")

    def reset(self) -> None:
        self.hosts.clear()
        self.flows.clear()
        self.flush()
