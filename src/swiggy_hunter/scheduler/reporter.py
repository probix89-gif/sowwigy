"""
ReporterLoop — periodic progress + findings report to telegram.

Default interval: 30 minutes. Also exposes build_report() for the
/progress command.

The report covers:
  - runtime state + uptime
  - auth + stealth status
  - task counts
  - agent states
  - new findings since last report (grouped by severity)
  - token usage today
  - narrative (current focus + next actions)
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Awaitable, Callable

from ..logging_setup import get_logger
from ..state.blackboard import Blackboard

log = get_logger(__name__)


ReportSender = Callable[[str], Awaitable[None]]


class ReporterLoop:
    def __init__(
        self,
        blackboard: Blackboard,
        sender: ReportSender,
        stop_event: asyncio.Event,
        interval_minutes: int = 30,
        usage_snapshot: Callable[[], Awaitable[dict]] | None = None,
        lifecycle_snapshot: Callable[[], dict] | None = None,
        runtime_snapshot: Callable[[], dict] | None = None,
    ):
        self.blackboard = blackboard
        self.sender = sender
        self.stop_event = stop_event
        self.interval_s = max(60, interval_minutes * 60)
        self.usage_snapshot = usage_snapshot
        self.lifecycle_snapshot = lifecycle_snapshot
        self.runtime_snapshot = runtime_snapshot

        self._last_seen_finding_ids: set[str] = set()

    async def run(self) -> None:
        log.info("reporter.start", interval_s=self.interval_s)
        findings = await self.blackboard.list_findings()
        self._last_seen_finding_ids = {f.id for f in findings}

        while not self.stop_event.is_set():
            await self._sleep(self.interval_s)
            if self.stop_event.is_set():
                break
            try:
                await self.send_report()
            except Exception:
                log.exception("reporter.send_failed")
        log.info("reporter.stop")

    async def send_report(self) -> None:
        text = await self.build_report()
        await self.sender(text)

    async def build_report(self) -> str:
        findings = await self.blackboard.list_findings()
        tasks = await self.blackboard.list_tasks()
        agents = await self.blackboard.agent_statuses()
        narrative = self._read_narrative()

        new_findings = [f for f in findings if f.id not in self._last_seen_finding_ids]
        self._last_seen_finding_ids.update(f.id for f in new_findings)

        sev_buckets: dict[str, list] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": [],
        }
        for f in new_findings:
            sev_buckets.setdefault(f.severity.value, []).append(f)

        lines: list[str] = []
        lines.append("📊 <b>Swiggy Hunter — Progress Report</b>")
        lines.append(f"<i>{time.strftime('%Y-%m-%d %H:%M:%S')}</i>")
        lines.append("")

        if self.lifecycle_snapshot:
            snap = self.lifecycle_snapshot()
            uptime = self._fmt_duration(snap.get("uptime_s", 0))
            lines.append(
                f"<b>State:</b> <code>{snap.get('state', 'unknown')}</code> · "
                f"uptime {uptime}"
            )
            lines.append("")

        if self.runtime_snapshot:
            rt = self.runtime_snapshot()
            auth = rt.get("auth") or {}
            stealth = rt.get("stealth") or {}
            auth_marker = "🟢" if auth.get("authenticated") else "🔴"
            lines.append(
                f"{auth_marker} <b>Auth:</b> "
                f"{'logged in' if auth.get('authenticated') else 'not logged in'}"
                + (f" ({auth.get('phone')})" if auth.get("phone") else "")
            )
            if stealth:
                fp = stealth.get("fingerprint") or "?"
                reqs = stealth.get("requests") or 0
                lines.append(f"🥷 <b>Stealth:</b> fp <code>{fp}</code> · {reqs} reqs")
                beh = stealth.get("behavior") or {}
                if beh.get("consecutive_403") or beh.get("consecutive_429"):
                    lines.append(
                        f"   blocks: 403×{beh.get('consecutive_403', 0)} "
                        f"429×{beh.get('consecutive_429', 0)}"
                    )
            lines.append("")

        lines.append("<b>Progress</b>")
        lines.append(f"• tasks total: <code>{len(tasks)}</code>")
        lines.append(
            f"• pending: <code>{sum(1 for t in tasks if t.status.value == 'pending')}</code> · "
            f"running: <code>{sum(1 for t in tasks if t.status.value == 'running')}</code> · "
            f"done: <code>{sum(1 for t in tasks if t.status.value == 'done')}</code> · "
            f"failed: <code>{sum(1 for t in tasks if t.status.value == 'failed')}</code>"
        )
        lines.append("")

        lines.append("<b>Agents</b>")
        for a in agents:
            marker = {
                "working": "🟢", "idle": "🟡", "blocked": "🔴",
                "error": "🔴", "stopped": "⚫",
            }.get(a.state, "•")
            lines.append(f"{marker} <code>{a.name.value}</code> — {a.state}")
        lines.append("")

        lines.append(
            f"<b>Findings</b> — total <code>{len(findings)}</code> · "
            f"new <code>{len(new_findings)}</code>"
        )
        for sev in ("critical", "high", "medium", "low", "info"):
            bucket = sev_buckets.get(sev, [])
            if not bucket:
                continue
            lines.append(f"<i>{sev}</i> ({len(bucket)})")
            for f in bucket[:5]:
                lines.append(f"  • <code>{f.id}</code> {f.title[:80]}")
            if len(bucket) > 5:
                lines.append(f"  …and {len(bucket) - 5} more")
        if not new_findings:
            lines.append("<i>no new findings</i>")
        lines.append("")

        if self.usage_snapshot:
            usage = await self.usage_snapshot()
            today = usage.get("days", {}).get(time.strftime("%Y-%m-%d"), {})
            total = today.get("total", 0)
            calls = today.get("calls", 0)
            lines.append(
                f"<b>Tokens today:</b> <code>{total:,}</code> over {calls} calls"
            )
            by_agent = today.get("by_agent", {})
            if by_agent:
                for k, v in sorted(by_agent.items(), key=lambda x: -x[1])[:6]:
                    lines.append(f"  • <code>{k}</code> {v:,}")
            lines.append("")

        if narrative.get("current_focus"):
            lines.append("<b>Current focus</b>")
            lines.append(f"<i>{narrative['current_focus']}</i>")
        if narrative.get("next_actions"):
            lines.append("<b>Next actions</b>")
            lines.append(f"<i>{narrative['next_actions']}</i>")

        return "\n".join(lines)

    def _read_narrative(self) -> dict[str, str]:
        import re
        try:
            text = self.blackboard.path.read_text(encoding="utf-8")
        except Exception:
            return {}
        out: dict[str, str] = {}
        for key in ("Mission", "Current Focus", "Next Actions", "Notes"):
            m = re.search(rf"## {key}\n(.*?)(?=\n## |\Z)", text, re.DOTALL)
            if m:
                out[key.lower().replace(" ", "_")] = m.group(1).strip()
        return out

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        seconds = int(seconds)
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m}m"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop_event.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass
