"""
ReportBuilder — produces the full markdown report.

Used by /report, /findings (summary), and the final export.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from typing import Any

from ..state.blackboard import Blackboard
from ..state.schemas import Finding, FindingStatus


class ReportBuilder:
    def __init__(self, blackboard: Blackboard):
        self.blackboard = blackboard

    async def full_report(self) -> str:
        findings = await self.blackboard.list_findings()
        tasks = await self.blackboard.list_tasks()
        narrative = self._read_narrative()

        lines = [
            "# Swiggy Hunter — Full Report",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
        ]
        if narrative.get("mission"):
            lines.append(f"**Mission:** {narrative['mission']}")
            lines.append("")

        lines.append("## Summary")
        lines.append(f"- Findings total: **{len(findings)}**")
        by_sev: dict[str, int] = defaultdict(int)
        by_status: dict[str, int] = defaultdict(int)
        for f in findings:
            by_sev[f.severity.value] += 1
            by_status[f.status.value] += 1
        for sev in ("critical", "high", "medium", "low", "info"):
            if by_sev.get(sev):
                lines.append(f"  - {sev}: {by_sev[sev]}")
        lines.append("")
        for st in ("confirmed", "validating", "new", "false_positive", "reported"):
            if by_status.get(st):
                lines.append(f"  - {st}: {by_status[st]}")
        lines.append("")

        lines.append("## Tasks")
        lines.append(f"- Total: {len(tasks)}")
        by_task_status: dict[str, int] = defaultdict(int)
        for t in tasks:
            by_task_status[t.status.value] += 1
        for st, n in sorted(by_task_status.items()):
            lines.append(f"  - {st}: {n}")
        lines.append("")

        confirmed = [f for f in findings if f.status == FindingStatus.confirmed]
        if confirmed:
            lines.append("## Confirmed Findings")
            for f in confirmed:
                lines.extend(self._render_finding(f))
            lines.append("")

        other = [f for f in findings if f.status != FindingStatus.confirmed]
        for sev in ("critical", "high", "medium", "low", "info"):
            bucket = [f for f in other if f.severity.value == sev]
            if not bucket:
                continue
            lines.append(f"## {sev.title()} Findings")
            for f in bucket:
                lines.extend(self._render_finding(f))
            lines.append("")

        return "\n".join(lines)

    def _render_finding(self, f: Finding) -> list[str]:
        lines = [
            f"### `{f.id}` {f.title}",
            f"- **Severity:** {f.severity.value}",
            f"- **Status:** {f.status.value}",
            f"- **Category:** {f.category}",
        ]
        if f.endpoint:
            lines.append(f"- **Endpoint:** `{f.method or 'GET'} {f.endpoint}`")
        lines.append(f"- **Discovered by:** {f.discovered_by.value}")
        lines.append(
            f"- **Discovered at:** "
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(f.discovered_at))}"
        )
        if f.tags:
            lines.append(f"- **Tags:** {', '.join(f.tags)}")
        lines.append("")
        if f.description:
            lines.append(f.description)
            lines.append("")
        if f.repro_steps:
            lines.append("**Reproduction steps:**")
            for i, s in enumerate(f.repro_steps, 1):
                lines.append(f"{i}. {s}")
            lines.append("")
        if f.evidence:
            lines.append("**Evidence:**")
            for ev in f.evidence[:10]:
                lines.append("```")
                lines.append(ev[:2000])
                lines.append("```")
            lines.append("")
        return lines

    async def findings_json(self) -> str:
        findings = await self.blackboard.list_findings()
        return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)

    async def findings_by_status(self, status: str) -> str:
        findings = await self.blackboard.list_findings()
        picked = [f for f in findings if f.status.value == status]
        if not picked:
            return f"_no findings with status={status}_"
        lines = [f"*{status} — {len(picked)} findings*"]
        for f in picked[:30]:
            lines.append(f"• `{f.id}` [{f.severity.value}] {f.title[:80]}")
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
