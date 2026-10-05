"""
HTML-mode formatters. HTML chosen over MarkdownV2 to avoid escaping hell —
only < > & need escaping.
"""
from __future__ import annotations

import time
from typing import Any


MAX_LEN = 3800  # telegram hard cap is 4096, leave headroom


def escape(text: Any) -> str:
    if text is None:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def code(text: Any) -> str:
    return f"<code>{escape(text)}</code>"


def bold(text: Any) -> str:
    return f"<b>{escape(text)}</b>"


def italic(text: Any) -> str:
    return f"<i>{escape(text)}</i>"


def pre(text: str) -> str:
    return f"<pre>{escape(text)}</pre>"


def split_message(text: str, max_len: int = MAX_LEN) -> list[str]:
    """Split long messages on paragraph / line boundaries."""
    if len(text) <= max_len:
        return [text]
    chunks: list[str] = []
    current = ""
    for para in text.split("\n\n"):
        candidate = (current + "\n\n" + para) if current else para
        if len(candidate) <= max_len:
            current = candidate
            continue
        if current:
            chunks.append(current)
        if len(para) > max_len:
            line_buf = ""
            for line in para.split("\n"):
                if len(line_buf) + len(line) + 1 > max_len:
                    chunks.append(line_buf)
                    line_buf = line
                else:
                    line_buf = (line_buf + "\n" + line) if line_buf else line
            if line_buf:
                chunks.append(line_buf)
            current = ""
        else:
            current = para
    if current:
        chunks.append(current)
    return chunks


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def fmt_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


STATE_MARK = {
    "working": "🟢",
    "idle": "🟡",
    "blocked": "🔴",
    "error": "🔴",
    "stopped": "⚫",
}

SEVERITY_MARK = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}


# ==========================================================================
# renderers
# ==========================================================================

def render_status(snapshot: dict[str, Any]) -> str:
    lc = snapshot.get("lifecycle", {})
    state = lc.get("state", "unknown")
    uptime = fmt_duration(lc.get("uptime_s", 0)) if state == "running" else "—"

    auth = snapshot.get("auth") or {}
    stealth = snapshot.get("stealth") or {}
    rate = snapshot.get("rate") or {}
    thinking = snapshot.get("thinking") or {}

    lines = [
        "<b>Swiggy Hunter — Status</b>",
        "",
        f"• state: {code(state)}  uptime: {code(uptime)}",
        f"• target: {code(snapshot.get('target', '—'))}",
        f"• model: {code(snapshot.get('model', '—'))}  reasoning: {code(snapshot.get('reasoning', '—'))}",
        f"• report interval: {code(str(snapshot.get('report_interval_min', '—')) + 'm')}",
        "",
        "<b>Auth</b>",
        f"• authenticated: {code(auth.get('authenticated', False))}",
    ]
    if auth.get("phone"):
        lines.append(f"• phone: {code(auth['phone'])}")
    if auth.get("cookies"):
        lines.append(f"• cookies: {code(auth['cookies'])}")
    otp = auth.get("otp") or {}
    if otp.get("pending"):
        lines.append(
            f"• OTP pending: {code(str(otp.get('phone')))} "
            f"({code(str(otp.get('age_s', 0)))}s ago, attempts={otp.get('attempts', 0)})"
        )

    lines.append("")
    lines.append("<b>Stealth</b>")
    if stealth:
        lines.append(f"• fingerprint: {code(stealth.get('fingerprint', '?'))}")
        lines.append(f"• engine: {code(stealth.get('engine', '?'))}")
        lines.append(f"• requests this session: {code(stealth.get('requests', 0))}")
        beh = stealth.get("behavior") or {}
        c403 = beh.get("consecutive_403", 0)
        c429 = beh.get("consecutive_429", 0)
        if c403 or c429:
            lines.append(f"• blocks: 403×{code(c403)} 429×{code(c429)}")
        cd = beh.get("cool_down_remaining_s") or 0
        if cd and cd > 0.5:
            lines.append(f"• cool-down remaining: {code(f'{cd:.1f}s')}")
    else:
        lines.append("<i>(stealth layer inactive)</i>")

    if rate:
        lines.append("")
        lines.append("<b>LLM Rate</b>")
        lines.append(
            f"• used in window: {code(rate.get('in_window', 0))} / "
            f"{code(rate.get('limit', 0))} · "
            f"remaining: {code(rate.get('remaining', 0))}"
        )
    if thinking:
        lines.append(
            f"• thinking window: {code(thinking.get('min_seconds'))}-"
            f"{code(thinking.get('max_seconds'))}s on "
            f"{code(','.join(thinking.get('agents', [])))}"
        )

    lines.append("")
    lines.append(f"• findings: {code(snapshot.get('findings', 0))}")
    lines.append(f"• tasks: {code(snapshot.get('tasks', 0))}")
    lines.append("")
    lines.append("<b>Agents</b>")
    for a in snapshot.get("agents", []):
        marker = STATE_MARK.get(a.get("state", ""), "•")
        line = f"{marker} {code(a.get('name', '?'))} — {a.get('state', '?')}"
        if a.get("task"):
            line += f"  {code(a['task'])}"
        lines.append(line)

    return "\n".join(lines)


def render_findings_list(findings: list[dict[str, Any]],
                         title: str = "Findings") -> str:
    if not findings:
        return f"<i>{escape(title)}: none yet</i>"
    lines = [f"<b>{escape(title)}</b> — {len(findings)} total", ""]
    for f in findings[:30]:
        mark = SEVERITY_MARK.get(f.get("severity", "info"), "•")
        line = (
            f"{mark} {code(f.get('id', '?'))} "
            f"[{escape(f.get('status', '?'))}] "
            f"{escape((f.get('title') or '')[:80])}"
        )
        lines.append(line)
    if len(findings) > 30:
        lines.append(f"<i>…and {len(findings) - 30} more</i>")
    return "\n".join(lines)


def render_auth_status(auth: dict[str, Any]) -> str:
    lines = ["<b>Auth state</b>", ""]
    if auth.get("authenticated"):
        lines.append(f"🟢 authenticated")
        if auth.get("phone"):
            lines.append(f"• phone: {code(auth['phone'])}")
    else:
        lines.append("🔴 not authenticated")
    lines.append(f"• cookies: {code(auth.get('cookies', 0))}")
    lines.append(f"• fingerprint: {code(auth.get('fingerprint', '?'))}")
    lines.append(f"• session name: {code(auth.get('session_name', '?'))}")

    otp = auth.get("otp") or {}
    if otp.get("pending"):
        lines.append("")
        lines.append("<b>OTP pending</b>")
        lines.append(f"• phone: {code(otp.get('phone'))}")
        lines.append(f"• age: {code(str(otp.get('age_s', 0)) + 's')}")
        lines.append(f"• attempts: {code(otp.get('attempts', 0))}")
        if otp.get("last_error"):
            lines.append(f"• last error: {escape(otp['last_error'])}")

    vault = auth.get("vault_sessions") or []
    if vault:
        lines.append("")
        lines.append(f"<b>Vault sessions:</b> {code(', '.join(vault))}")

    return "\n".join(lines)


def render_directives(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<i>no directives yet</i>"
    lines = ["<b>Recent directives</b>", ""]
    for d in items:
        status = "✅" if d.get("consumed") else "⏳"
        kind = d.get("kind", "chat")
        text = escape((d.get("text") or "")[:140])
        lines.append(f"{status} {code(d.get('id'))} [{kind}] {text}")
        if d.get("response"):
            lines.append(f"   ↳ {escape(d['response'][:220])}")
    return "\n".join(lines)
