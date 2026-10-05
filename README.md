# swiggy-hunter

**v2** — autonomous, stealth-hardened AI scanner for `swiggy.com`
business-logic bug hunting. Multi-agent. Multi-tool. Telegram-driven.

```
 ██╗  ██╗███████╗██████╗ ███╗   ███╗███████╗███████╗
 ██║  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝
 ███████║█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗
 ██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║
 ██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║
 ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝
```

## What it is

An autonomous assessment system that runs against `swiggy.com` inside
a strict scope, using seven LLM agents coordinated by a decision-maker,
with a stealth HTTP layer that impersonates real Chrome/Firefox TLS +
timing, OTP + cookie authentication, and multi-tool attack chains.

**You talk to Agent 0 (the decision-maker) directly through Telegram.**
Just send plain text — it becomes a directive that the planner reads
on the next cycle and replies to.

## Agents

| agent | role |
|---|---|
| **decision** | master planner + your interlocutor; reads blackboard, plans tasks, answers you |
| **recon** | subdomains, endpoints, JS bundles, tech fingerprinting |
| **business_logic** | coupon / cart / checkout / wallet abuse hunting |
| **research** | public writeups, changelogs, competitor bugs |
| **validation** | reproduce, falsify, confirm |
| **attacker** | multi-step chains, PoC scripts, tool installs |
| **hermes** | stealth navigator — end-to-end user flows, browser when needed |

## Stealth

- **TLS impersonation** via `curl_cffi` (real Chrome 124–127, Firefox 130–133, Safari 17–18)
- **Coherent fingerprints** — UA + `sec-ch-ua` + accept-language never mixed across versions
- **Human timing** — log-normal jitter, think-pauses, burst-pauses
- **Referer chains** — coherent across a flow
- **Per-host rate governor** — 5 rps default, cooldown on 403/429
- **Auto-rotation** — fingerprint swaps after sustained blocks
- **Playwright browser** — headless with stealth init scripts for JS-gated pages

## Auth

- **OTP login** — `/login <phone>` then `/otp <code>` from Telegram
- **Cookie login** — `/cookie a=1; b=2` (or JSON / Netscape), validated before storing
- **Encrypted vault** — Fernet, auto key management, persists across restarts
- **Session restore** — `/restore` reloads from the vault
- **Session rotation** — `/rotate` swaps fingerprint, keeps auth cookies

## Install

```bash
git clone <this-repo> swiggy-hunter
cd swiggy-hunter
chmod +x install.sh
./install.sh
# optional: playwright install chromium
```

Then edit `.env` (LLM key, Telegram bot token, chat id) and `config.yaml`
(target scope, model name, thinking window).

## Run

```bash
swiggy-hunter run
```

Autostart is controlled by `autostart: true` in `config.yaml`. The
runtime boots the LLM client, stealth layer, auth manager, all seven
agents, and the telegram bot.

## Telegram

### Talk to the decision-maker (Agent 0)

Just send **plain text** — no slash. Examples:

```
> focus on the coupon-race angle today
🧠 decision-maker: got it — queuing a 20-concurrent coupon-race sweep
   against the apply-coupon endpoint.

> what's the most promising lead?
🧠 decision-maker: finding f4a8c1 — likely race in apply-coupon.
   attacker is building a 20-thread PoC now.
```

Explicit forms:

- `/ask <msg>` — same as plain text
- `/inject <task>` — force a task without waiting for planning
- `/note <text>` — append to plan notes only
- `/directives` — see recent directives + replies

### Commands

**Runtime**
```
/start /help      show help
/scan             start the scanner
/resume /pause    resume / pause workers
/stop             graceful stop
/restart          stop and start
/emergency        kill switch
```

**Auth**
```
/login <phone>    start OTP login
/otp <code>       enter the OTP
/cookie <raw>     import cookies (a=1;b=2 | JSON | Netscape)
/auth             show auth state (with inline buttons)
/rotate           rotate fingerprint
/logout           clear session
/restore          reload from vault
```

**Tools**
```
/download <mgr> <pkg> [bin]    install a tool
```

**Info**
```
/status /usage /progress /findings /report /target /scope /model
```

**Control**
```
/reason low|medium|high        reasoning depth
/interval <minutes>            report interval
/retest <finding_id>           requeue a finding for validation
/clear                         wipe findings + tasks (confirm)
```

## Thinking window

The model spends 12–32 seconds thinking on every decision-maker and
attacker call. This is enforced by `ThinkingController` — if the
underlying LLM answers faster, we pad. If slower, we log a warning but
don't abort (network calls can't be cancelled mid-stream cleanly).

Configure in `config.yaml`:

```yaml
model:
  thinking_window:
    enabled: true
    min_seconds: 12
    max_seconds: 32
    agents: ["decision", "attacker"]
```

## Layout

```
src/swiggy_hunter/
├── agents/         7 agents + base loop + blackboard tools + context
├── auth/           vault (Fernet), OTP flow, cookies, AuthManager
├── llm/            client, rate limiter, token budget, thinking, prompts
├── scanner/        scope, rate governor, dedup, evidence, exploits,
│                   profiler, payloads, deep probe
├── scheduler/      lifecycle, task scheduler, supervisor, decision loop,
│                   reporter, report builder
├── stealth/        fingerprints, headers, timing, behavior, session, browser
├── state/          schemas, blackboard (markdown + json)
├── telegram/       bot, notifier, formatters, keyboards, auth gate
├── tools/          stealth_http, stealth_race, browser, installer, auth,
│                   blackboard, shell, file, crypto, analysis, recon, web
├── config.py       pydantic config model
├── directives.py   operator → decision-maker queue (JSONL)
├── runtime.py      process-wide singletons
├── orchestrator.py top-level runtime
└── main.py         entrypoint
```

## Safety layers

1. **ScopeGuard** blocks out-of-scope URLs at tool entry
2. **RateGovernor** enforces per-host rps + 403/429 cooldowns
3. **Behavior** exponential back-off + auto-rotate on sustained block
4. **Vault** keeps sessions Fernet-encrypted at rest
5. **Dedup** prevents duplicate findings from flooding the blackboard
6. **Evidence** persists every capture for audit
7. **Emergency** stops everything and flushes state

## Docs

- `docs/ARCHITECTURE.md` — how the pieces fit
- `docs/STEALTH.md` — how browsing stays unblocked
- `docs/AUTH.md` — OTP + cookie flows

## Development

```bash
make install      # pip install -e .[dev]
make browser      # playwright install chromium
make test         # pytest
make lint         # ruff
make run          # boot
```
