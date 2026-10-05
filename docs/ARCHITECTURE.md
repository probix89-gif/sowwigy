# Architecture

## One-liner

A decision-maker plans; six workers act. All state lives in one
markdown+json blackboard. Every LLM call goes through one shared
client that enforces rate + budget + thinking window. Every target
request goes through one stealth session that impersonates a real
browser.

## Message flow

```
                    ┌───────────────────┐
                    │  DirectiveQueue   │   operator (telegram)
                    │  (append-only)    │────────────┐
                    └────────┬──────────┘            │
                             │ pending directives    │
                             ▼                       │
                    ┌───────────────────┐            │
                    │  DecisionAgent    │◄───────────┘
                    │  (plans; replies) │
                    └────────┬──────────┘
                             │ tasks + narrative
                             ▼
                    ┌───────────────────┐
                    │   Blackboard      │  (state.md)
                    │   (single truth)  │
                    └────────┬──────────┘
                             │ tasks
                             ▼
    ┌────────────────────────────────────────────────────┐
    │         TaskScheduler  +  AgentSupervisor          │
    │   priority + age + least-recently-assigned         │
    └────────────────────────────────────────────────────┘
       │        │          │           │           │
       ▼        ▼          ▼           ▼           ▼
     recon   business_   research   validation   attacker
             logic                              + hermes
       │        │          │           │           │
       └────────┴──────────┴───────────┴───────────┘
                             │ report_finding
                             ▼
                ┌───────────────────────┐
                │  FindingDedup +       │
                │  EvidenceCollector    │
                └────────┬──────────────┘
                         │
                         ▼
                ┌───────────────────────┐
                │     Blackboard        │
                └────────┬──────────────┘
                         │
                         ▼
                ┌───────────────────────┐
                │    ReporterLoop       │ (every N minutes)
                └────────┬──────────────┘
                         │
                         ▼
                  Telegram / operator
```

## Rate limit

Single API key → single `LLMClient` → `SlidingWindowRateLimiter`
(45 rpm, 1 margin, 4 concurrent). Every agent goes through it. The
limiter guarantees ≤ N calls in any rolling 60-second window.

## Thinking window

`ThinkingController` wraps the LLM call for `decision` + `attacker`
agents. If the call returns in < `min_seconds`, we pad the wall-clock
time. If it exceeds `max_seconds`, we log a warning but don't abort.

## Budget

`UsageTracker` persists daily totals to disk, keyed by date, tracks
prompt / completion / thinking tokens separately. `LLMClient.chat`
checks `can_spend` before every call. `AgentTokenBudget` gives each
agent a soft per-day cap so a runaway worker can't eat the quota.

## Stealth stack

```
StealthHttpTool           ← tool the agents call
        │
        ▼
StealthSession            ← identity + fingerprint + cookie jar
        │
        ├─ TimingModel    ← log-normal jitter + think / burst pauses
        ├─ Behavior       ← 403/429 backoff, auto-rotate
        ├─ HeaderBuilder  ← coherent headers per request kind
        ├─ Fingerprint    ← UA + sec-ch-ua + TLS target
        └─ curl_cffi      ← real Chrome/Firefox TLS fingerprint
```

## Auth stack

```
AuthManager               ← one singleton for the runtime
        │
        ├─ OtpFlow            ← send / verify with cooldown + TTL
        ├─ CookieImporter     ← parse + validate before accepting
        ├─ SessionVault       ← Fernet encrypted at rest
        └─ StealthSession     ← the session we authenticate into
```

## Safety layers

1. **ScopeGuard** — pattern match + private-IP block
2. **RateGovernor** — per-host rps + cooldown (used by stealth_race)
3. **Behavior** — exponential backoff + rotate on sustained 403/429
4. **Vault** — sessions encrypted at rest, tight file perms
5. **Dedup** — signature-based merge prevents blackboard flooding
6. **Evidence** — every capture persisted for audit
7. **Emergency** — cancels all tasks and flushes

## Extending

- **New agent**: subclass `BaseAgent`, add to `AGENT_CLASSES` in
  `agents/__init__.py`, add its prompt in `llm/prompts.py`, add its
  playbook to `_initial_messages`, tune in `config.yaml`.
- **New tool**: subclass `Tool`, register in `build_base_registry`,
  add to every agent's `allow_tools` you want it available on.
- **New command**: add handler in `telegram/bot.py`, register in
  `_register_handlers`, add to `HELP_TEXT`.
