# Runbook

## First boot

```bash
cp .env.example .env
# fill GLM_API_KEY, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID

swiggy-hunter run
```

Runtime autostarts if `autostart: true`. Send `/start` to your bot.

## Login

```
/login <phone>
/otp <code>
```

or

```
/cookie session=...; t_id=...
```

Confirm with `/auth`.

## Watch it work

- `/status` — snapshot
- `/progress` — same as the 30-min report, on demand
- `/findings` — latest findings
- `/directives` — see your messages + agent 0's replies

## When it gets blocked

Signs:
- `/status` shows `blocks: 403×N` climbing
- `cool-down remaining: XXs` is large
- agents report "blocked" state

Actions:
1. `/rotate` — new fingerprint, same auth
2. If still blocked after 2 rotations, `/pause`, wait 15 min, `/resume`
3. Last resort: `/logout`, re-login with a fresh OTP

## When the model is rate-limited

Signs:
- frequent 429 logs in `logs/swiggy_hunter.jsonl`
- `/usage` shows rapid climbing

Actions:
1. Reduce concurrency in `config.yaml` (`rate_limit.max_concurrent: 2`)
2. `/reason low` to shorten attacker prompts
3. Increase `/interval` so reports are less frequent

## When you're done

```
/stop
```

or just Ctrl+C. The runtime flushes blackboard, closes sessions,
stops the browser, and shuts down cleanly.

## Emergency

```
/emergency
```

Cancels all tasks, closes sessions, flushes state. Use when something
is misbehaving.
