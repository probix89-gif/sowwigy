# Stealth

Anti-bot systems correlate dozens of signals. Our stealth layer keeps
them coherent:

## Fingerprints

A `Fingerprint` is one bundle: UA, `sec-ch-ua`, `sec-ch-ua-mobile`,
`sec-ch-ua-platform`, accept-language, accept-encoding, viewport,
timezone, and a `curl_cffi` TLS impersonation target.

We never mix Chrome 124 UA with Chrome 126 `sec-ch-ua` — anti-bot
heuristics specifically look for that. Each `StealthSession` draws
exactly one fingerprint and keeps it for its lifetime.

## Timing

`TimingModel` produces human-like delays:
- base delay = `base_delay_ms` + log-normal-ish jitter
- occasional "think pause" (1.4–4.8s) with `think_pauses_prob`
- occasional "burst pause" (6–22s) with `burst_pause_prob`
  (probability grows with a burst counter, so long runs of requests
  are guaranteed to pause eventually)

## Headers

`HeaderBuilder` shapes headers per request kind:
- `navigate` → `sec-fetch-dest: document`
- `xhr` → `sec-fetch-dest: empty`, `sec-fetch-mode: cors`, JSON accept
- `form` → `sec-fetch-mode: navigate`, form content-type, origin set
- `asset` → `sec-fetch-mode: no-cors`
- `preflight` → CORS preflight headers

Referer chains are tracked per host: after visiting `/restaurants`,
the next request to `/cart` gets `referer: .../restaurants`.

## Behavior

- 403 → exponential backoff (20s → 40 → 80 → 160 → 300)
- 429 → honor `Retry-After` header if present
- 3 consecutive 403/429 → flag the session for auto-rotation

## Rotation

On rotation:
- close the current `curl_cffi` session
- draw a new fingerprint
- clear cookies EXCEPT auth-critical ones
  (`session`, `swiggy_session`, `access_token`, `t_id`, `sid`)

## Browser

Playwright Chromium with stealth init scripts:
- `navigator.webdriver` → undefined
- `navigator.plugins` → plausible list
- `navigator.languages` → `['en-IN', 'en', 'en-GB']`
- `window.chrome.runtime` → `{}`

Real UA, viewport, timezone, locale from the fingerprint. Cookies
import/export so HTTP and browser share auth state.
