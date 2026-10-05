# Auth

Two independent login paths. Both end up in `StealthSession.cookies`
and get persisted to the encrypted vault.

## OTP login (primary)

Interactive, driven from Telegram:

```
/login 9876543210
```
→ hits `send_endpoint` with `{mobile: "9876543210"}`
→ replies "OTP sent" and stores a `PendingOtp` (10 min TTL, 45s
resend cooldown)

```
/otp 123456
```
→ hits `verify_endpoint` with `{mobile, otp}`
→ on success, absorb `Set-Cookie` from the response
→ validate against `https://www.swiggy.com/api/user/me`
→ save to vault

Both endpoints and the phone/otp field names are configurable in
`config.yaml`:

```yaml
auth:
  otp:
    send_endpoint: "https://www.swiggy.com/api/auth/send-otp"
    verify_endpoint: "https://www.swiggy.com/api/auth/verify-otp"
    phone_field: "mobile"
    otp_field: "otp"
    resend_cooldown_s: 45
```

## Cookie login (fallback)

```
/cookie session=abc; t_id=xyz
/cookie {"session":"abc","t_id":"xyz"}
/cookie <netscape-file-lines>
```

Parse → validate against the same probe → save to vault.

## Vault

Encrypted at rest with Fernet. Key resolution:
1. `SWIGGY_SESSION_VAULT_KEY` env var
2. `data/.vault_key` file (0600)
3. auto-generate + write with 0600 perms

Never commit the vault file or the key.

## Restore

On boot you can call `/restore` to reload the vault's `primary`
session. It's validated before accepting. If it's dead, the vault
entry is deleted and you'll need to re-login.

## Rotation

`/rotate` swaps the fingerprint and drops non-auth cookies. Use it
after sustained 403/429. Auth cookies are preserved by name
(`session`, `swiggy_session`, `access_token`, `t_id`, `sid`).
