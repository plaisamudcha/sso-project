# Smoke Test

This smoke test validates all critical SSO flows against `sso-server`:

- ClientA OAuth flow (no `openid`)
- ClientA OIDC flow (`openid email`)
- ClientB OAuth flow (no `openid`)
- ClientB OIDC flow (`openid email`)
- Token refresh and logout behavior
- `/userinfo` scope behavior differences

## Prerequisites

1. `sso-server` is running on `SSO_SERVER` from `clientA/.env` (default: `http://localhost:4000`)
2. MongoDB and Redis are available
3. `clientA/.env` and `clientB/.env` contain valid `CLIENT_ID` and `CLIENT_SECRET`

You do not need to run clientA/clientB servers for this script.

## Run

From repository root:

```bash
node smoke_test.js
```

## Expected Result

- OAuth-only flows: `/userinfo` returns `403 insufficient_scope`
- OIDC flows: `/userinfo` returns `200` with `sub` and `email`
- Refresh flow succeeds for each flow
- Logout invalidates the active session

If any flow fails, the script exits with code `1` and prints details.

## Note About 429 Login Limits

The script automatically retries login up to 3 times when SSO returns `429 Too many login attempts`.
For local testing, it rotates `X-Forwarded-For` per flow to avoid stale limiter counters from previous runs.
