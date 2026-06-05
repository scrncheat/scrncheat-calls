# Pierre Fouquet Calls

A Cloudflare Workers calling app:

- **In-app calls** — two signed-in users call each other directly over WebRTC
  (free, peer-to-peer, Cloudflare STUN/TURN). **Live.**
- **Passwordless auth** — sign in with an email + a 6-digit code. No passwords.
  Email is sent via the Cloudflare Email Service `send_email` binding. **Live.**
- **External (PSTN) calls + number verification** — dial real mobiles/landlines
  and present a *verified* number as caller ID. Built behind a spend-capped
  provider interface and a mock carrier, but **switched off** until a real
  telephone carrier is wired in (reaching the phone network costs per-minute and
  needs a carrier — there is no free, provider-less path). **Deferred.**

## Architecture

| Piece | What it does |
|---|---|
| `src/worker.js` | HTTP router, auth API, session-gated `/ws` upgrade, security headers. Owns all secrets/DB/authorization. |
| `src/signaling-do.js` | `SignalingRoom` Durable Object — WebSocket-Hibernation registry + 1:1 relay. Identity is bound server-side; client-supplied sender ids are ignored. |
| `src/lib/*` | `auth` (codes + sessions), `email` (Email Service), `ratelimit` (atomic D1 counters), `turn` (short-lived ICE creds), `crypto`, `cookies`, `responses`. |
| D1 (`DB`) | users, sessions, login_codes, verified_numbers, call_logs, dial_policy, rate_counters. |
| `public/` | Single-page client: login, in-app dialer, (disabled) external dialer. |

## Develop

```sh
npm install
npm run dev          # wrangler dev (local D1 + DO + assets)
npm run migrate:local
```

## Test

```sh
npm test             # Vitest on workerd: functional + abuse-resistance suite
npm run test:e2e     # Playwright browser E2E (fake media)
```

The suite includes abuse tests, not just functionality: OTP brute-force/expiry/
replay, neutral (non-enumerating) responses, session forgery, CSRF, cross-origin
blocking, WebSocket access control, **signaling sender-spoofing**, and oversized
frames.

## Deploy

Deployment is via the **native Cloudflare ↔ GitHub integration** (Workers
Builds) on pushes to `main`. Bindings live in `wrangler.toml`; secrets are set
in the Cloudflare dashboard:

- `OTP_PEPPER` — HMAC pepper for login codes
- `TURN_KEY_ID`, `TURN_API_TOKEN` — Cloudflare Realtime TURN (optional; STUN-only without)
- *(later)* carrier credentials for PSTN

Before the first deploy, create the D1 database and set its id in
`wrangler.toml` (`database_id`), and authenticate the Email Service sending
domain.
