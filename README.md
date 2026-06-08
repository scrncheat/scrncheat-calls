# Pierre Fouquet Calls

A Cloudflare Workers calling app:

- **In-app calls** — two signed-in users call each other directly over WebRTC
  (free, peer-to-peer, Cloudflare STUN/TURN). **Live.**
- **Passwordless auth** — sign in with an email + a 6-digit code. No passwords.
  Email is sent via the Cloudflare Email Service `send_email` binding. **Live.**
- **External (PSTN) calls + number verification** — dial real phone numbers from
  the browser, presenting your own mobile as caller ID. Audio flows browser ⇄
  Twilio ⇄ PSTN over WebRTC (Workers can't carry SIP/RTP); the Worker mints a
  short-lived Twilio Access Token, runs the toll-fraud gate (caller-ID ownership,
  allow-lists, premium-rate blocks, velocity caps, daily spend cap, per-call time
  limit, kill-switch), and authorizes each call via a single-use ticket redeemed
  at a signature-verified TwiML webhook. Caller ID is your own mobile, validated
  once via Twilio's Verified Caller ID flow (no rented number). Built behind a
  **swappable provider interface** and **off by default** (`TELEPHONY_ENABLED`)
  until you connect a Twilio account — see *Connecting Twilio* below. Reaching the
  phone network costs per-minute; there is no free, provider-less path.

## Architecture

| Piece | What it does |
|---|---|
| `src/worker.js` | HTTP router, auth API, session-gated `/ws` upgrade, security headers. Owns all secrets/DB/authorization. |
| `src/signaling-do.js` | `SignalingRoom` Durable Object — WebSocket-Hibernation registry + 1:1 relay. Identity is bound server-side; client-supplied sender ids are ignored. |
| `src/lib/*` | `auth` (codes + sessions), `email` (Email Service), `numbers` (registration + verification), `dial` + `policy` (toll-fraud gate + dial tickets), `phone` (E.164), `telephony/*` (swappable provider interface: `mock` + `twilio`, JWT + webhook-signature utils), `ratelimit` (atomic D1 counters), `turn`, `crypto`, `cookies`, `responses`. |
| D1 (`DB`) | users, sessions, login_codes, verified_numbers, call_logs, dial_policy, dial_tickets, rate_counters. |
| `public/` | Single-page client: login, in-app dialer, and the external (Twilio) browser softphone. |

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
- `TWILIO_AUTH_TOKEN`, `TWILIO_API_KEY_SID`, `TWILIO_API_KEY_SECRET` — only if you
  connect Twilio for PSTN (see *Connecting Twilio* below)

Before the first deploy, create the D1 database and set its id in
`wrangler.toml` (`database_id`), and authenticate the Email Service sending
domain.

## Connecting Twilio (real PSTN)

External calling stays off until you connect Twilio. Audio runs browser ⇄ Twilio
⇄ PSTN over WebRTC; the Worker only mints tokens, authorizes dials, and receives
signed webhooks. There's no free outbound PSTN, but Twilio's sign-up credit
(~$15) covers low volume for a long time, and presenting your own mobile as
caller ID means no rented number.

One-time setup in the Twilio Console:

1. Create an account and add a little pay-as-you-go credit (this lifts the
   trial-only "can only call verified numbers" restriction).
2. Create an **API Key** (SID + Secret) — used to mint browser Access Tokens.
3. Create a **TwiML App** and set its Voice Request URL to
   `https://<your-domain>/api/voice/twiml` (POST).
4. Validate your mobile as an **Outgoing Caller ID** — or just add the number
   in-app: the app triggers Twilio's validation call and shows you the code to
   key in on your handset.

Then set these in the Cloudflare dashboard and redeploy:

| Name | Kind | Value |
|---|---|---|
| `TELEPHONY_PROVIDER` | var | `twilio` |
| `TELEPHONY_ENABLED` | var | `true` (flip on only after an end-to-end test) |
| `TWILIO_ACCOUNT_SID` | var | from the Console |
| `TWILIO_TWIML_APP_SID` | var | the TwiML App SID |
| `TWILIO_AUTH_TOKEN` | secret | REST auth + webhook signature verification |
| `TWILIO_API_KEY_SID`, `TWILIO_API_KEY_SECRET` | secret | Access-Token signing |

Optional toll-fraud caps (vars): `TELEPHONY_RATE_MICRO_PER_MIN` (estimated
cost/min in micros, used to accrue spend) and `DEFAULT_DAILY_SPEND_CAP_MICRO`
(block once a user's estimated daily spend reaches it). Per-user overrides live
in the `dial_policy` table (`daily_spend_cap_micro`, `per_call_max_sec`).

Apply the new migration before first use: `npm run migrate:remote`.
