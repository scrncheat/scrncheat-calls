-- Pierre Fouquet Calls — initial schema.
-- Timestamps are unix epoch milliseconds (INTEGER). IDs are UUID/opaque TEXT.

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL,                 -- stored lowercased
  display_name  TEXT,
  created_at    INTEGER NOT NULL,
  last_login_at INTEGER,
  status        TEXT NOT NULL DEFAULT 'active' -- active | suspended
);
CREATE UNIQUE INDEX idx_users_email ON users (email);

-- Opaque, DB-backed sessions (hash stored, never the raw token) so revocation
-- is instant.
CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,    -- sha256(token)
  user_id      TEXT NOT NULL REFERENCES users (id),
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,    -- absolute expiry
  last_seen_at INTEGER NOT NULL,    -- idle tracking
  ip           TEXT,
  user_agent   TEXT,
  revoked_at   INTEGER
);
CREATE INDEX idx_sessions_user ON sessions (user_id);
CREATE INDEX idx_sessions_expires ON sessions (expires_at);

-- Passwordless email login codes. Only the HMAC of the code is stored.
CREATE TABLE login_codes (
  id         TEXT PRIMARY KEY,
  email      TEXT NOT NULL,
  code_hash  TEXT NOT NULL,          -- hmac_sha256(pepper, code + ':' + salt)
  salt       TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  attempts   INTEGER NOT NULL DEFAULT 0,
  ip         TEXT
);
CREATE INDEX idx_login_codes_email ON login_codes (email, created_at);

-- External numbers a user has proven ownership of (Phase 3, mock for now).
CREATE TABLE verified_numbers (
  id             TEXT PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users (id),
  e164           TEXT NOT NULL,
  country        TEXT,                          -- ISO 3166-1 alpha-2
  line_type      TEXT,                          -- mobile | landline | voip | unknown
  status         TEXT NOT NULL DEFAULT 'pending', -- pending | verified | failed
  channel        TEXT,                          -- sms | voice
  provider_ref   TEXT,                          -- carrier-side id (e.g. OutgoingCallerId SID)
  verify_attempts INTEGER NOT NULL DEFAULT 0,
  verify_code_hash TEXT,                         -- hmac of the in-flight OTP
  verify_salt    TEXT,
  verify_code_expires_at INTEGER,
  created_at     INTEGER NOT NULL,
  verified_at    INTEGER
);
CREATE INDEX idx_vn_user ON verified_numbers (user_id);
CREATE UNIQUE INDEX idx_vn_user_e164 ON verified_numbers (user_id, e164);

-- Unified call history (in-app P2P and, later, PSTN).
CREATE TABLE call_logs (
  id            TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users (id),
  kind          TEXT NOT NULL,        -- p2p | pstn
  direction     TEXT,                 -- outbound | inbound
  from_e164     TEXT,                 -- caller id presented (pstn)
  to_e164       TEXT,                 -- destination (pstn)
  peer_handle   TEXT,                 -- peer email/handle (p2p)
  provider_call_ref TEXT,
  status        TEXT,                 -- initiated|ringing|in-progress|completed|failed|blocked
  started_at    INTEGER,
  ended_at      INTEGER,
  duration_sec  INTEGER,
  price_micro   INTEGER,              -- cost * 1e6
  currency      TEXT,
  block_reason  TEXT
);
CREATE INDEX idx_calls_user_time ON call_logs (user_id, started_at);
CREATE INDEX idx_calls_callref ON call_logs (provider_call_ref);

-- Per-user dialing policy / toll-fraud controls (Phase 3).
CREATE TABLE dial_policy (
  user_id                  TEXT PRIMARY KEY REFERENCES users (id),
  allowed_country_prefixes TEXT,      -- JSON array e.g. ["+44","+33"]
  daily_spend_cap_micro    INTEGER,
  per_call_max_sec         INTEGER,
  blocked_prefixes         TEXT,      -- JSON array
  enabled                  INTEGER NOT NULL DEFAULT 1
);

-- Active outbound PSTN calls (presence), so "one call at a time" spans BOTH
-- in-app and phone calls. Set/cleared by the dial gate via the signaling DO.
CREATE TABLE pstn_presence (
  handle TEXT PRIMARY KEY,   -- user's email/handle
  since  INTEGER NOT NULL
);

-- Authoritative, atomic rate-limit / abuse counters.
CREATE TABLE rate_counters (
  bucket       TEXT PRIMARY KEY,      -- e.g. "otp:req:email:foo@x", "otp:verify:ip:1.2.3.4"
  count        INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL
);
