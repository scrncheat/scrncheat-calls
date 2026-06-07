-- Pre-authorized outbound-dial tickets. With a browser-WebRTC carrier (Twilio)
-- the call is placed by the browser SDK, so the toll-fraud gate runs at
-- /api/voice/dial and mints a short-lived single-use ticket. The browser passes
-- only the opaque ticket to Twilio; the TwiML webhook redeems it (proving the
-- destination + caller ID were authorized) before <Dial> is emitted. One-call-
-- at-a-time presence is reserved at redeem time and released on the status
-- webhook, so an abandoned dial never wedges a user.
CREATE TABLE dial_tickets (
  id          TEXT PRIMARY KEY,      -- opaque token handed to the browser
  user_id     TEXT NOT NULL REFERENCES users (id),
  handle      TEXT NOT NULL,         -- user's email/handle (matches From=client:<handle>)
  from_e164   TEXT NOT NULL,         -- authorized caller ID (the user's verified mobile)
  to_e164     TEXT NOT NULL,         -- authorized destination
  time_limit_sec INTEGER,            -- hard per-call cap, authorized at dial time
  call_sid    TEXT,                  -- Twilio CallSid, bound at redeem
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER                -- single-use: set when redeemed
);
CREATE INDEX idx_dial_tickets_expires ON dial_tickets (expires_at);
CREATE INDEX idx_dial_tickets_callsid ON dial_tickets (call_sid);
