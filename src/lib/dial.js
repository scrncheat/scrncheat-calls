// Outbound PSTN dialing and the toll-fraud authorization gate.
//
// Two provider shapes are supported behind one gate:
//   - Server-side (mock): the gate reserves presence, places the call, logs it,
//     and releases presence immediately (the mock completes instantly).
//   - Browser-initiated (Twilio): the call is placed by the browser Voice SDK, so
//     the gate authorizes the destination + caller ID and mints a single-use
//     ticket. The TwiML webhook redeems the ticket (reserving one-call-at-a-time
//     presence at that point) and the status webhook releases it. This keeps the
//     Worker the sole authorization point while audio flows browser <-> carrier.

import { evaluateDialPolicy, parsePrefixes, DEFAULT_BLOCKED_PREFIXES } from "./policy.js";
import { incrementCounter } from "./ratelimit.js";
import { getProvider } from "./telephony/index.js";
import { classify } from "./phone.js";
import { randomId, randomToken } from "./crypto.js";

const HOUR = 3600;
const DAY_MS = 24 * 60 * 60 * 1000;
const HOURLY_CALL_LIMIT = 20;
// Backstop so a missed end-of-call signal can't wedge a user permanently.
const MAX_PSTN_BUSY_MS = 4 * 60 * 60 * 1000;
// A dial ticket is short-lived: the browser must place the call promptly.
const TICKET_TTL_MS = 2 * 60 * 1000;
// Hard cap on a single call's length (also a toll-fraud backstop). Overridable
// per user via dial_policy.per_call_max_sec.
const DEFAULT_CALL_TIME_LIMIT_SEC = 3600;

/** Resolve the daily spend cap (micros): per-user override, else env default, else none. */
function resolveDailyCap(policyRow, env) {
  if (policyRow && policyRow.daily_spend_cap_micro != null) return policyRow.daily_spend_cap_micro;
  const def = parseInt(env.DEFAULT_DAILY_SPEND_CAP_MICRO ?? "", 10);
  return Number.isFinite(def) ? def : null;
}

/** Estimated call cost in micros from duration + the configured per-minute rate. */
function estimateCostMicro(env, durationSec) {
  const rate = parseInt(env.TELEPHONY_RATE_MICRO_PER_MIN ?? "", 10);
  if (!Number.isFinite(rate) || rate <= 0 || durationSec <= 0) return 0;
  return Math.ceil(durationSec / 60) * rate;
}

const TERMINAL_STATUSES = new Set(["completed", "busy", "no-answer", "failed", "canceled"]);

/**
 * @param {object} [opts]
 * @param {number} [opts.now]
 * @param {boolean} [opts.enabled] override the telephony kill-switch (tests)
 */
export async function authorizeAndDial(env, user, toRaw, numberId, opts = {}) {
  const now = opts.now ?? Date.now();
  const enabled = opts.enabled ?? env.TELEPHONY_ENABLED === "true";
  const dest = classify(toRaw);
  const toE164 = dest.e164;
  const destinationType = dest.lineType;

  const verifiedNumber = numberId
    ? await env.DB.prepare("SELECT * FROM verified_numbers WHERE id = ?").bind(numberId).first()
    : null;

  const policyRow = await env.DB.prepare("SELECT * FROM dial_policy WHERE user_id = ?")
    .bind(user.id)
    .first();
  const allowedPrefixes =
    policyRow && policyRow.allowed_country_prefixes
      ? JSON.parse(policyRow.allowed_country_prefixes)
      : parsePrefixes(env.DEFAULT_ALLOWED_PREFIXES);
  const blockedPrefixes =
    policyRow && policyRow.blocked_prefixes
      ? JSON.parse(policyRow.blocked_prefixes)
      : DEFAULT_BLOCKED_PREFIXES;

  // Count this attempt toward the hourly velocity cap (atomic).
  const hourlyCount = await incrementCounter(env, `pstn:user:${user.id}:hour`, HOUR, now);

  // Daily spend cap (optional). Only sum today's estimated cost when a cap exists.
  const dailyCapMicro = resolveDailyCap(policyRow, env);
  let dailySpentMicro = 0;
  if (dailyCapMicro != null) {
    const row = await env.DB.prepare(
      `SELECT COALESCE(SUM(price_micro), 0) AS spent FROM call_logs
       WHERE user_id = ? AND kind = 'pstn' AND started_at >= ?`
    )
      .bind(user.id, now - DAY_MS)
      .first();
    dailySpentMicro = row ? row.spent : 0;
  }

  const decision = evaluateDialPolicy({
    enabled,
    toE164,
    destinationType,
    verifiedNumber,
    userId: user.id,
    allowedPrefixes,
    blockedPrefixes,
    hourlyCount,
    hourlyLimit: HOURLY_CALL_LIMIT,
    dailyCapMicro: dailyCapMicro ?? undefined,
    dailySpentMicro,
  });

  if (!decision.allowed) {
    await logCall(env, user.id, {
      to_e164: toE164,
      from_e164: verifiedNumber ? verifiedNumber.e164 : null,
      status: "blocked",
      block_reason: decision.reason,
      started_at: now,
    });
    return { ok: false, reason: decision.reason };
  }

  // One call at a time per user — unified across in-app and PSTN. In-app "busy"
  // is owned by the signaling DO; PSTN presence is owned in D1. Advisory check
  // here gives fast UX feedback; the authoritative PSTN reservation happens when
  // the call actually starts (server-side place below, or ticket redeem).
  const handle = String(user.email || "").toLowerCase();
  const presence = env.SIGNALING.get(env.SIGNALING.idFromName("global"));

  const inAppBusy = await isInAppBusy(presence, handle);
  const pstnRow = await env.DB.prepare("SELECT since FROM pstn_presence WHERE handle = ?")
    .bind(handle)
    .first();
  const pstnBusy = !!(pstnRow && now - pstnRow.since < MAX_PSTN_BUSY_MS);

  if (inAppBusy || pstnBusy) {
    await logCall(env, user.id, {
      to_e164: toE164,
      from_e164: decision.fromE164,
      status: "blocked",
      block_reason: "already_on_call",
      started_at: now,
    });
    return { ok: false, reason: "already_on_call" };
  }

  const provider = getProvider(env);

  // Browser-initiated carrier (Twilio): hand the browser a one-time ticket. The
  // call is placed by the SDK and re-authorized at the TwiML webhook, which
  // reserves presence. An abandoned dial never reserves presence, so it can't
  // wedge one-call-at-a-time.
  if (!provider.placesCallsServerSide) {
    const ticket = randomToken(24);
    const timeLimitSec = (policyRow && policyRow.per_call_max_sec) || DEFAULT_CALL_TIME_LIMIT_SEC;
    await env.DB.prepare(
      `INSERT INTO dial_tickets (id, user_id, handle, from_e164, to_e164, time_limit_sec, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(ticket, user.id, handle, decision.fromE164, toE164, timeLimitSec, now, now + TICKET_TTL_MS)
      .run();
    return { ok: true, ticket, from: decision.fromE164, status: "ready" };
  }

  // Server-side carrier (mock): reserve presence, place, log, release now.
  await env.DB.prepare("INSERT OR REPLACE INTO pstn_presence (handle, since) VALUES (?, ?)")
    .bind(handle, now)
    .run();
  await controlPstn(presence, "pstn-begin", handle);

  try {
    const res = await provider.placeCall({ fromE164: decision.fromE164, toE164, userId: user.id });

    await logCall(env, user.id, {
      to_e164: toE164,
      from_e164: decision.fromE164,
      provider_call_ref: res.callRef,
      status: res.status,
      started_at: now,
      ended_at: now,
      duration_sec: res.durationSec || 0,
      price_micro: res.priceMicro || 0,
      currency: res.currency || "GBP",
    });

    return { ok: true, callRef: res.callRef, status: res.status, from: decision.fromE164 };
  } finally {
    await env.DB.prepare("DELETE FROM pstn_presence WHERE handle = ?").bind(handle).run();
    await controlPstn(presence, "pstn-end", handle);
  }
}

/**
 * Redeem a dial ticket at the carrier's TwiML webhook. Proves the destination +
 * caller ID were authorized, atomically reserves one-call-at-a-time presence,
 * binds the carrier CallSid, and opens the call log. Returns the parameters the
 * webhook needs to emit the <Dial>.
 *
 * @param {object} args
 * @param {string} args.ticketId
 * @param {string} args.callSid     carrier-side call id
 * @param {string} args.clientHandle  handle Twilio derived from the access token
 * @returns {{ok:true, fromE164:string, toE164:string, timeLimitSec:number} | {ok:false, reason:string}}
 */
export async function redeemDialTicket(env, { ticketId, callSid, clientHandle }, opts = {}) {
  const now = opts.now ?? Date.now();
  if (!ticketId || !callSid) return { ok: false, reason: "bad_request" };

  const t = await env.DB.prepare("SELECT * FROM dial_tickets WHERE id = ?").bind(ticketId).first();
  if (!t) return { ok: false, reason: "no_ticket" };
  if (t.used_at) return { ok: false, reason: "ticket_used" };
  if (t.expires_at < now) return { ok: false, reason: "ticket_expired" };
  // Identity comes from the signed access token (From=client:<handle>), never
  // from client-supplied params. Reject if it doesn't match the ticket's owner.
  if (clientHandle && t.handle !== clientHandle) return { ok: false, reason: "handle_mismatch" };

  const handle = t.handle;
  const presence = env.SIGNALING.get(env.SIGNALING.idFromName("global"));
  if (await isInAppBusy(presence, handle)) return { ok: false, reason: "already_on_call" };

  // Reserve PSTN presence atomically: clear a stale row, then insert-if-absent.
  await env.DB.prepare("DELETE FROM pstn_presence WHERE handle = ? AND since < ?")
    .bind(handle, now - MAX_PSTN_BUSY_MS)
    .run();
  const reserved = await env.DB.prepare(
    "INSERT INTO pstn_presence (handle, since) VALUES (?, ?) ON CONFLICT(handle) DO NOTHING"
  )
    .bind(handle, now)
    .run();
  if (!reserved.meta || reserved.meta.changes !== 1) return { ok: false, reason: "already_on_call" };
  await controlPstn(presence, "pstn-begin", handle);

  await env.DB.prepare("UPDATE dial_tickets SET used_at = ?, call_sid = ? WHERE id = ?")
    .bind(now, callSid, ticketId)
    .run();
  await logCall(env, t.user_id, {
    to_e164: t.to_e164,
    from_e164: t.from_e164,
    provider_call_ref: callSid,
    status: "in-progress",
    started_at: now,
  });

  return {
    ok: true,
    fromE164: t.from_e164,
    toE164: t.to_e164,
    timeLimitSec: t.time_limit_sec || DEFAULT_CALL_TIME_LIMIT_SEC,
  };
}

/**
 * Finalize a call from the carrier's status webhook: record the outcome and, on
 * a terminal status, release one-call-at-a-time presence. Idempotent.
 */
export async function finalizeCallByStatus(env, params, opts = {}) {
  const now = opts.now ?? Date.now();
  const callSid = params.CallSid || params.DialCallSid;
  if (!callSid) return { ok: false };

  const status = String(params.DialCallStatus || params.CallStatus || "").toLowerCase();
  const durationSec = parseInt(params.DialCallDuration || params.CallDuration || "0", 10) || 0;
  const terminal = TERMINAL_STATUSES.has(status);

  if (terminal) {
    await env.DB.prepare(
      "UPDATE call_logs SET status = ?, duration_sec = ?, price_micro = ?, currency = 'GBP', ended_at = ? WHERE provider_call_ref = ?"
    )
      .bind(status || "completed", durationSec, estimateCostMicro(env, durationSec), now, callSid)
      .run();
  } else {
    await env.DB.prepare("UPDATE call_logs SET status = ? WHERE provider_call_ref = ?")
      .bind(status || "in-progress", callSid)
      .run();
  }

  if (terminal) {
    const t = await env.DB.prepare("SELECT handle FROM dial_tickets WHERE call_sid = ?")
      .bind(callSid)
      .first();
    if (t) {
      const presence = env.SIGNALING.get(env.SIGNALING.idFromName("global"));
      await env.DB.prepare("DELETE FROM pstn_presence WHERE handle = ?").bind(t.handle).run();
      await controlPstn(presence, "pstn-end", t.handle);
    }
  }
  return { ok: true, terminal };
}

async function isInAppBusy(stub, handle) {
  try {
    const resp = await stub.fetch("https://signaling/control/busy", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle }),
    });
    const data = await resp.json();
    return !!data.busy;
  } catch {
    return false;
  }
}

async function controlPstn(stub, action, handle) {
  try {
    await stub.fetch(`https://signaling/control/${action}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle }),
    });
  } catch {
    // best-effort mirror; D1 is authoritative
  }
}

async function logCall(env, userId, f) {
  await env.DB.prepare(
    `INSERT INTO call_logs
       (id, user_id, kind, direction, from_e164, to_e164, provider_call_ref, status,
        started_at, ended_at, duration_sec, price_micro, currency, block_reason)
     VALUES (?, ?, 'pstn', 'outbound', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      randomId(),
      userId,
      f.from_e164 || null,
      f.to_e164 || null,
      f.provider_call_ref || null,
      f.status || null,
      f.started_at || null,
      f.ended_at || null,
      f.duration_sec || null,
      f.price_micro || null,
      f.currency || null,
      f.block_reason || null
    )
    .run();
}
