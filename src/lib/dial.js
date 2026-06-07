// Outbound PSTN dialing: run the toll-fraud authorization gate, then (if
// allowed) place the call via the telephony provider and log it. With the mock
// provider this never reaches the phone network and costs nothing.

import { evaluateDialPolicy, parsePrefixes, DEFAULT_BLOCKED_PREFIXES } from "./policy.js";
import { incrementCounter } from "./ratelimit.js";
import { getProvider } from "./telephony/index.js";
import { normalizeE164 } from "./phone.js";
import { randomId } from "./crypto.js";

const HOUR = 3600;
const HOURLY_CALL_LIMIT = 20;

/**
 * @param {object} [opts]
 * @param {number} [opts.now]
 * @param {boolean} [opts.enabled] override the telephony kill-switch (tests)
 */
export async function authorizeAndDial(env, user, toRaw, numberId, opts = {}) {
  const now = opts.now ?? Date.now();
  const enabled = opts.enabled ?? env.TELEPHONY_ENABLED === "true";
  const toE164 = normalizeE164(toRaw);

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

  const decision = evaluateDialPolicy({
    enabled,
    toE164,
    verifiedNumber,
    userId: user.id,
    allowedPrefixes,
    blockedPrefixes,
    hourlyCount,
    hourlyLimit: HOURLY_CALL_LIMIT,
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

  const res = await getProvider(env).placeCall({
    fromE164: decision.fromE164,
    toE164,
    userId: user.id,
  });

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
