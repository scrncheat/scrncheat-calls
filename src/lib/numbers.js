// Verified external numbers: registration, ownership verification (in-house OTP
// delivered via the telephony provider), and listing/removal.

import {
  randomId,
  randomToken,
  randomDigitCode,
  hmacSha256Hex,
  timingSafeEqualHex,
} from "./crypto.js";
import { classify } from "./phone.js";
import { getProvider } from "./telephony/index.js";
import { checkRateLimit } from "./ratelimit.js";

const MAX_NUMBERS_PER_USER = 5;
const VERIFY_TTL_SECONDS = 600;
const MAX_VERIFY_ATTEMPTS = 5;

function defaultChannel(lineType) {
  return lineType === "landline" ? "voice" : "sms";
}

export async function listNumbers(env, userId) {
  const { results } = await env.DB.prepare(
    `SELECT id, e164, country, line_type, status, channel, created_at, verified_at
     FROM verified_numbers WHERE user_id = ? ORDER BY created_at DESC`
  )
    .bind(userId)
    .all();
  return results || [];
}

export async function registerNumber(env, userId, rawNumber, now = Date.now()) {
  const c = classify(rawNumber);
  if (!c.e164) return { ok: false, error: "invalid_number" };

  const existing = await env.DB.prepare(
    "SELECT id, status FROM verified_numbers WHERE user_id = ? AND e164 = ?"
  )
    .bind(userId, c.e164)
    .first();
  if (existing) {
    return {
      ok: true,
      id: existing.id,
      e164: c.e164,
      status: existing.status,
      lineType: c.lineType,
      channel: defaultChannel(c.lineType),
      existing: true,
    };
  }

  const countRow = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM verified_numbers WHERE user_id = ?"
  )
    .bind(userId)
    .first();
  if ((countRow ? countRow.n : 0) >= MAX_NUMBERS_PER_USER) {
    return { ok: false, error: "too_many_numbers" };
  }

  const id = randomId();
  const channel = defaultChannel(c.lineType);
  await env.DB.prepare(
    `INSERT INTO verified_numbers
       (id, user_id, e164, country, line_type, status, channel, verify_attempts, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?, 0, ?)`
  )
    .bind(id, userId, c.e164, c.country, c.lineType, channel, now)
    .run();

  return { ok: true, id, e164: c.e164, status: "pending", lineType: c.lineType, channel };
}

export async function sendNumberVerification(env, userId, numberId, channelOverride, now = Date.now()) {
  const row = await env.DB.prepare("SELECT * FROM verified_numbers WHERE id = ? AND user_id = ?")
    .bind(numberId, userId)
    .first();
  if (!row) return { ok: false, error: "not_found" };
  if (row.status === "verified") return { ok: false, error: "already_verified" };

  // Cap verification sends per number per day.
  const rl = await checkRateLimit(env, `num:verify:send:${numberId}`, 5, 86400, now);
  if (!rl.allowed) return { ok: false, error: "rate_limited" };

  const provider = getProvider(env);

  // Carrier-driven caller-ID validation (e.g. Twilio): the carrier owns the
  // code and calls the number; we just show the code and poll for completion.
  if (provider.verificationStyle === "carrier-callerid") {
    const statusCb = env.APP_ORIGIN ? `${env.APP_ORIGIN}/api/numbers/callerid-status` : undefined;
    const res = await provider.startCallerIdValidation({
      e164: row.e164,
      friendlyName: `user:${userId}`,
      statusCallbackUrl: statusCb,
    });
    if (!res.ok) {
      console.warn("startCallerIdValidation failed", {
        status: res.status,
        code: res.code,
        detail: res.detail,
      });
      return { ok: false, error: "provider_error", status: res.status, code: res.code, detail: res.detail };
    }
    await env.DB.prepare(
      "UPDATE verified_numbers SET channel = 'voice', provider_ref = ?, verify_attempts = 0 WHERE id = ?"
    )
      .bind(res.ref || null, numberId)
      .run();
    // displayCode is meant to be shown to the user (not a secret like the OTP).
    return { ok: true, channel: "voice", displayCode: res.displayCode };
  }

  const channel =
    channelOverride === "voice" || channelOverride === "sms"
      ? channelOverride
      : row.channel || defaultChannel(row.line_type);

  const code = randomDigitCode(6);
  const salt = randomToken(8);
  const codeHash = await hmacSha256Hex(env.OTP_PEPPER ?? "", `${code}:${salt}`);

  await env.DB.prepare(
    `UPDATE verified_numbers
       SET verify_code_hash = ?, verify_salt = ?, verify_code_expires_at = ?, channel = ?, verify_attempts = 0
     WHERE id = ?`
  )
    .bind(codeHash, salt, now + VERIFY_TTL_SECONDS * 1000, channel, numberId)
    .run();

  await provider.sendVerification({ e164: row.e164, channel, code });

  const out = { ok: true, channel };
  if (env.EXPOSE_CODES === "1") out.devCode = code; // test-only; never returned over HTTP
  return out;
}

export async function confirmNumber(env, userId, numberId, code, now = Date.now()) {
  const row = await env.DB.prepare("SELECT * FROM verified_numbers WHERE id = ? AND user_id = ?")
    .bind(numberId, userId)
    .first();
  if (!row) return { ok: false, error: "not_found" };
  if (row.status === "verified") return { ok: true, status: "verified" };

  // Carrier-driven style: there is no code to check here — ask the carrier
  // whether the number is now a validated caller ID.
  const provider = getProvider(env);
  if (provider.verificationStyle === "carrier-callerid") {
    if (!(await provider.isCallerIdValidated(row.e164))) {
      return { ok: false, error: "not_yet_validated" };
    }
    await markVerified(env, numberId, now);
    return { ok: true, status: "verified" };
  }

  if (!row.verify_code_hash || !row.verify_code_expires_at || row.verify_code_expires_at < now) {
    return { ok: false, error: "no_pending_code" };
  }
  if (row.verify_attempts >= MAX_VERIFY_ATTEMPTS) return { ok: false, error: "too_many_attempts" };

  const candidate = await hmacSha256Hex(env.OTP_PEPPER ?? "", `${String(code)}:${row.verify_salt}`);
  if (!timingSafeEqualHex(candidate, row.verify_code_hash)) {
    await env.DB.prepare("UPDATE verified_numbers SET verify_attempts = verify_attempts + 1 WHERE id = ?")
      .bind(numberId)
      .run();
    return { ok: false, error: "invalid_code" };
  }

  await markVerified(env, numberId, now);
  return { ok: true, status: "verified" };
}

/** Flip a number to verified and clear any in-flight OTP material. */
async function markVerified(env, numberId, now) {
  await env.DB.prepare(
    `UPDATE verified_numbers
       SET status = 'verified', verified_at = ?, verify_code_hash = NULL, verify_salt = NULL, verify_code_expires_at = NULL
     WHERE id = ?`
  )
    .bind(now, numberId)
    .run();
}

export async function deleteNumber(env, userId, numberId) {
  await env.DB.prepare("DELETE FROM verified_numbers WHERE id = ? AND user_id = ?")
    .bind(numberId, userId)
    .run();
  return { ok: true };
}
