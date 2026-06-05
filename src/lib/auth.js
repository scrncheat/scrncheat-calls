// Passwordless email-code auth: code issuance/verification + opaque sessions.
// All security-critical state lives in D1; codes are stored only as HMACs.

import {
  randomId,
  randomToken,
  randomDigitCode,
  sha256Hex,
  hmacSha256Hex,
  timingSafeEqualHex,
} from "./crypto.js";
import { checkRateLimit } from "./ratelimit.js";
import { sendLoginCodeEmail } from "./email.js";

const HOUR = 3600;
const TEN_MIN = 600;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

export function isValidEmail(email) {
  const e = normalizeEmail(email);
  return e.length >= 3 && e.length <= 254 && EMAIL_RE.test(e);
}

function hashCode(env, code, salt) {
  return hmacSha256Hex(env.OTP_PEPPER ?? "", `${code}:${salt}`);
}

/**
 * Issue an email login code. Returns a neutral result; callers must not leak
 * whether the email exists. `reason: "rate_limited"` lets the endpoint return
 * 429 (keyed on IP/email so it is not an enumeration oracle).
 */
export async function requestLoginCode(env, rawEmail, ip, now = Date.now()) {
  const email = normalizeEmail(rawEmail);
  if (!isValidEmail(email)) return { sent: false, reason: "invalid" };

  const perEmail = await checkRateLimit(env, `otp:req:email:${email}`, 5, HOUR, now);
  const perIp = await checkRateLimit(env, `otp:req:ip:${ip}`, 20, HOUR, now);
  if (!perEmail.allowed || !perIp.allowed) {
    return { sent: false, reason: "rate_limited" };
  }

  const code = randomDigitCode(6);
  const salt = randomToken(8);
  const codeHash = await hashCode(env, code, salt);
  const ttl = Number(env.LOGIN_CODE_TTL_SECONDS || TEN_MIN);

  await env.DB.prepare(
    `INSERT INTO login_codes (id, email, code_hash, salt, created_at, expires_at, attempts, ip)
     VALUES (?, ?, ?, ?, ?, ?, 0, ?)`
  )
    .bind(randomId(), email, codeHash, salt, now, now + ttl * 1000, ip || null)
    .run();

  await sendLoginCodeEmail(env, email, code);

  // Test-only escape hatch for deterministic assertions. Gated by an env flag
  // that is never set in production; the HTTP handler ignores this field, so
  // the code is never exposed over the network regardless.
  const result = { sent: true };
  if (env.EXPOSE_CODES === "1") result.devCode = code;
  return result;
}

const MAX_CODE_ATTEMPTS = 5;

/**
 * Verify a submitted code. On success creates (or finds) the user and a session.
 */
export async function verifyLoginCode(env, rawEmail, rawCode, ip, ua, now = Date.now()) {
  const email = normalizeEmail(rawEmail);
  const code = String(rawCode || "");
  if (!isValidEmail(email) || !/^\d{6}$/.test(code)) {
    return { ok: false, error: "invalid" };
  }

  // Throttle verification attempts per IP (across codes) to blunt brute force.
  const perIp = await checkRateLimit(env, `otp:verify:ip:${ip}`, 30, TEN_MIN, now);
  if (!perIp.allowed) return { ok: false, error: "rate_limited" };

  const row = await env.DB.prepare(
    `SELECT * FROM login_codes
     WHERE email = ? AND consumed_at IS NULL
     ORDER BY created_at DESC LIMIT 1`
  )
    .bind(email)
    .first();

  // Same generic error for "no code", expired, exhausted, or wrong — no oracle.
  if (!row || row.expires_at < now || row.attempts >= MAX_CODE_ATTEMPTS) {
    return { ok: false, error: "invalid" };
  }

  const candidate = await hashCode(env, code, row.salt);
  if (!timingSafeEqualHex(candidate, row.code_hash)) {
    await env.DB.prepare(`UPDATE login_codes SET attempts = attempts + 1 WHERE id = ?`)
      .bind(row.id)
      .run();
    return { ok: false, error: "invalid" };
  }

  // Single-use: consume this code and any other outstanding codes for the email.
  await env.DB.prepare(`UPDATE login_codes SET consumed_at = ? WHERE email = ? AND consumed_at IS NULL`)
    .bind(now, email)
    .run();

  const user = await getOrCreateUser(env, email, now);
  const session = await createSession(env, user.id, ip, ua, now);
  return { ok: true, user, session };
}

export async function getOrCreateUser(env, email, now = Date.now()) {
  const existing = await env.DB.prepare(`SELECT * FROM users WHERE email = ?`).bind(email).first();
  if (existing) {
    await env.DB.prepare(`UPDATE users SET last_login_at = ? WHERE id = ?`).bind(now, existing.id).run();
    return existing;
  }
  const id = randomId();
  await env.DB.prepare(
    `INSERT INTO users (id, email, created_at, last_login_at, status) VALUES (?, ?, ?, ?, 'active')`
  )
    .bind(id, email, now, now)
    .run();
  return { id, email, created_at: now, last_login_at: now, status: "active" };
}

export async function createSession(env, userId, ip, ua, now = Date.now()) {
  const token = randomToken(32);
  const id = await sha256Hex(token);
  const ttl = Number(env.SESSION_TTL_SECONDS || 2592000);
  const expiresAt = now + ttl * 1000;
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, ip, user_agent)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, userId, now, expiresAt, now, ip || null, (ua || "").slice(0, 256))
    .run();
  return { token, expiresAt };
}

/** Resolve a raw session token to a user, or null. Touches idle timestamp. */
export async function getSessionUser(env, token, now = Date.now()) {
  if (!token) return null;
  const id = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT s.id AS sid, s.expires_at AS expires_at, s.revoked_at AS revoked_at,
            u.id AS user_id, u.email AS email, u.status AS status
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.id = ?`
  )
    .bind(id)
    .first();
  if (!row || row.revoked_at || row.expires_at < now || row.status !== "active") {
    return null;
  }
  await env.DB.prepare(`UPDATE sessions SET last_seen_at = ? WHERE id = ?`).bind(now, id).run();
  return { id: row.user_id, email: row.email, status: row.status };
}

export async function revokeSession(env, token, now = Date.now()) {
  if (!token) return;
  const id = await sha256Hex(token);
  await env.DB.prepare(`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
    .bind(now, id)
    .run();
}
