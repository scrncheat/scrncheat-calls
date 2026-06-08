import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { getOrCreateUser } from "../src/lib/auth.js";
import { authorizeAndDial, redeemDialTicket, finalizeCallByStatus } from "../src/lib/dial.js";

const twilioEnv = (over = {}) => ({ ...env, TELEPHONY_PROVIDER: "twilio", ...over });

async function seedVerified(userId, e164) {
  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO verified_numbers
       (id, user_id, e164, country, line_type, status, channel, verify_attempts, created_at, verified_at)
     VALUES (?, ?, ?, 'GB', 'mobile', 'verified', 'voice', 0, ?, ?)`
  )
    .bind(id, userId, e164, now, now)
    .run();
  return id;
}

describe("toll-fraud safety nets", () => {
  it("binds the per-call time limit to the ticket and surfaces it at redeem", async () => {
    const u = await getOrCreateUser(env, "cap-perCall@example.com");
    const numId = await seedVerified(u.id, "+447400556001");
    await env.DB.prepare(
      "INSERT OR REPLACE INTO dial_policy (user_id, per_call_max_sec, enabled) VALUES (?, ?, 1)"
    )
      .bind(u.id, 90)
      .run();

    const { ticket } = await authorizeAndDial(twilioEnv(), u, "+33123456789", numId, { enabled: true });
    const row = await env.DB.prepare("SELECT time_limit_sec FROM dial_tickets WHERE id = ?")
      .bind(ticket)
      .first();
    expect(row.time_limit_sec).toBe(90);

    const r = await redeemDialTicket(twilioEnv(), {
      ticketId: ticket,
      callSid: "CA-cap-1",
      clientHandle: u.email,
    });
    expect(r).toMatchObject({ ok: true, timeLimitSec: 90 });
  });

  it("blocks dialing once the daily spend cap is reached", async () => {
    const u = await getOrCreateUser(env, "cap-spend@example.com");
    const numId = await seedVerified(u.id, "+447400556002");
    // A completed call today that already hit the cap.
    await env.DB.prepare(
      `INSERT INTO call_logs (id, user_id, kind, direction, to_e164, status, started_at, price_micro)
       VALUES (?, ?, 'pstn', 'outbound', '+33000000000', 'completed', ?, ?)`
    )
      .bind(crypto.randomUUID(), u.id, Date.now(), 100000)
      .run();

    const r = await authorizeAndDial(
      twilioEnv({ DEFAULT_DAILY_SPEND_CAP_MICRO: "100000" }),
      u,
      "+33123456789",
      numId,
      { enabled: true }
    );
    expect(r).toMatchObject({ ok: false, reason: "spend_cap" });
  });

  it("does not cap when none is configured", async () => {
    const u = await getOrCreateUser(env, "cap-none@example.com");
    const numId = await seedVerified(u.id, "+447400556003");
    const r = await authorizeAndDial(twilioEnv(), u, "+33123456789", numId, { enabled: true });
    expect(r.ok).toBe(true);
  });

  it("accrues an estimated price on call completion", async () => {
    const u = await getOrCreateUser(env, "cap-accrue@example.com");
    const numId = await seedVerified(u.id, "+447400556004");
    const e = twilioEnv({ TELEPHONY_RATE_MICRO_PER_MIN: "30000" });
    const { ticket } = await authorizeAndDial(e, u, "+33123456789", numId, { enabled: true });
    await redeemDialTicket(e, { ticketId: ticket, callSid: "CA-accrue-1", clientHandle: u.email });

    await finalizeCallByStatus(e, {
      CallSid: "CA-accrue-1",
      DialCallStatus: "completed",
      DialCallDuration: "120", // 2 minutes
    });

    const log = await env.DB.prepare("SELECT price_micro FROM call_logs WHERE provider_call_ref = ?")
      .bind("CA-accrue-1")
      .first();
    expect(log.price_micro).toBe(60000); // ceil(120/60) * 30000
  });
});
