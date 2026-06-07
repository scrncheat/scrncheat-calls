import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { getOrCreateUser } from "../src/lib/auth.js";
import { authorizeAndDial, redeemDialTicket, finalizeCallByStatus } from "../src/lib/dial.js";

const twilioEnv = { ...env, TELEPHONY_PROVIDER: "twilio" };

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

const presenceRow = (handle) =>
  env.DB.prepare("SELECT since FROM pstn_presence WHERE handle = ?").bind(handle).first();

describe("twilio browser-initiated dial — ticket flow", () => {
  it("authorize mints a ticket (no presence reserved, no callRef)", async () => {
    const u = await getOrCreateUser(env, "tk-auth@example.com");
    const numId = await seedVerified(u.id, "+447400555001");

    const r = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });
    expect(r).toMatchObject({ ok: true, from: "+447400555001", status: "ready" });
    expect(r.ticket).toBeTruthy();
    expect(r.callRef).toBeUndefined();

    const ticket = await env.DB.prepare("SELECT * FROM dial_tickets WHERE id = ?").bind(r.ticket).first();
    expect(ticket).toMatchObject({ user_id: u.id, from_e164: "+447400555001", to_e164: "+33123456789" });
    expect(ticket.used_at).toBeNull();
    // Abandoned dial must not wedge presence.
    expect(await presenceRow(u.email)).toBeNull();
  });

  it("redeem reserves presence, binds the CallSid, and opens the call log", async () => {
    const u = await getOrCreateUser(env, "tk-redeem@example.com");
    const numId = await seedVerified(u.id, "+447400555002");
    const { ticket } = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });

    const r = await redeemDialTicket(twilioEnv, {
      ticketId: ticket,
      callSid: "CA-redeem-1",
      clientHandle: u.email,
    });
    expect(r).toMatchObject({ ok: true, fromE164: "+447400555002", toE164: "+33123456789" });
    expect(r.timeLimitSec).toBeGreaterThan(0);

    expect(await presenceRow(u.email)).not.toBeNull();
    const log = await env.DB.prepare(
      "SELECT * FROM call_logs WHERE provider_call_ref = ?"
    ).bind("CA-redeem-1").first();
    expect(log).toMatchObject({ status: "in-progress", from_e164: "+447400555002", to_e164: "+33123456789" });

    // Single-use: a second redeem is rejected.
    expect(
      await redeemDialTicket(twilioEnv, { ticketId: ticket, callSid: "CA-x", clientHandle: u.email })
    ).toMatchObject({ ok: false, reason: "ticket_used" });
  });

  it("rejects an unknown, expired, or mismatched ticket", async () => {
    const u = await getOrCreateUser(env, "tk-bad@example.com");
    const numId = await seedVerified(u.id, "+447400555003");

    expect(
      await redeemDialTicket(twilioEnv, { ticketId: "nope", callSid: "CA1", clientHandle: u.email })
    ).toMatchObject({ ok: false, reason: "no_ticket" });

    const { ticket } = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });
    // Wrong identity (token-derived handle) must be rejected.
    expect(
      await redeemDialTicket(twilioEnv, { ticketId: ticket, callSid: "CA1", clientHandle: "attacker@example.com" })
    ).toMatchObject({ ok: false, reason: "handle_mismatch" });

    const expired = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });
    expect(
      await redeemDialTicket(
        twilioEnv,
        { ticketId: expired.ticket, callSid: "CA1", clientHandle: u.email },
        { now: Date.now() + 10 * 60 * 1000 }
      )
    ).toMatchObject({ ok: false, reason: "ticket_expired" });
  });

  it("redeem is blocked while already on a call (one at a time)", async () => {
    const u = await getOrCreateUser(env, "tk-busy@example.com");
    const numId = await seedVerified(u.id, "+447400555004");
    // Mint the ticket while free, then become busy before redeem — this exercises
    // redeem's atomic presence reservation (the dial-time check is only advisory).
    const { ticket } = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });
    await env.DB.prepare("INSERT OR REPLACE INTO pstn_presence (handle, since) VALUES (?, ?)")
      .bind(u.email, Date.now())
      .run();
    const r = await redeemDialTicket(twilioEnv, { ticketId: ticket, callSid: "CA1", clientHandle: u.email });
    expect(r).toMatchObject({ ok: false, reason: "already_on_call" });
  });

  it("status webhook finalizes the log and releases presence", async () => {
    const u = await getOrCreateUser(env, "tk-final@example.com");
    const numId = await seedVerified(u.id, "+447400555005");
    const { ticket } = await authorizeAndDial(twilioEnv, u, "+33123456789", numId, { enabled: true });
    await redeemDialTicket(twilioEnv, { ticketId: ticket, callSid: "CA-final-1", clientHandle: u.email });

    expect(await presenceRow(u.email)).not.toBeNull();

    await finalizeCallByStatus(twilioEnv, {
      CallSid: "CA-final-1",
      DialCallStatus: "completed",
      DialCallDuration: "42",
    });

    expect(await presenceRow(u.email)).toBeNull();
    const log = await env.DB.prepare("SELECT * FROM call_logs WHERE provider_call_ref = ?")
      .bind("CA-final-1")
      .first();
    expect(log).toMatchObject({ status: "completed", duration_sec: 42 });
    expect(log.ended_at).not.toBeNull();
  });
});
