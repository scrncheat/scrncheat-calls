import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { getOrCreateUser } from "../src/lib/auth.js";
import {
  registerNumber,
  sendNumberVerification,
  confirmNumber,
  listNumbers,
} from "../src/lib/numbers.js";
import { authorizeAndDial } from "../src/lib/dial.js";

const user = (email) => getOrCreateUser(env, email);

describe("number registration & verification", () => {
  it("registers and classifies a valid number", async () => {
    const u = await user("num1@example.com");
    const r = await registerNumber(env, u.id, "+44 7400 123456");
    expect(r.ok).toBe(true);
    expect(r.e164).toBe("+447400123456");
    expect(r.status).toBe("pending");
    expect(r.lineType).toBe("mobile");
  });

  it("rejects an invalid number", async () => {
    const u = await user("num2@example.com");
    const r = await registerNumber(env, u.id, "not a number");
    expect(r).toMatchObject({ ok: false, error: "invalid_number" });
  });

  it("enforces a per-user cap of 5 numbers", async () => {
    const u = await user("cap@example.com");
    for (const n of ["+447400123401", "+447400123402", "+447400123403", "+447400123404", "+447400123405"]) {
      expect((await registerNumber(env, u.id, n)).ok).toBe(true);
    }
    expect(await registerNumber(env, u.id, "+447400123406")).toMatchObject({
      ok: false,
      error: "too_many_numbers",
    });
  });

  it("verifies ownership via the OTP code", async () => {
    const u = await user("verify@example.com");
    const reg = await registerNumber(env, u.id, "+447400123410");
    const send = await sendNumberVerification(env, u.id, reg.id);
    expect(send.ok).toBe(true);
    expect(send.devCode).toMatch(/^\d{6}$/);

    const confirm = await confirmNumber(env, u.id, reg.id, send.devCode);
    expect(confirm).toMatchObject({ ok: true, status: "verified" });

    const list = await listNumbers(env, u.id);
    expect(list.find((x) => x.id === reg.id).status).toBe("verified");
  });

  it("rejects a wrong OTP and caps attempts at 5", async () => {
    const u = await user("wrongotp@example.com");
    const reg = await registerNumber(env, u.id, "+447400123411");
    const send = await sendNumberVerification(env, u.id, reg.id);
    const wrong = send.devCode === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) {
      expect((await confirmNumber(env, u.id, reg.id, wrong)).ok).toBe(false);
    }
    // Budget spent: the correct code is now rejected too.
    expect((await confirmNumber(env, u.id, reg.id, send.devCode)).ok).toBe(false);
  });

  it("prevents one user from verifying another user's number", async () => {
    const a = await user("owner@example.com");
    const b = await user("attacker@example.com");
    const reg = await registerNumber(env, a.id, "+447400123412");
    expect((await sendNumberVerification(env, b.id, reg.id)).error).toBe("not_found");
    expect((await confirmNumber(env, b.id, reg.id, "000000")).error).toBe("not_found");
  });
});

describe("external dial authorization (mock carrier)", () => {
  async function verifiedNumberFor(u, e164) {
    const reg = await registerNumber(env, u.id, e164);
    const send = await sendNumberVerification(env, u.id, reg.id);
    await confirmNumber(env, u.id, reg.id, send.devCode);
    return reg.id;
  }

  it("blocks dialing while telephony is disabled (default kill-switch)", async () => {
    const u = await user("dial-off@example.com");
    const numId = await verifiedNumberFor(u, "+447400123420");
    const r = await authorizeAndDial(env, u, "+33123456789", numId);
    expect(r).toMatchObject({ ok: false, reason: "telephony_disabled" });
  });

  it("places a call when enabled, presenting an owned verified caller id", async () => {
    const u = await user("dial-on@example.com");
    const numId = await verifiedNumberFor(u, "+447400123421");
    const r = await authorizeAndDial(env, u, "+33123456789", numId, { enabled: true });
    expect(r.ok).toBe(true);
    expect(r.from).toBe("+447400123421");
    expect(r.callRef).toMatch(/^mock-call-/);
  });

  it("refuses to present a caller id the user does not own", async () => {
    const a = await user("a-owner@example.com");
    const b = await user("b-attacker@example.com");
    const aNum = await verifiedNumberFor(a, "+447400123422");
    const r = await authorizeAndDial(env, b, "+33123456789", aNum, { enabled: true });
    expect(r).toMatchObject({ ok: false, reason: "caller_id_not_verified" });
  });

  it("blocks premium-rate destinations even when enabled", async () => {
    const u = await user("premium@example.com");
    const numId = await verifiedNumberFor(u, "+447400123423");
    const r = await authorizeAndDial(env, u, "+449001234567", numId, { enabled: true });
    expect(r).toMatchObject({ ok: false, reason: "destination_blocked" });
  });

  it("logs blocked attempts to call history", async () => {
    const u = await user("logged@example.com");
    const numId = await verifiedNumberFor(u, "+447400123424");
    await authorizeAndDial(env, u, "+12025550123", numId, { enabled: true }); // valid US, not in allow-list
    const { results } = await env.DB.prepare(
      "SELECT status, block_reason FROM call_logs WHERE user_id = ? ORDER BY started_at DESC LIMIT 1"
    )
      .bind(u.id)
      .all();
    expect(results[0]).toMatchObject({ status: "blocked", block_reason: "destination_not_allowed" });
  });
});
