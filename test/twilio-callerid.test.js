import { env } from "cloudflare:test";
import { describe, it, expect, vi, afterEach } from "vitest";
import { getOrCreateUser } from "../src/lib/auth.js";
import { registerNumber, sendNumberVerification, confirmNumber } from "../src/lib/numbers.js";
import { TwilioProvider } from "../src/lib/telephony/twilio.js";

const ACCOUNT = "ACtest0000000000000000000000000000";
const fakeEnv = (over = {}) => ({
  ...env,
  TELEPHONY_PROVIDER: "twilio",
  TWILIO_ACCOUNT_SID: ACCOUNT,
  TWILIO_AUTH_TOKEN: "token",
  ...over,
});

// Stub global fetch with a tiny router over (method, path) -> json body.
function stubTwilio(routes) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init = {}) => {
      const u = new URL(String(url));
      const method = (init.method || "GET").toUpperCase();
      const key = `${method} ${u.pathname}${u.search}`;
      const match = routes[key];
      if (!match) return new Response("no mock for " + key, { status: 418 });
      return new Response(JSON.stringify(match.body), {
        status: match.status,
        headers: { "content-type": "application/json" },
      });
    })
  );
}
afterEach(() => vi.unstubAllGlobals());

const base = `/2010-04-01/Accounts/${ACCOUNT}/OutgoingCallerIds.json`;
const listKey = (e164) => `GET ${base}?PhoneNumber=${encodeURIComponent(e164)}`;

describe("twilio verified caller id — provider", () => {
  it("startCallerIdValidation returns the display code and call ref", async () => {
    stubTwilio({
      [`POST ${base}`]: {
        status: 201,
        body: { validation_code: "482913", call_sid: "CA123", phone_number: "+447400123456" },
      },
    });
    const p = new TwilioProvider(fakeEnv());
    const r = await p.startCallerIdValidation({ e164: "+447400123456" });
    expect(r).toMatchObject({ ok: true, displayCode: "482913", ref: "CA123" });
  });

  it("startCallerIdValidation surfaces Twilio's error code and message on failure", async () => {
    stubTwilio({
      [`POST ${base}`]: {
        status: 400,
        body: { code: 21215, message: "Account not authorized to call +447400123456" },
      },
    });
    const p = new TwilioProvider(fakeEnv());
    const r = await p.startCallerIdValidation({ e164: "+447400123456" });
    expect(r).toMatchObject({
      ok: false,
      status: 400,
      code: 21215,
      detail: "Account not authorized to call +447400123456",
    });
  });

  it("isCallerIdValidated reflects whether the number is on the account", async () => {
    const e164 = "+447400123456";
    stubTwilio({ [listKey(e164)]: { status: 200, body: { outgoing_caller_ids: [{ phone_number: e164 }] } } });
    const p = new TwilioProvider(fakeEnv());
    expect(await p.isCallerIdValidated(e164)).toBe(true);
  });

  it("isCallerIdValidated is false when the list is empty", async () => {
    const e164 = "+447400999999";
    stubTwilio({ [listKey(e164)]: { status: 200, body: { outgoing_caller_ids: [] } } });
    const p = new TwilioProvider(fakeEnv());
    expect(await p.isCallerIdValidated(e164)).toBe(false);
  });
});

describe("twilio verified caller id — numbers flow", () => {
  it("verifies via Twilio's validation instead of the in-house OTP", async () => {
    const u = await getOrCreateUser(env, "twilio-cid@example.com");
    const e164 = "+447400123777";
    const tEnv = fakeEnv();

    const reg = await registerNumber(tEnv, u.id, e164);
    expect(reg.ok).toBe(true);

    // Send → Twilio starts validation and we surface the display code.
    stubTwilio({ [`POST ${base}`]: { status: 201, body: { validation_code: "246810", call_sid: "CA777" } } });
    const send = await sendNumberVerification(tEnv, u.id, reg.id);
    expect(send).toMatchObject({ ok: true, channel: "voice", displayCode: "246810" });
    expect(send.devCode).toBeUndefined(); // never an in-house OTP for this style

    // Confirm before Twilio finishes → not yet validated.
    stubTwilio({ [listKey(e164)]: { status: 200, body: { outgoing_caller_ids: [] } } });
    expect(await confirmNumber(tEnv, u.id, reg.id, "")).toMatchObject({
      ok: false,
      error: "not_yet_validated",
    });

    // Confirm once Twilio has validated → verified.
    stubTwilio({ [listKey(e164)]: { status: 200, body: { outgoing_caller_ids: [{ phone_number: e164 }] } } });
    expect(await confirmNumber(tEnv, u.id, reg.id, "")).toMatchObject({ ok: true, status: "verified" });
  });
});
