import { SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { twilioSignatureBase64 } from "../src/lib/telephony/twilio-signature.js";

const ORIGIN = "https://calls.example";
const AUTH = "test-twilio-token"; // must match the vitest.config TWILIO_AUTH_TOKEN binding

function form(params) {
  return new URLSearchParams(params).toString();
}

async function post(path, params, { signature } = {}) {
  const url = `${ORIGIN}${path}`;
  const headers = { "Content-Type": "application/x-www-form-urlencoded" };
  if (signature !== null) {
    headers["X-Twilio-Signature"] = signature ?? (await twilioSignatureBase64(AUTH, url, params));
  }
  return SELF.fetch(url, { method: "POST", headers, body: form(params) });
}

describe("twilio webhook signature gate (end-to-end through the worker)", () => {
  it("rejects an unsigned TwiML request with 403", async () => {
    const res = await post("/api/voice/twiml", { CallSid: "CA1", ticket: "x" }, { signature: null });
    expect(res.status).toBe(403);
    expect(await res.text()).toContain("<Reject/>");
  });

  it("accepts a correctly signed request (then rejects the bogus ticket with 200)", async () => {
    const res = await post("/api/voice/twiml", {
      CallSid: "CA1",
      From: "client:nobody@example.com",
      ticket: "bogus",
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain("<Reject/>"); // signature passed; ticket redemption failed
  });

  it("rejects a tampered status request (signature no longer matches)", async () => {
    const signed = { CallSid: "CA1", DialCallStatus: "completed" };
    const signature = await twilioSignatureBase64(AUTH, `${ORIGIN}/api/voice/twilio/status`, signed);
    // Tamper with a parameter after signing.
    const res = await post(
      "/api/voice/twilio/status",
      { ...signed, DialCallStatus: "busy" },
      { signature }
    );
    expect(res.status).toBe(403);
  });
});
