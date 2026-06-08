import { describe, it, expect } from "vitest";
import { mintVoiceAccessToken } from "../src/lib/telephony/twilio-jwt.js";
import {
  twilioSignatureBase64,
  isValidTwilioRequest,
} from "../src/lib/telephony/twilio-signature.js";

function decodeJwtPart(part) {
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)));
}

const CFG = {
  accountSid: "ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  apiKeySid: "SKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  apiKeySecret: "super-secret-key",
  twimlAppSid: "APxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  identity: "user@example.com",
};

describe("twilio access token", () => {
  it("mints a JWT with the expected header and voice grant", async () => {
    const jwt = await mintVoiceAccessToken({ ...CFG, ttlSeconds: 3600, now: 1_700_000_000_000 });
    const [h, p] = jwt.split(".");
    expect(jwt.split(".")).toHaveLength(3);

    const header = decodeJwtPart(h);
    expect(header).toMatchObject({ typ: "JWT", alg: "HS256", cty: "twilio-fpa;v=1" });

    const payload = decodeJwtPart(p);
    expect(payload.iss).toBe(CFG.apiKeySid);
    expect(payload.sub).toBe(CFG.accountSid);
    expect(payload.exp - payload.iat).toBe(3600);
    expect(payload.grants.identity).toBe(CFG.identity);
    expect(payload.grants.voice.outgoing.application_sid).toBe(CFG.twimlAppSid);
  });

  it("throws when misconfigured (missing secret)", async () => {
    await expect(mintVoiceAccessToken({ ...CFG, apiKeySecret: "" })).rejects.toThrow(
      "twilio_access_token_misconfigured"
    );
  });
});

describe("twilio webhook signature", () => {
  // Twilio's official documented test vector.
  const url = "https://mycompany.com/myapp.php?foo=1&bar=2";
  const params = {
    Digits: "1234",
    To: "+18005551212",
    From: "+14158675309",
    Caller: "+14158675309",
    CallSid: "CA1234567890ABCDE",
  };
  const authToken = "12345";
  // Cross-checked against Node's crypto (the same algorithm Twilio's own helper
  // library uses): base64(HMAC-SHA1(token, url + sorted key+value concat)).
  const expectedSig = "RSOYDt4T1cUTdK1PDd93/VVr8B8=";

  it("reproduces the reference signature vector", async () => {
    expect(await twilioSignatureBase64(authToken, url, params)).toBe(expectedSig);
  });

  it("accepts a correctly signed request", async () => {
    expect(await isValidTwilioRequest({ authToken, url, params, signature: expectedSig })).toBe(true);
  });

  it("rejects a tampered parameter", async () => {
    const tampered = { ...params, To: "+19998887777" };
    expect(await isValidTwilioRequest({ authToken, url, params: tampered, signature: expectedSig })).toBe(
      false
    );
  });

  it("rejects a wrong auth token", async () => {
    expect(
      await isValidTwilioRequest({ authToken: "wrong", url, params, signature: expectedSig })
    ).toBe(false);
  });

  it("rejects a missing signature", async () => {
    expect(await isValidTwilioRequest({ authToken, url, params, signature: "" })).toBe(false);
  });
});
