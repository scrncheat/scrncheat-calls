// Mint Twilio Access Tokens (JWT, HS256) so the browser Voice SDK can register
// without ever seeing a long-lived secret. Signed with the API Key Secret; the
// short TTL means a leaked token expires quickly. Built on Web Crypto so it runs
// in the Worker (the Twilio Node SDK does not).

import { base64UrlEncode } from "../crypto.js";

async function hmacSha256Bytes(keyStr, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyStr),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

/**
 * Build a Twilio Voice Access Token granting outgoing calls through our TwiML
 * App. `identity` is the authenticated user handle — Twilio echoes it back as
 * `From=client:<identity>` on the TwiML webhook, which is how the Worker knows
 * who is calling without trusting client-supplied params.
 */
export async function mintVoiceAccessToken({
  accountSid,
  apiKeySid,
  apiKeySecret,
  twimlAppSid,
  identity,
  ttlSeconds = 3600,
  now = Date.now(),
}) {
  if (!accountSid || !apiKeySid || !apiKeySecret || !twimlAppSid || !identity) {
    throw new Error("twilio_access_token_misconfigured");
  }
  const iat = Math.floor(now / 1000);
  const header = { typ: "JWT", alg: "HS256", cty: "twilio-fpa;v=1" };
  const payload = {
    jti: `${apiKeySid}-${iat}`,
    iss: apiKeySid,
    sub: accountSid,
    iat,
    nbf: iat,
    exp: iat + ttlSeconds,
    grants: {
      identity,
      voice: { outgoing: { application_sid: twimlAppSid } },
    },
  };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(
    JSON.stringify(payload)
  )}`;
  const sig = base64UrlEncode(await hmacSha256Bytes(apiKeySecret, signingInput));
  return `${signingInput}.${sig}`;
}
