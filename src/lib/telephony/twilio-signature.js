// Authenticate inbound Twilio webhooks (the TwiML and status-callback routes are
// not cookie/CSRF protected — they are called by Twilio, not the browser).
// Twilio signs each request as
//   base64( HMAC-SHA1( authToken, fullUrl + sortedConcat(key+value) ) )
// and sends it in the X-Twilio-Signature header. We recompute and compare in
// constant time. A valid signature also proves params weren't tampered with.

import { base64Encode, timingSafeEqualHex } from "../crypto.js";

async function hmacSha1Bytes(keyStr, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(keyStr),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

/** The signature Twilio should have sent for this exact url + POST params. */
export async function twilioSignatureBase64(authToken, url, params) {
  let data = url;
  for (const k of Object.keys(params).sort()) data += k + (params[k] ?? "");
  return base64Encode(await hmacSha1Bytes(authToken, data));
}

/**
 * @param {object} o
 * @param {string} o.authToken  Twilio account auth token (secret)
 * @param {string} o.url        the exact URL Twilio requested (incl. scheme/host)
 * @param {Record<string,string>} o.params  POST form params
 * @param {string} o.signature  X-Twilio-Signature header value
 */
export async function isValidTwilioRequest({ authToken, url, params, signature }) {
  if (!authToken || !signature) return false;
  const expected = await twilioSignatureBase64(authToken, url, params);
  // timingSafeEqualHex is a constant-time equal-length string compare (not hex-
  // specific); it returns false on length mismatch, which is what we want here.
  return timingSafeEqualHex(expected, signature);
}
