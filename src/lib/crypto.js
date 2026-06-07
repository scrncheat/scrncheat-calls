// Small crypto helpers built on Web Crypto (available globally in Workers).

function toHex(bytes) {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function toBase64Url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  return new TextEncoder().encode(String(input));
}

/** Base64url (no padding) of a string or byte buffer — used for JWT parts. */
export function base64UrlEncode(input) {
  return toBase64Url(toBytes(input));
}

/** Standard base64 of a string or byte buffer — used for Basic auth + HMAC sigs. */
export function base64Encode(input) {
  let bin = "";
  for (const b of toBytes(input)) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** UUID v4 (random). */
export function randomId() {
  return crypto.randomUUID();
}

/** A 256-bit (by default) URL-safe opaque token. */
export function randomToken(bytes = 32) {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return toBase64Url(b);
}

/**
 * A uniform numeric code of `length` digits (zero-padded), using rejection
 * sampling to avoid modulo bias.
 */
export function randomDigitCode(length = 6) {
  const max = 10 ** length;
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return String(x % max).padStart(length, "0");
}

export async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toHex(new Uint8Array(digest));
}

export async function hmacSha256Hex(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message));
  return toHex(new Uint8Array(sig));
}

/** Timing-safe comparison of two equal-length hex strings. */
export function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
