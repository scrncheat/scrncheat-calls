// Cookie parsing/serialisation helpers.

export function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const out = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    const name = part.slice(0, idx).trim();
    if (!name) continue;
    out[name] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

/**
 * Serialise a Set-Cookie value.
 * @param {object} [opts]
 * @param {boolean} [opts.httpOnly]
 * @param {boolean} [opts.secure]
 * @param {"Strict"|"Lax"|"None"} [opts.sameSite]
 * @param {string} [opts.path]
 * @param {number} [opts.maxAge] seconds; 0 expires immediately
 */
export function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${opts.path || "/"}`);
  if (opts.httpOnly) parts.push("HttpOnly");
  if (opts.secure) parts.push("Secure");
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (typeof opts.maxAge === "number") {
    parts.push(`Max-Age=${opts.maxAge}`);
    const expires = new Date(Date.now() + opts.maxAge * 1000).toUTCString();
    parts.push(`Expires=${expires}`);
  }
  return parts.join("; ");
}

export const SESSION_COOKIE = "pfc_session";
export const CSRF_COOKIE = "pfc_csrf";
