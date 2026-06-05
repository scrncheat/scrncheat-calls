// Worker entry: static SPA, passwordless auth API, session-gated WebSocket
// signaling, and (later) the PSTN authorization gate. Owns all secrets, DB
// access, and authorization.

import { parseCookies, serializeCookie, SESSION_COOKIE, CSRF_COOKIE } from "./lib/cookies.js";
import {
  ok,
  badRequest,
  unauthorized,
  forbidden,
  tooManyRequests,
  notFound,
  serverError,
} from "./lib/responses.js";
import {
  requestLoginCode,
  verifyLoginCode,
  getSessionUser,
  revokeSession,
} from "./lib/auth.js";
import { randomToken, timingSafeEqualHex } from "./lib/crypto.js";
import { getTurnCredentials } from "./lib/turn.js";
import { SignalingRoom } from "./signaling-do.js";

export { SignalingRoom };

export default {
  async fetch(request, env, ctx) {
    try {
      return await handle(request, env, ctx);
    } catch (err) {
      console.error("Unhandled error:", err && err.stack ? err.stack : err);
      return serverError();
    }
  },
};

async function handle(request, env) {
  const url = new URL(request.url);

  if (url.pathname === "/ws") {
    return handleWsUpgrade(request, env, url);
  }
  if (url.pathname.startsWith("/api/")) {
    return handleApi(request, env, url);
  }
  return serveAsset(request, env);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    (request.headers.get("X-Forwarded-For") || "").split(",")[0].trim() ||
    "0.0.0.0"
  );
}

// CSRF defence: a state-changing request's Origin must match the target origin.
// Requests without an Origin header (curl, same-origin GET, tests) are allowed;
// browser-issued cross-site requests always carry Origin and are rejected.
function originAllowed(request, url) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  return origin === url.origin;
}

function jsonWithHeaders(data, status, headers) {
  const h = new Headers(headers);
  h.set("Content-Type", "application/json; charset=utf-8");
  h.set("Cache-Control", "no-store");
  h.set("X-Content-Type-Options", "nosniff");
  return new Response(JSON.stringify(data), { status, headers: h });
}

// ---------------------------------------------------------------------------
// API routing
// ---------------------------------------------------------------------------

const ROUTES = [
  { method: "POST", path: "/api/auth/request-code", handler: hRequestCode, auth: false, csrf: false },
  { method: "POST", path: "/api/auth/verify-code", handler: hVerifyCode, auth: false, csrf: false },
  { method: "POST", path: "/api/auth/logout", handler: hLogout, auth: true, csrf: true },
  { method: "GET", path: "/api/auth/me", handler: hMe, auth: true, csrf: false },
  { method: "GET", path: "/api/turn", handler: hTurn, auth: true, csrf: false },
];

async function handleApi(request, env, url) {
  const method = request.method;
  const unsafe = method !== "GET" && method !== "HEAD";
  if (unsafe && !originAllowed(request, url)) return forbidden("bad_origin");

  const route = ROUTES.find((r) => r.method === method && r.path === url.pathname);
  if (!route) return notFound();

  const cookies = parseCookies(request);
  const c = { url, cookies, secure: url.protocol === "https:", user: null };

  if (route.auth) {
    const user = await getSessionUser(env, cookies[SESSION_COOKIE]);
    if (!user) return unauthorized();
    c.user = user;
  }

  if (route.csrf) {
    const headerToken = request.headers.get("X-CSRF-Token") || "";
    const cookieToken = cookies[CSRF_COOKIE] || "";
    if (
      !headerToken ||
      !cookieToken ||
      headerToken.length !== cookieToken.length ||
      !timingSafeEqualHex(headerToken, cookieToken)
    ) {
      return forbidden("bad_csrf");
    }
  }

  return route.handler(request, env, c);
}

// ---------------------------------------------------------------------------
// Auth handlers
// ---------------------------------------------------------------------------

async function hRequestCode(request, env, c) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest();
  }
  const result = await requestLoginCode(env, body && body.email, clientIp(request));
  if (result.reason === "rate_limited") return tooManyRequests();
  // Neutral response — never reveal whether the address exists.
  return ok({ message: "If that email is valid, a code has been sent." });
}

async function hVerifyCode(request, env, c) {
  let body;
  try {
    body = await request.json();
  } catch {
    return badRequest();
  }
  const ua = request.headers.get("User-Agent") || "";
  const result = await verifyLoginCode(env, body && body.email, body && body.code, clientIp(request), ua);
  if (!result.ok) {
    if (result.error === "rate_limited") return tooManyRequests();
    return unauthorized("invalid_code");
  }

  const maxAge = Math.max(1, Math.floor((result.session.expiresAt - Date.now()) / 1000));
  const csrf = randomToken(24);
  const headers = new Headers();
  headers.append(
    "Set-Cookie",
    serializeCookie(SESSION_COOKIE, result.session.token, {
      httpOnly: true,
      secure: c.secure,
      sameSite: "Lax",
      path: "/",
      maxAge,
    })
  );
  headers.append(
    "Set-Cookie",
    serializeCookie(CSRF_COOKIE, csrf, {
      httpOnly: false,
      secure: c.secure,
      sameSite: "Lax",
      path: "/",
      maxAge,
    })
  );
  return jsonWithHeaders({ ok: true, user: { email: result.user.email } }, 200, headers);
}

async function hLogout(request, env, c) {
  await revokeSession(env, c.cookies[SESSION_COOKIE]);
  const headers = new Headers();
  for (const [name, httpOnly] of [
    [SESSION_COOKIE, true],
    [CSRF_COOKIE, false],
  ]) {
    headers.append(
      "Set-Cookie",
      serializeCookie(name, "", { httpOnly, secure: c.secure, sameSite: "Lax", path: "/", maxAge: 0 })
    );
  }
  return jsonWithHeaders({ ok: true }, 200, headers);
}

async function hMe(request, env, c) {
  return ok({ user: { email: c.user.email } });
}

async function hTurn(request, env, c) {
  const iceServers = await getTurnCredentials(env);
  return ok({ iceServers });
}

// ---------------------------------------------------------------------------
// WebSocket signaling upgrade
// ---------------------------------------------------------------------------

async function handleWsUpgrade(request, env, url) {
  if (request.headers.get("Upgrade") !== "websocket") {
    return new Response("expected websocket", { status: 426 });
  }
  // Same-origin only.
  const origin = request.headers.get("Origin");
  if (origin && origin !== url.origin) {
    return new Response("forbidden", { status: 403 });
  }

  const cookies = parseCookies(request);
  const user = await getSessionUser(env, cookies[SESSION_COOKIE]);
  if (!user) return new Response("unauthorized", { status: 401 });

  // Forward to the single global signaling DO, injecting the authenticated
  // handle (overwriting any client-supplied value).
  const id = env.SIGNALING.idFromName("global");
  const stub = env.SIGNALING.get(id);
  const fwd = new URL(url);
  fwd.searchParams.set("handle", user.email);
  return stub.fetch(new Request(fwd.toString(), request));
}

// ---------------------------------------------------------------------------
// Static assets (SPA) with security headers
// ---------------------------------------------------------------------------

const CSP =
  "default-src 'self'; connect-src 'self'; media-src 'self' blob:; " +
  "img-src 'self' data:; style-src 'self'; script-src 'self'; " +
  "base-uri 'none'; frame-ancestors 'none'";

async function serveAsset(request, env) {
  const resp = await env.ASSETS.fetch(request);
  const headers = new Headers(resp.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Referrer-Policy", "same-origin");
  headers.set("Content-Security-Policy", CSP);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers });
}
