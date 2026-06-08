// Worker entry: static SPA, passwordless auth API, session-gated WebSocket
// signaling, and (later) the PSTN authorization gate. Owns all secrets, DB
// access, and authorization.

import { parseCookies, serializeCookie, SESSION_COOKIE, CSRF_COOKIE } from "./lib/cookies.js";
import {
  json,
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
import {
  listNumbers,
  registerNumber,
  sendNumberVerification,
  confirmNumber,
  deleteNumber,
} from "./lib/numbers.js";
import { authorizeAndDial, redeemDialTicket, finalizeCallByStatus } from "./lib/dial.js";
import { getProvider } from "./lib/telephony/index.js";
import { isValidTwilioRequest } from "./lib/telephony/twilio-signature.js";
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

  { method: "GET", path: "/api/numbers", handler: hListNumbers, auth: true, csrf: false },
  { method: "POST", path: "/api/numbers", handler: hRegisterNumber, auth: true, csrf: true },
  { method: "POST", path: "/api/numbers/:id/verify", handler: hSendVerify, auth: true, csrf: true },
  { method: "POST", path: "/api/numbers/:id/confirm", handler: hConfirmNumber, auth: true, csrf: true },
  { method: "DELETE", path: "/api/numbers/:id", handler: hDeleteNumber, auth: true, csrf: true },
  { method: "GET", path: "/api/voice/token", handler: hVoiceToken, auth: true, csrf: false },
  { method: "POST", path: "/api/voice/dial", handler: hDial, auth: true, csrf: true },
  { method: "GET", path: "/api/calls", handler: hCalls, auth: true, csrf: false },

  // Carrier webhooks: authenticated by the Twilio request signature (not the
  // session cookie/CSRF), since Twilio — not the browser — calls these.
  { method: "POST", path: "/api/voice/twiml", handler: hTwiml, auth: false, csrf: false },
  { method: "POST", path: "/api/voice/twilio/status", handler: hTwilioStatus, auth: false, csrf: false },
];

async function handleApi(request, env, url) {
  const method = request.method;
  const unsafe = method !== "GET" && method !== "HEAD";
  if (unsafe && !originAllowed(request, url)) return forbidden("bad_origin");

  const matched = matchRoute(method, url.pathname);
  if (!matched) return notFound();
  const { route, params } = matched;

  const cookies = parseCookies(request);
  const c = { url, cookies, params, secure: url.protocol === "https:", user: null };

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
  const dev = env.EXPOSE_CODES === "1" && result.devCode ? { devCode: result.devCode } : {};
  return ok({ message: "If that email is valid, a code has been sent.", ...dev });
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
  return ok({
    user: { email: c.user.email },
    telephonyEnabled: env.TELEPHONY_ENABLED === "true",
  });
}

async function hTurn(request, env, c) {
  const iceServers = await getTurnCredentials(env);
  return ok({ iceServers });
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function matchRoute(method, pathname) {
  const segs = pathname.split("/").filter(Boolean);
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const pat = route.path.split("/").filter(Boolean);
    if (pat.length !== segs.length) continue;
    const params = {};
    let okMatch = true;
    for (let i = 0; i < pat.length; i++) {
      if (pat[i].startsWith(":")) params[pat[i].slice(1)] = decodeURIComponent(segs[i]);
      else if (pat[i] !== segs[i]) {
        okMatch = false;
        break;
      }
    }
    if (okMatch) return { route, params };
  }
  return null;
}

// --- Verified numbers & external dialing (mock carrier; carrier OFF by default) ---

async function hListNumbers(request, env, c) {
  return ok({ numbers: await listNumbers(env, c.user.id) });
}

async function hRegisterNumber(request, env, c) {
  const body = await readJson(request);
  if (!body) return badRequest();
  const r = await registerNumber(env, c.user.id, body.number);
  if (!r.ok) return badRequest(r.error);
  return ok({ number: { id: r.id, e164: r.e164, status: r.status, lineType: r.lineType, channel: r.channel } });
}

async function hSendVerify(request, env, c) {
  const body = (await readJson(request)) || {};
  const r = await sendNumberVerification(env, c.user.id, c.params.id, body.channel);
  if (!r.ok) {
    if (r.error === "rate_limited") return tooManyRequests();
    if (r.error === "not_found") return notFound();
    if (r.error === "provider_error") {
      console.warn("number verification provider error", { status: r.status, code: r.code, detail: r.detail });
      return json(
        { ok: false, error: "provider_error", providerStatus: r.status, providerCode: r.code, detail: r.detail },
        400
      );
    }
    return badRequest(r.error);
  }
  // The OTP is delivered by the carrier; only exposed over HTTP in dev/test.
  // A carrier-driven displayCode (Twilio Verified Caller ID) is meant to be
  // shown to the user, so it is always returned.
  const dev = env.EXPOSE_CODES === "1" && r.devCode ? { devCode: r.devCode } : {};
  const display = r.displayCode ? { displayCode: r.displayCode } : {};
  return ok({ channel: r.channel, ...display, ...dev });
}

async function hConfirmNumber(request, env, c) {
  const body = await readJson(request);
  if (!body) return badRequest();
  const r = await confirmNumber(env, c.user.id, c.params.id, body.code);
  if (!r.ok) {
    if (r.error === "not_found") return notFound();
    return badRequest(r.error);
  }
  return ok({ status: r.status });
}

async function hDeleteNumber(request, env, c) {
  await deleteNumber(env, c.user.id, c.params.id);
  return ok({});
}

async function hDial(request, env, c) {
  const body = await readJson(request);
  if (!body) return badRequest();
  const r = await authorizeAndDial(env, c.user, body.to, body.numberId);
  if (!r.ok) {
    const status = r.reason === "rate_limited" ? 429 : 403;
    return jsonWithHeaders({ ok: false, error: r.reason }, status, new Headers());
  }
  // `ticket` (browser-initiated carrier) or `callRef` (server-side mock) — the
  // client passes the ticket opaquely to the Voice SDK; it never sees To/callerId.
  return ok({ ticket: r.ticket, callRef: r.callRef, from: r.from, status: r.status });
}

async function hCalls(request, env, c) {
  const { results } = await env.DB.prepare(
    `SELECT id, kind, direction, from_e164, to_e164, status, block_reason, started_at, duration_sec
     FROM call_logs WHERE user_id = ? ORDER BY started_at DESC LIMIT 50`
  )
    .bind(c.user.id)
    .all();
  return ok({ calls: results || [] });
}

// --- Browser softphone: mint a short-lived carrier Access Token (session-gated) ---

async function hVoiceToken(request, env, c) {
  if (env.TELEPHONY_ENABLED !== "true") return badRequest("telephony_disabled");
  const provider = getProvider(env);
  if (typeof provider.createAccessToken !== "function") return badRequest("token_unsupported");
  try {
    const identity = String(c.user.email || "").toLowerCase();
    const token = await provider.createAccessToken(identity);
    return ok({ token, identity });
  } catch {
    return serverError("token_error");
  }
}

// --- Twilio carrier webhooks (authenticated by request signature) ---

async function readTwilioForm(request, env) {
  const signature = request.headers.get("X-Twilio-Signature") || "";
  const text = await request.text();
  const params = Object.fromEntries(new URLSearchParams(text));
  const valid = await isValidTwilioRequest({
    authToken: env.TWILIO_AUTH_TOKEN,
    url: request.url,
    params,
    signature,
  });
  return { valid, params };
}

function xmlResponse(body, status = 200) {
  return new Response(`<?xml version="1.0" encoding="UTF-8"?>${body}`, {
    status,
    headers: { "Content-Type": "text/xml; charset=utf-8", "Cache-Control": "no-store" },
  });
}

// Twilio fetches this when the browser places a call. The browser passed only an
// opaque ticket; we redeem it to recover the authorized caller ID + destination
// and emit the <Dial>. Identity is taken from From=client:<handle> (token-derived).
async function hTwiml(request, env) {
  const { valid, params } = await readTwilioForm(request, env);
  if (!valid) return xmlResponse("<Response><Reject/></Response>", 403);

  const from = params.From || "";
  const clientHandle = from.startsWith("client:") ? from.slice("client:".length).toLowerCase() : "";
  const r = await redeemDialTicket(env, {
    ticketId: params.ticket || "",
    callSid: params.CallSid || "",
    clientHandle,
  });
  if (!r.ok) return xmlResponse("<Response><Reject/></Response>");

  const action = `${env.APP_ORIGIN}/api/voice/twilio/status`;
  return xmlResponse(
    `<Response><Dial answerOnBridge="true" callerId="${r.fromE164}" timeLimit="${r.timeLimitSec}" ` +
      `action="${action}" method="POST"><Number>${r.toE164}</Number></Dial></Response>`
  );
}

// Twilio posts call-status here (via the <Dial> action). We record the outcome
// and release one-call-at-a-time presence on a terminal status.
async function hTwilioStatus(request, env) {
  const { valid, params } = await readTwilioForm(request, env);
  if (!valid) return xmlResponse("<Response/>", 403);
  await finalizeCallByStatus(env, params);
  return xmlResponse("<Response/>");
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

// connect-src also allows Twilio's Voice SDK signaling (wss) and event gateway
// (https) so the browser softphone can reach the carrier. Media (DTLS/SRTP) is
// not governed by CSP. The SDK itself is self-hosted, so script-src stays 'self'.
const CSP =
  "default-src 'self'; connect-src 'self' https://*.twilio.com wss://*.twilio.com; " +
  "media-src 'self' blob:; img-src 'self' data:; style-src 'self'; script-src 'self'; " +
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
