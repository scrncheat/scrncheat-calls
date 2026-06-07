// JSON response helpers with conservative security headers.

const BASE_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "same-origin",
};

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...BASE_HEADERS, ...extraHeaders },
  });
}

export function ok(data = {}, extraHeaders = {}) {
  return json({ ok: true, ...data }, 200, extraHeaders);
}

export function badRequest(message = "bad_request") {
  return json({ ok: false, error: message }, 400);
}

export function unauthorized(message = "unauthorized") {
  return json({ ok: false, error: message }, 401);
}

export function forbidden(message = "forbidden") {
  return json({ ok: false, error: message }, 403);
}

export function tooManyRequests(message = "rate_limited") {
  return json({ ok: false, error: message }, 429);
}

export function notFound(message = "not_found") {
  return json({ ok: false, error: message }, 404);
}

export function serverError(message = "server_error") {
  return json({ ok: false, error: message }, 500);
}
