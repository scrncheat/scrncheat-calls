import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { requestLoginCode, verifyLoginCode, getSessionUser } from "../src/lib/auth.js";

const ORIGIN = "https://calls.example";

const jsonPost = (path, body, headers = {}) =>
  SELF.fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

function parseSetCookies(res) {
  const list = res.headers.getSetCookie ? res.headers.getSetCookie() : [res.headers.get("Set-Cookie")];
  const out = {};
  for (const c of list) {
    if (!c) continue;
    const [pair] = c.split(";");
    const idx = pair.indexOf("=");
    out[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
  }
  return out;
}

describe("passwordless auth — functional", () => {
  it("issues a code and verifies it, creating a session", async () => {
    const r = await requestLoginCode(env, "a@example.com", "1.1.1.1");
    expect(r.sent).toBe(true);
    expect(r.devCode).toMatch(/^\d{6}$/);

    const v = await verifyLoginCode(env, "a@example.com", r.devCode, "1.1.1.1", "ua");
    expect(v.ok).toBe(true);

    const user = await getSessionUser(env, v.session.token);
    expect(user).not.toBeNull();
    expect(user.email).toBe("a@example.com");
  });

  it("stores only an HMAC of the code, never the plaintext", async () => {
    const r = await requestLoginCode(env, "hash@example.com", "1.1.1.1");
    const row = await env.DB.prepare("SELECT code_hash FROM login_codes WHERE email = ?")
      .bind("hash@example.com")
      .first();
    expect(row.code_hash).not.toContain(r.devCode);
    expect(row.code_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("issues a session + CSRF cookie over HTTP on verify", async () => {
    const r = await requestLoginCode(env, "http@example.com", "1.1.1.1");
    const res = await jsonPost("/api/auth/verify-code", { email: "http@example.com", code: r.devCode });
    expect(res.status).toBe(200);
    const cookies = parseSetCookies(res);
    expect(cookies.pfc_session).toBeTruthy();
    expect(cookies.pfc_csrf).toBeTruthy();
  });
});

describe("passwordless auth — abuse resistance", () => {
  it("rejects an expired code (deterministic clock)", async () => {
    const t0 = 1_000_000_000;
    const r = await requestLoginCode(env, "exp@example.com", "1.1.1.1", t0);
    const later = t0 + 11 * 60 * 1000; // past the 10-minute TTL
    const v = await verifyLoginCode(env, "exp@example.com", r.devCode, "1.1.1.1", "ua", later);
    expect(v.ok).toBe(false);
  });

  it("is single-use: a verified code cannot be replayed", async () => {
    const r = await requestLoginCode(env, "replay@example.com", "1.1.1.1");
    expect((await verifyLoginCode(env, "replay@example.com", r.devCode, "1.1.1.1", "ua")).ok).toBe(true);
    expect((await verifyLoginCode(env, "replay@example.com", r.devCode, "1.1.1.1", "ua")).ok).toBe(false);
  });

  it("locks a code after 5 wrong attempts, even if the right code follows", async () => {
    const r = await requestLoginCode(env, "bf@example.com", "9.9.9.9");
    const wrong = r.devCode === "000000" ? "111111" : "000000";
    for (let i = 0; i < 5; i++) {
      expect((await verifyLoginCode(env, "bf@example.com", wrong, "9.9.9.9", "ua")).ok).toBe(false);
    }
    // Correct code now rejected because the attempt budget is spent.
    expect((await verifyLoginCode(env, "bf@example.com", r.devCode, "9.9.9.9", "ua")).ok).toBe(false);
  });

  it("rate-limits code issuance per email (6th request blocked)", async () => {
    let last;
    for (let i = 0; i < 6; i++) {
      last = await requestLoginCode(env, "rl@example.com", "4.4.4.4");
    }
    expect(last.sent).toBe(false);
    expect(last.reason).toBe("rate_limited");
  });

  it("does not reveal whether an email exists (neutral request-code response)", async () => {
    const r1 = await jsonPost("/api/auth/request-code", { email: "exists@example.com" });
    const r2 = await jsonPost("/api/auth/request-code", { email: "nobody-here@example.com" });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    // The user-facing message is identical regardless of whether the email
    // exists. (The dev-only devCode field is never present in production.)
    const [j1, j2] = [await r1.json(), await r2.json()];
    expect(j1.message).toBe(j2.message);
  });

  it("rejects a forged/garbage session cookie", async () => {
    const res = await SELF.fetch(`${ORIGIN}/api/auth/me`, {
      headers: { Cookie: "pfc_session=not-a-real-token" },
    });
    expect(res.status).toBe(401);
  });

  it("requires a CSRF token for state-changing logout", async () => {
    const r = await requestLoginCode(env, "csrf@example.com", "1.1.1.1");
    const login = await jsonPost("/api/auth/verify-code", { email: "csrf@example.com", code: r.devCode });
    const cookies = parseSetCookies(login);

    // Without the CSRF header -> 403.
    const noToken = await SELF.fetch(`${ORIGIN}/api/auth/logout`, {
      method: "POST",
      headers: { Cookie: `pfc_session=${cookies.pfc_session}` },
    });
    expect(noToken.status).toBe(403);

    // With matching cookie + header -> 200.
    const withToken = await SELF.fetch(`${ORIGIN}/api/auth/logout`, {
      method: "POST",
      headers: {
        Cookie: `pfc_session=${cookies.pfc_session}; pfc_csrf=${cookies.pfc_csrf}`,
        "X-CSRF-Token": cookies.pfc_csrf,
      },
    });
    expect(withToken.status).toBe(200);
  });

  it("blocks a cross-origin state-changing request (Origin mismatch)", async () => {
    const res = await SELF.fetch(`${ORIGIN}/api/auth/request-code`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: "https://evil.example" },
      body: JSON.stringify({ email: "x@example.com" }),
    });
    expect(res.status).toBe(403);
  });
});
