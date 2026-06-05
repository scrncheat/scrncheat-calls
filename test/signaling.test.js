import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { getOrCreateUser, createSession } from "../src/lib/auth.js";

const ORIGIN = "https://calls.example";

async function sessionFor(email) {
  const u = await getOrCreateUser(env, email);
  const s = await createSession(env, u.id, "1.1.1.1", "ua");
  return s.token;
}

function openWs(token, extraHeaders = {}) {
  return SELF.fetch(`${ORIGIN}/ws`, {
    headers: { Upgrade: "websocket", ...(token ? { Cookie: `pfc_session=${token}` } : {}), ...extraHeaders },
  });
}

function nextJson(ws) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("ws message timeout")), 5000);
    ws.addEventListener(
      "message",
      (e) => {
        clearTimeout(timer);
        resolve(JSON.parse(e.data));
      },
      { once: true }
    );
  });
}

describe("signaling — access control", () => {
  it("rejects a /ws upgrade without a session", async () => {
    const res = await openWs(null);
    expect(res.status).toBe(401);
  });

  it("rejects a /ws upgrade from a foreign origin", async () => {
    const token = await sessionFor("origin@example.com");
    const res = await openWs(token, { Origin: "https://evil.example" });
    expect(res.status).toBe(403);
  });

  it("upgrades to a websocket with a valid session", async () => {
    const token = await sessionFor("ok@example.com");
    const res = await openWs(token);
    expect(res.status).toBe(101);
    expect(res.webSocket).toBeTruthy();
    res.webSocket.accept();
    res.webSocket.close();
  });
});

describe("signaling — abuse resistance", () => {
  it("relays calls with the SERVER-derived sender id, ignoring client spoofing", async () => {
    const tokenA = await sessionFor("alice@example.com");
    const tokenB = await sessionFor("bob@example.com");

    const rb = await openWs(tokenB);
    const wsB = rb.webSocket;
    wsB.accept();
    expect((await nextJson(wsB)).type).toBe("registered");

    const ra = await openWs(tokenA);
    const wsA = ra.webSocket;
    wsA.accept();
    expect((await nextJson(wsA)).type).toBe("registered");

    const incoming = nextJson(wsB);
    // Alice calls Bob but lies about who she is.
    wsA.send(JSON.stringify({ type: "call", target: "bob@example.com", senderId: "admin@evil.example" }));
    const msg = await incoming;

    expect(msg.type).toBe("incoming-call");
    expect(msg.senderId).toBe("alice@example.com"); // forged sender ignored

    wsA.close();
    wsB.close();
  });

  it("tells the caller when the target is offline", async () => {
    const token = await sessionFor("lonely@example.com");
    const r = await openWs(token);
    const ws = r.webSocket;
    ws.accept();
    expect((await nextJson(ws)).type).toBe("registered");

    const reply = nextJson(ws);
    ws.send(JSON.stringify({ type: "call", target: "nobody-online@example.com" }));
    const msg = await reply;
    expect(msg.type).toBe("call-rejected");
    expect(msg.reason).toBe("offline");
    ws.close();
  });

  it("closes the socket on an oversized frame", async () => {
    const token = await sessionFor("big@example.com");
    const r = await openWs(token);
    const ws = r.webSocket;
    ws.accept();
    expect((await nextJson(ws)).type).toBe("registered");

    const closed = new Promise((resolve) =>
      ws.addEventListener("close", (e) => resolve(e), { once: true })
    );
    ws.send("x".repeat(65 * 1024)); // > 64KB cap
    const ev = await closed;
    expect(ev.code).toBe(1009);
  });
});
