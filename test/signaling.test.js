import { env, SELF } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { getOrCreateUser, createSession } from "../src/lib/auth.js";
import { registerNumber, sendNumberVerification, confirmNumber } from "../src/lib/numbers.js";
import { authorizeAndDial } from "../src/lib/dial.js";

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

describe("signaling — one call at a time", () => {
  async function connect(email) {
    const ws = (await openWs(await sessionFor(email))).webSocket;
    ws.accept();
    await nextJson(ws); // "registered"
    return ws;
  }

  async function establishCall(a, aEmail, b, bEmail) {
    const incoming = nextJson(b);
    a.send(JSON.stringify({ type: "call", target: bEmail }));
    await incoming;
    const answered = nextJson(a);
    b.send(JSON.stringify({ type: "answer-call", target: aEmail }));
    await answered;
  }

  it("rejects calling a user who is already in a call", async () => {
    const a = await connect("busy-a@example.com");
    const b = await connect("busy-b@example.com");
    const c = await connect("busy-c@example.com");
    await establishCall(a, "busy-a@example.com", b, "busy-b@example.com");

    const reply = nextJson(c);
    c.send(JSON.stringify({ type: "call", target: "busy-b@example.com" }));
    const msg = await reply;
    expect(msg.type).toBe("call-rejected");
    expect(msg.reason).toBe("busy");

    a.close();
    b.close();
    c.close();
  });

  it("rejects starting a second call while already calling", async () => {
    const a = await connect("sec-a@example.com");
    const b = await connect("sec-b@example.com");

    const incoming = nextJson(b);
    a.send(JSON.stringify({ type: "call", target: "sec-b@example.com" }));
    await incoming; // A is now busy

    const reply = nextJson(a);
    a.send(JSON.stringify({ type: "call", target: "sec-c@example.com" }));
    const msg = await reply;
    expect(msg.type).toBe("call-rejected");
    expect(msg.reason).toBe("busy");

    a.close();
    b.close();
  });

  it("frees the user after hangup so they can call again", async () => {
    const a = await connect("free-a@example.com");
    const b = await connect("free-b@example.com");
    await establishCall(a, "free-a@example.com", b, "free-b@example.com");

    const ended = nextJson(b);
    a.send(JSON.stringify({ type: "hangup", target: "free-b@example.com" }));
    await ended; // call-ended

    const incoming = nextJson(b);
    a.send(JSON.stringify({ type: "call", target: "free-b@example.com" }));
    const msg = await incoming;
    expect(msg.type).toBe("incoming-call");

    a.close();
    b.close();
  });
});

describe("signaling — in-app and PSTN are linked", () => {
  async function connectWs(email) {
    const ws = (await openWs(await sessionFor(email))).webSocket;
    ws.accept();
    await nextJson(ws); // "registered"
    return ws;
  }

  async function verifyNum(userId, e164) {
    const reg = await registerNumber(env, userId, e164);
    const send = await sendNumberVerification(env, userId, reg.id);
    await confirmNumber(env, userId, reg.id, send.devCode);
    return reg.id;
  }

  const presence = () => env.SIGNALING.get(env.SIGNALING.idFromName("global"));

  it("a PSTN call blocks an incoming in-app call", async () => {
    const callee = "linkpstn-callee@example.com";
    const caller = await connectWs("linkpstn-caller@example.com");
    // Reserve a PSTN call for the callee via the presence service.
    await presence().fetch("https://signaling/control/pstn-begin", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ handle: callee }),
    });

    const reply = nextJson(caller);
    caller.send(JSON.stringify({ type: "call", target: callee }));
    const msg = await reply;
    expect(msg.type).toBe("call-rejected");
    expect(msg.reason).toBe("busy");
    caller.close();
  });

  it("an in-app call blocks a PSTN dial for the same user", async () => {
    const aEmail = "linkapp-a@example.com";
    const bEmail = "linkapp-b@example.com";
    const a = await connectWs(aEmail);
    const b = await connectWs(bEmail);

    // Establish an in-app call A <-> B.
    const incoming = nextJson(b);
    a.send(JSON.stringify({ type: "call", target: bEmail }));
    await incoming;
    const answered = nextJson(a);
    b.send(JSON.stringify({ type: "answer-call", target: aEmail }));
    await answered;

    // A now tries to place a phone call -> blocked by the same presence.
    const u = await getOrCreateUser(env, aEmail);
    const numId = await verifyNum(u.id, "+447400123430");
    const r = await authorizeAndDial(env, u, "+33123456789", numId, { enabled: true });
    expect(r).toMatchObject({ ok: false, reason: "already_on_call" });

    a.close();
    b.close();
  });
});
