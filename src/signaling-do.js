// Signaling registry + 1:1 relay for in-app WebRTC calls, and the in-app side
// of the app's "one call at a time" rule.
//
// A single global Durable Object holds the live WebSocket connections (using
// WebSocket Hibernation so it costs nothing while idle). Each socket is tagged
// with its authenticated handle (the user's email) stored via
// serializeAttachment — the relay NEVER trusts a client-supplied sender id.
//
// Presence: in-app "busy" lives in the socket attachment. PSTN presence is
// owned durably by the Worker's dial gate in D1; the Worker also mirrors it into
// this DO's in-memory set via the /control API so an in-app call can be blocked
// while the peer is on a phone call. The DO itself performs NO storage I/O.

const MAX_MESSAGE_BYTES = 64 * 1024;
const MSG_WINDOW_MS = 10_000;
const MSG_MAX_PER_WINDOW = 120;

export class SignalingRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    // Best-effort mirror of handles currently on a PSTN call (authoritative copy
    // is in D1). Used only to block in-app calls to someone on the phone.
    this.pstnBusy = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/control/")) return this.handleControl(request, url);

    const handle = (url.searchParams.get("handle") || "").toLowerCase();
    if (!handle) return new Response("missing handle", { status: 400 });
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const { 0: client, 1: server } = new WebSocketPair();
    this.ctx.acceptWebSocket(server, [handle]);
    server.serializeAttachment({ handle, windowStart: Date.now(), count: 0, busyWith: null });
    server.send(JSON.stringify({ type: "registered", handle }));

    return new Response(null, { status: 101, webSocket: client });
  }

  // Internal presence API, called by the Worker's dial gate (clients can't
  // address the DO directly). No storage I/O here — in-memory only.
  async handleControl(request, url) {
    let body = {};
    try {
      body = await request.json();
    } catch {
      /* empty */
    }
    const handle = String(body.handle || "").toLowerCase();
    const reply = (obj, status = 200) =>
      new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json" } });
    if (!handle) return reply({ error: "missing_handle" }, 400);

    switch (url.pathname) {
      case "/control/busy":
        // In-app busy only; the Worker checks D1 for PSTN.
        return reply({ busy: this.isInAppBusy(handle) });
      case "/control/pstn-begin":
        this.pstnBusy.add(handle);
        return reply({ ok: true });
      case "/control/pstn-end":
        this.pstnBusy.delete(handle);
        return reply({ ok: true });
      default:
        return reply({ error: "not_found" }, 404);
    }
  }

  async webSocketMessage(ws, raw) {
    const size = typeof raw === "string" ? raw.length : raw.byteLength;
    if (size > MAX_MESSAGE_BYTES) {
      ws.close(1009, "message too large");
      return;
    }

    // Per-socket flood control, tracked in the (hibernation-safe) attachment.
    const att = ws.deserializeAttachment() || {};
    const handle = att.handle;
    const now = Date.now();
    let windowStart = att.windowStart || now;
    let count = att.count || 0;
    if (now - windowStart > MSG_WINDOW_MS) {
      windowStart = now;
      count = 0;
    }
    count += 1;
    ws.serializeAttachment({ ...att, windowStart, count });
    if (count > MSG_MAX_PER_WINDOW) {
      ws.close(1008, "rate limit");
      return;
    }
    if (!handle) return;

    let msg;
    try {
      msg = JSON.parse(typeof raw === "string" ? raw : new TextDecoder().decode(raw));
    } catch {
      return;
    }
    if (!msg || typeof msg.type !== "string") return;

    const senderId = handle; // authoritative; client-supplied sender is ignored
    const target = typeof msg.target === "string" ? msg.target.toLowerCase() : null;
    if (!target || target === senderId) return;

    switch (msg.type) {
      case "call": {
        // One call at a time (covers the peer being on a PSTN call too).
        if (this.isBusy(senderId) || this.isBusy(target)) {
          ws.send(JSON.stringify({ type: "call-rejected", senderId: target, reason: "busy" }));
          return;
        }
        const delivered = this.sendTo(target, { type: "incoming-call", senderId });
        if (delivered === 0) {
          ws.send(JSON.stringify({ type: "call-rejected", senderId: target, reason: "offline" }));
          return;
        }
        this.setBusy(ws, target); // caller is now committed to this call
        return;
      }

      case "answer-call": {
        if (this.isBusy(senderId)) return; // already in a call elsewhere
        this.setBusy(ws, target);
        this.sendTo(target, { type: "answer-call", senderId });
        return;
      }

      case "reject-call": {
        this.clearUserBusy(target); // the caller was holding a "calling" state
        this.sendTo(target, { type: "call-rejected", senderId, reason: "rejected" });
        return;
      }

      case "hangup": {
        this.clearUserBusy(senderId);
        this.clearUserBusy(target);
        this.sendTo(target, { type: "call-ended", senderId });
        return;
      }

      case "offer":
      case "answer": {
        if (!msg.sdp || typeof msg.sdp !== "object") return;
        this.sendTo(target, { type: msg.type, senderId, sdp: msg.sdp });
        return;
      }

      case "ice": {
        if (!msg.candidate) return;
        this.sendTo(target, { type: "ice", senderId, candidate: msg.candidate });
        return;
      }

      default:
        return;
    }
  }

  webSocketClose(ws) {
    const att = ws.deserializeAttachment() || {};
    if (att.busyWith) {
      this.sendTo(att.busyWith, { type: "call-ended", senderId: att.handle });
      this.clearUserBusy(att.busyWith);
    }
    try {
      ws.close();
    } catch {
      // already closed
    }
  }

  webSocketError() {
    // Socket is torn down automatically.
  }

  // --- presence helpers ---

  isInAppBusy(handle) {
    for (const s of this.ctx.getWebSockets(handle)) {
      const a = s.deserializeAttachment();
      if (a && a.busyWith) return true;
    }
    return false;
  }

  isBusy(handle) {
    return this.isInAppBusy(handle) || this.pstnBusy.has(handle);
  }

  setBusy(ws, peer) {
    const a = ws.deserializeAttachment() || {};
    a.busyWith = peer;
    ws.serializeAttachment(a);
  }

  clearUserBusy(handle) {
    for (const s of this.ctx.getWebSockets(handle)) {
      const a = s.deserializeAttachment() || {};
      if (a.busyWith) {
        a.busyWith = null;
        s.serializeAttachment(a);
      }
    }
  }

  /** Send `payload` to every live socket for `targetHandle`; returns the count. */
  sendTo(targetHandle, payload) {
    const data = JSON.stringify(payload);
    let n = 0;
    for (const s of this.ctx.getWebSockets(targetHandle)) {
      try {
        s.send(data);
        n += 1;
      } catch {
        // socket going away; ignore
      }
    }
    return n;
  }
}
