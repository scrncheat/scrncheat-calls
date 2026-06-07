// Signaling registry + 1:1 relay for in-app WebRTC calls.
//
// A single global Durable Object holds the live WebSocket connections, using
// WebSocket Hibernation so it costs nothing while idle. Each socket is tagged
// with its authenticated handle (the user's email) stored via
// serializeAttachment — the relay NEVER trusts a client-supplied sender id, and
// targets are resolved from the DO's own connection set.
//
// Concurrency: a user may be in at most ONE call at a time. "Busy" state lives
// in the socket attachment (survives hibernation); a user counts as busy if any
// of their sockets is in a call. A call to/from a busy user is rejected.

const MAX_MESSAGE_BYTES = 64 * 1024;
const MSG_WINDOW_MS = 10_000;
const MSG_MAX_PER_WINDOW = 120;

export class SignalingRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    const url = new URL(request.url);
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
        // One call at a time: reject if either party is already busy.
        if (this.isUserBusy(senderId) || this.isUserBusy(target)) {
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
        if (this.isUserBusy(senderId)) return; // already in a call elsewhere
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
    // If this socket was in a call, end it for the peer and free them.
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

  // --- concurrency helpers (a user is busy if any of their sockets is) ---

  isUserBusy(handle) {
    for (const s of this.ctx.getWebSockets(handle)) {
      const a = s.deserializeAttachment();
      if (a && a.busyWith) return true;
    }
    return false;
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
