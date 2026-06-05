// Signaling registry + 1:1 relay for in-app WebRTC calls.
//
// A single global Durable Object instance holds the live WebSocket connections,
// using WebSocket Hibernation so it costs nothing while idle. Each socket is
// tagged with its authenticated handle (the user's email) and the handle is
// stored server-side via serializeAttachment — the relay NEVER trusts a
// client-supplied sender id. Targets are resolved from the DO's own connection
// set (ctx.getWebSockets(tag)), so a client cannot impersonate or address
// arbitrary internal state.

const MAX_MESSAGE_BYTES = 64 * 1024;
const MSG_WINDOW_MS = 10_000;
const MSG_MAX_PER_WINDOW = 120;

function outgoingType(t) {
  switch (t) {
    case "call":
      return "incoming-call";
    case "reject-call":
      return "call-rejected";
    case "hangup":
      return "call-ended";
    default:
      return t; // answer-call, offer, answer, ice
  }
}

const PASSTHROUGH = new Set(["answer-call", "reject-call", "offer", "answer", "ice", "hangup"]);

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
    // Tag the socket by handle so getWebSockets(handle) routes to this user.
    this.ctx.acceptWebSocket(server, [handle]);
    server.serializeAttachment({ handle, windowStart: Date.now(), count: 0 });
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
    ws.serializeAttachment({ handle, windowStart, count });
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

    if (msg.type === "call") {
      const delivered = this.sendTo(target, { type: "incoming-call", senderId });
      if (delivered === 0) {
        this.sendTo(senderId, { type: "call-rejected", senderId: target, reason: "offline" });
      }
      return;
    }

    if (!PASSTHROUGH.has(msg.type)) return;

    const payload = { type: outgoingType(msg.type), senderId };
    if (msg.type === "offer" || msg.type === "answer") {
      if (!msg.sdp || typeof msg.sdp !== "object") return;
      payload.sdp = msg.sdp;
    }
    if (msg.type === "ice") {
      if (!msg.candidate) return;
      payload.candidate = msg.candidate;
    }
    this.sendTo(target, payload);
  }

  webSocketClose(ws) {
    // No bookkeeping required: getWebSockets() stops returning a closed socket.
    try {
      ws.close();
    } catch {
      // already closed
    }
  }

  webSocketError() {
    // Socket is torn down automatically.
  }

  /** Send `payload` to every live socket for `targetHandle`; returns the count. */
  sendTo(targetHandle, payload) {
    const sockets = this.ctx.getWebSockets(targetHandle);
    const data = JSON.stringify(payload);
    let n = 0;
    for (const s of sockets) {
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
