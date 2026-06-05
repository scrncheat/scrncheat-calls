// Pierre Fouquet Calls — SPA: passwordless login + in-app WebRTC calling.

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function show(el) { el.classList.remove("hidden"); }
function hide(el) { el.classList.add("hidden"); }

function getCookie(name) {
  for (const part of document.cookie.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return decodeURIComponent(v.join("="));
  }
  return "";
}

async function api(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCookie("pfc_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = {};
  try { data = await res.json(); } catch { /* non-JSON */ }
  return { status: res.status, ok: res.ok, data };
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

let myEmail = null;

async function bootstrap() {
  const me = await api("/api/auth/me");
  if (me.ok && me.data.user) {
    myEmail = me.data.user.email;
    enterApp();
  } else {
    showLogin();
  }
}

function showLogin() {
  hide($("appView"));
  hide($("account"));
  show($("loginView"));
  show($("emailStep"));
  hide($("codeStep"));
  $("loginStatus").textContent = "";
}

$("sendCodeButton").addEventListener("click", async () => {
  const email = $("email").value.trim();
  if (!email) { $("loginStatus").textContent = "Enter your email."; return; }
  $("sendCodeButton").disabled = true;
  const res = await api("/api/auth/request-code", { method: "POST", body: { email } });
  $("sendCodeButton").disabled = false;
  if (res.status === 429) {
    $("loginStatus").textContent = "Too many requests — please wait a bit and try again.";
    return;
  }
  $("codeEmailLabel").textContent = email;
  hide($("emailStep"));
  show($("codeStep"));
  $("loginStatus").textContent = "Check your email for the code.";
  $("code").focus();
});

$("backButton").addEventListener("click", () => {
  show($("emailStep"));
  hide($("codeStep"));
  $("loginStatus").textContent = "";
});

$("verifyButton").addEventListener("click", async () => {
  const email = $("codeEmailLabel").textContent;
  const code = $("code").value.trim();
  if (!/^\d{6}$/.test(code)) { $("loginStatus").textContent = "Enter the 6-digit code."; return; }
  $("verifyButton").disabled = true;
  const res = await api("/api/auth/verify-code", { method: "POST", body: { email, code } });
  $("verifyButton").disabled = false;
  if (!res.ok) {
    $("loginStatus").textContent =
      res.status === 429 ? "Too many attempts — wait and retry." : "Invalid or expired code.";
    return;
  }
  myEmail = res.data.user.email;
  enterApp();
});

$("logoutButton").addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" });
  teardownCall();
  if (ws) { try { ws.close(); } catch {} ws = null; }
  myEmail = null;
  showLogin();
});

function enterApp() {
  hide($("loginView"));
  show($("appView"));
  show($("account"));
  $("accountEmail").textContent = myEmail;
  connectSignaling();
}

// ---------------------------------------------------------------------------
// Signaling + WebRTC
// ---------------------------------------------------------------------------

let ws = null;
let pc = null;
let localStream = null;
let currentPeer = null;
let role = null; // "caller" | "callee"
let pendingCandidates = [];
let iceServers = [{ urls: ["stun:stun.cloudflare.com:3478"] }];

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(obj));
}

function setConn(text) { $("connStatus").textContent = text; }
function setCall(text) { $("callStatus").textContent = text; }

async function connectSignaling() {
  // Refresh ICE servers (short-lived TURN creds minted server-side).
  try {
    const t = await api("/api/turn");
    if (t.ok && Array.isArray(t.data.iceServers)) iceServers = t.data.iceServers;
  } catch { /* keep STUN default */ }

  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    setConn("online");
    $("callButton").disabled = false;
  };
  ws.onclose = () => {
    setConn("disconnected");
    $("callButton").disabled = true;
    // Reconnect only while still signed in.
    if (myEmail) setTimeout(connectSignaling, 3000);
  };
  ws.onerror = () => setConn("error");
  ws.onmessage = (event) => handleSignal(JSON.parse(event.data));
}

async function handleSignal(msg) {
  switch (msg.type) {
    case "registered":
      setConn("online");
      break;

    case "incoming-call":
      // Server-derived caller id; show accept/reject.
      $("incomingFrom").textContent = msg.senderId;
      currentPeer = msg.senderId;
      role = "callee";
      show($("incomingCall"));
      break;

    case "answer-call": {
      // Callee accepted; caller now creates the offer.
      if (role !== "caller") return;
      setCall("Connecting…");
      await createPeer();
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      send({ type: "offer", target: currentPeer, sdp: offer });
      break;
    }

    case "offer": {
      if (role !== "callee") return;
      await createPeer();
      await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
      await drainCandidates();
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      send({ type: "answer", target: currentPeer, sdp: answer });
      setCall("Connecting…");
      break;
    }

    case "answer":
      if (pc) {
        await pc.setRemoteDescription(new RTCSessionDescription(msg.sdp));
        await drainCandidates();
      }
      break;

    case "ice":
      if (pc && pc.remoteDescription && pc.remoteDescription.type) {
        try { await pc.addIceCandidate(msg.candidate); } catch (e) { console.warn(e); }
      } else {
        pendingCandidates.push(msg.candidate);
      }
      break;

    case "call-rejected":
      setCall(msg.reason === "offline" ? "User is offline." : "Call rejected.");
      teardownCall();
      break;

    case "call-ended":
      setCall("Call ended by the other party.");
      teardownCall();
      break;
  }
}

async function drainCandidates() {
  for (const c of pendingCandidates) {
    try { await pc.addIceCandidate(c); } catch (e) { console.warn(e); }
  }
  pendingCandidates = [];
}

async function createPeer() {
  if (pc) return;
  pc = new RTCPeerConnection({ iceServers });

  pc.onicecandidate = (e) => {
    if (e.candidate && currentPeer) send({ type: "ice", target: currentPeer, candidate: e.candidate });
  };
  pc.ontrack = (e) => {
    if (e.streams && e.streams[0]) $("remoteAudio").srcObject = e.streams[0];
  };
  pc.onconnectionstatechange = () => {
    if (pc && pc.connectionState === "connected") {
      setCall("Connected.");
      $("hangupButton").disabled = false;
    } else if (pc && (pc.connectionState === "failed" || pc.connectionState === "disconnected")) {
      setCall("Connection lost.");
    }
  };

  localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  for (const track of localStream.getTracks()) pc.addTrack(track, localStream);
}

$("callButton").addEventListener("click", async () => {
  const target = $("callTarget").value.trim().toLowerCase();
  if (!target) { setCall("Enter who to call."); return; }
  if (target === myEmail) { setCall("You can't call yourself."); return; }
  currentPeer = target;
  role = "caller";
  $("callButton").disabled = true;
  setCall(`Calling ${target}…`);
  send({ type: "call", target });
});

$("acceptButton").addEventListener("click", async () => {
  hide($("incomingCall"));
  $("callButton").disabled = true;
  setCall(`In call with ${currentPeer}…`);
  // Prepare to receive the offer, then signal acceptance.
  await createPeer();
  send({ type: "answer-call", target: currentPeer });
});

$("rejectButton").addEventListener("click", () => {
  hide($("incomingCall"));
  send({ type: "reject-call", target: currentPeer });
  currentPeer = null;
  role = null;
});

$("hangupButton").addEventListener("click", () => {
  if (currentPeer) send({ type: "hangup", target: currentPeer });
  setCall("Call ended.");
  teardownCall();
});

function teardownCall() {
  if (pc) { try { pc.close(); } catch {} pc = null; }
  if (localStream) { localStream.getTracks().forEach((t) => t.stop()); localStream = null; }
  pendingCandidates = [];
  currentPeer = null;
  role = null;
  $("remoteAudio").srcObject = null;
  $("hangupButton").disabled = true;
  $("callButton").disabled = !(ws && ws.readyState === WebSocket.OPEN);
  hide($("incomingCall"));
}

// ---------------------------------------------------------------------------
bootstrap();
