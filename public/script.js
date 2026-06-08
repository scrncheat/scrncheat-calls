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
  if (voiceCall) { try { voiceCall.disconnect(); } catch {} voiceCall = null; }
  if (voiceDevice) { try { voiceDevice.destroy(); } catch {} voiceDevice = null; }
  if (ws) { try { ws.close(); } catch {} ws = null; }
  myEmail = null;
  showLogin();
});

async function enterApp() {
  hide($("loginView"));
  show($("appView"));
  show($("account"));
  $("accountEmail").textContent = myEmail;

  const me = await api("/api/auth/me");
  const enabled = me.ok && me.data.telephonyEnabled;
  $("telephonyStatus").textContent = enabled
    ? "carrier connected"
    : "off — external calls are disabled until a carrier is connected";

  connectSignaling();
  loadNumbers();
  if (enabled) setupVoiceDevice();
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

    case "call-rejected": {
      const reason =
        msg.reason === "offline"
          ? "User is offline."
          : msg.reason === "busy"
          ? "User is busy on another call."
          : "Call rejected.";
      setCall(reason);
      teardownCall();
      break;
    }

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
// My numbers + external dialing
// ---------------------------------------------------------------------------

function setNumbersStatus(text) { $("numbersStatus").textContent = text; }

async function loadNumbers() {
  const res = await api("/api/numbers");
  const numbers = res.ok ? res.data.numbers : [];
  renderNumbers(numbers);
  populateCallerIds(numbers);
}

function renderNumbers(numbers) {
  const list = $("numbersList");
  list.innerHTML = "";
  if (!numbers.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No numbers yet.";
    list.appendChild(li);
    return;
  }
  for (const n of numbers) {
    const li = document.createElement("li");
    li.className = "number-item";

    const label = document.createElement("span");
    label.textContent = `${n.e164} · ${n.line_type || "?"} · ${n.status}`;
    li.appendChild(label);

    const actions = document.createElement("span");
    actions.className = "number-actions";
    if (n.status === "verified") {
      const badge = document.createElement("span");
      badge.className = "badge ok";
      badge.textContent = "verified";
      actions.appendChild(badge);
    } else {
      const sendBtn = document.createElement("button");
      sendBtn.textContent = "Send code";
      sendBtn.dataset.action = "send";
      sendBtn.dataset.id = n.id;
      actions.appendChild(sendBtn);

      const codeInput = document.createElement("input");
      codeInput.placeholder = "code";
      codeInput.maxLength = 6;
      codeInput.className = "code-input";
      codeInput.dataset.code = n.id;
      actions.appendChild(codeInput);

      const confirmBtn = document.createElement("button");
      confirmBtn.textContent = "Confirm";
      confirmBtn.dataset.action = "confirm";
      confirmBtn.dataset.id = n.id;
      actions.appendChild(confirmBtn);
    }
    const rm = document.createElement("button");
    rm.textContent = "Remove";
    rm.className = "link";
    rm.dataset.action = "remove";
    rm.dataset.id = n.id;
    actions.appendChild(rm);

    li.appendChild(actions);
    list.appendChild(li);
  }
}

function populateCallerIds(numbers) {
  const sel = $("callerId");
  sel.innerHTML = "";
  const verified = numbers.filter((n) => n.status === "verified");
  if (!verified.length) {
    const opt = document.createElement("option");
    opt.value = "";
    opt.textContent = "— verify a number first —";
    sel.appendChild(opt);
    return;
  }
  for (const n of verified) {
    const opt = document.createElement("option");
    opt.value = n.id;
    opt.textContent = n.e164;
    sel.appendChild(opt);
  }
}

$("addNumberButton").addEventListener("click", async () => {
  const number = $("newNumber").value.trim();
  if (!number) return;
  const res = await api("/api/numbers", { method: "POST", body: { number } });
  if (res.ok) {
    $("newNumber").value = "";
    setNumbersStatus("");
    loadNumbers();
  } else {
    setNumbersStatus(`Could not add number: ${res.data.error || res.status}`);
  }
});

$("numbersList").addEventListener("click", async (e) => {
  const btn = e.target.closest("button");
  if (!btn) return;
  const { action, id } = btn.dataset;
  if (action === "send") {
    const res = await api(`/api/numbers/${id}/verify`, { method: "POST" });
    if (!res.ok) {
      // Carrier failures carry Twilio's own message + code so the reason is visible.
      const detail = res.data.detail
        ? `${res.data.detail}${res.data.providerCode ? ` (Twilio ${res.data.providerCode})` : ""}`
        : res.data.error || res.status;
      setNumbersStatus(`Error: ${detail}`);
    } else if (res.data.displayCode) {
      // Carrier-driven validation (Twilio): the carrier calls the number and the
      // user keys in this code on their handset, then clicks Confirm.
      setNumbersStatus(
        `The carrier is calling this number — enter ${res.data.displayCode} on your phone, then click Confirm.`
      );
    } else {
      setNumbersStatus("Code sent (delivered by carrier). Enter it and click Confirm.");
    }
  } else if (action === "confirm") {
    const input = document.querySelector(`input[data-code="${id}"]`);
    const code = input ? input.value.trim() : "";
    const res = await api(`/api/numbers/${id}/confirm`, { method: "POST", body: { code } });
    if (res.ok) { setNumbersStatus("Number verified."); loadNumbers(); }
    else setNumbersStatus(`Error: ${res.data.error || res.status}`);
  } else if (action === "remove") {
    await api(`/api/numbers/${id}`, { method: "DELETE" });
    loadNumbers();
  }
});

// --- Browser softphone (Twilio Voice SDK) ---------------------------------

let voiceDevice = null;
let voiceCall = null;

async function refreshVoiceToken() {
  const t = await api("/api/voice/token");
  return t.ok && t.data.token ? t.data.token : null;
}

async function setupVoiceDevice() {
  if (voiceDevice || typeof Twilio === "undefined" || !Twilio.Device) return;
  const token = await refreshVoiceToken();
  if (!token) { $("telephonyStatus").textContent = "carrier token unavailable"; return; }

  voiceDevice = new Twilio.Device(token, { codecPreferences: ["opus", "pcmu"], logLevel: "error" });
  voiceDevice.on("error", (e) => {
    $("dialStatus").textContent = `Carrier error: ${e.message || e.code || e}`;
  });
  voiceDevice.on("tokenWillExpire", async () => {
    const fresh = await refreshVoiceToken();
    if (fresh) voiceDevice.updateToken(fresh);
  });
}

function wireVoiceCall(to) {
  $("dialHangupButton").disabled = false;
  voiceCall.on("accept", () => { $("dialStatus").textContent = `In call with ${to}.`; });
  voiceCall.on("disconnect", () => endVoiceCall("Call ended."));
  voiceCall.on("cancel", () => endVoiceCall("Call ended."));
  voiceCall.on("reject", () => endVoiceCall("Call rejected."));
  voiceCall.on("error", (e) => endVoiceCall(`Call error: ${e.message || e.code || e}`));
}

function endVoiceCall(message) {
  voiceCall = null;
  $("dialHangupButton").disabled = true;
  $("dialButton").disabled = false;
  if (message) $("dialStatus").textContent = message;
}

$("dialButton").addEventListener("click", async () => {
  const to = $("dialTarget").value.trim();
  const numberId = $("callerId").value;
  if (!to) { $("dialStatus").textContent = "Enter a number to dial."; return; }
  if (!numberId) { $("dialStatus").textContent = "Verify a caller-ID number first."; return; }
  if (voiceCall) { $("dialStatus").textContent = "Already on a call."; return; }

  $("dialButton").disabled = true;
  const res = await api("/api/voice/dial", { method: "POST", body: { to, numberId } });
  if (!res.ok) {
    $("dialStatus").textContent = `Blocked: ${res.data.error}`;
    $("dialButton").disabled = false;
    return;
  }
  // No ticket → server-side mock carrier (no browser audio leg); just report it.
  if (!res.data.ticket) {
    $("dialStatus").textContent = `Calling ${to} as ${res.data.from} (ref ${res.data.callRef}).`;
    $("dialButton").disabled = false;
    return;
  }
  if (!voiceDevice) {
    $("dialStatus").textContent = "Carrier not ready — reload and try again.";
    $("dialButton").disabled = false;
    return;
  }
  try {
    $("dialStatus").textContent = `Calling ${to} as ${res.data.from}…`;
    // The browser passes ONLY the opaque ticket; the destination + caller ID were
    // already authorized server-side and are recovered at the TwiML webhook.
    voiceCall = await voiceDevice.connect({ params: { ticket: res.data.ticket } });
    wireVoiceCall(to);
  } catch (e) {
    voiceCall = null;
    $("dialButton").disabled = false;
    $("dialStatus").textContent = `Could not start call: ${e.message || e}`;
  }
});

$("dialHangupButton").addEventListener("click", () => {
  if (voiceCall) voiceCall.disconnect();
  else if (voiceDevice) voiceDevice.disconnectAll();
});

// ---------------------------------------------------------------------------
bootstrap();
