// Mint short-lived ICE server credentials for the in-app P2P leg.
//
// TURN credentials are generated server-side (never embedded in client JS) via
// the Cloudflare Realtime TURN API. If no TURN key is configured we fall back to
// STUN-only, which still connects on permissive networks.

const CF_STUN = { urls: ["stun:stun.cloudflare.com:3478"] };

export async function getTurnCredentials(env, ttlSeconds = 3600) {
  const keyId = env.TURN_KEY_ID;
  const token = env.TURN_API_TOKEN;
  if (!keyId || !token) {
    return [CF_STUN];
  }
  try {
    const resp = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${keyId}/credentials/generate`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ ttl: ttlSeconds }),
      }
    );
    if (!resp.ok) return [CF_STUN];
    const data = await resp.json();
    if (data && data.iceServers) {
      return Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
    }
    return [CF_STUN];
  } catch {
    return [CF_STUN];
  }
}
