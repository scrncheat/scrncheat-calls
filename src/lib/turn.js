// Provide ICE servers for the in-app P2P leg. TURN credentials are served
// server-side (never embedded in static client JS) so they can be rotated and
// gated behind a session.
//
// Supports either:
//   A) static Cloudflare TURN credentials (env.TURN_USER + env.TURN_CRED), or
//   B) short-lived credentials minted from a Realtime TURN key
//      (env.TURN_KEY_ID + env.TURN_API_TOKEN).
// Falls back to STUN-only, which still connects on most networks.

const CF_STUN = { urls: ["stun:stun.cloudflare.com:3478"] };

const CF_TURN_URLS = [
  "turn:turn.cloudflare.com:3478?transport=udp",
  "turn:turn.cloudflare.com:3478?transport=tcp",
  "turns:turn.cloudflare.com:5349?transport=tcp",
];

export async function getTurnCredentials(env, ttlSeconds = 3600) {
  // Option A: static credentials supplied as secrets/vars.
  if (env.TURN_USER && env.TURN_CRED) {
    return [CF_STUN, { urls: CF_TURN_URLS, username: env.TURN_USER, credential: env.TURN_CRED }];
  }

  // Option B: mint short-lived credentials from a TURN key.
  if (env.TURN_KEY_ID && env.TURN_API_TOKEN) {
    try {
      const resp = await fetch(
        `https://rtc.live.cloudflare.com/v1/turn/keys/${env.TURN_KEY_ID}/credentials/generate`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${env.TURN_API_TOKEN}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ ttl: ttlSeconds }),
        }
      );
      if (resp.ok) {
        const data = await resp.json();
        if (data && data.iceServers) {
          return Array.isArray(data.iceServers) ? data.iceServers : [data.iceServers];
        }
      }
    } catch {
      // fall through to STUN-only
    }
  }

  return [CF_STUN];
}
