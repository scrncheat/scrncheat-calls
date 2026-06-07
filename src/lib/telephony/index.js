// Telephony provider selection. The mock is the default (used by the test suite
// and any environment without a carrier configured). Production sets
// `TELEPHONY_PROVIDER=twilio` (plus the Twilio secrets) in the Cloudflare
// dashboard to switch to the real carrier. Every provider implements the same
// interface (name, placesCallsServerSide, lookupLineType, sendVerification, and
// either placeCall or the browser-initiated dial flow).

import { MockProvider } from "./mock.js";
import { TwilioProvider } from "./twilio.js";

let cached = null;
let cachedKey = null;

export function getProvider(env) {
  const key = (env && env.TELEPHONY_PROVIDER) || "mock";
  if (cached && cachedKey === key) return cached;
  cachedKey = key;
  cached = key === "twilio" ? new TwilioProvider(env) : new MockProvider();
  return cached;
}
