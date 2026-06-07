// Telephony provider selection. Until a real carrier is wired in (Phase 4) this
// always returns the mock. A CarrierProvider implementing the same interface
// (lookupLineType, sendVerification, placeCall) is the only thing that changes.

import { MockProvider } from "./mock.js";

let cached = null;

export function getProvider(env) {
  // env reserved for future carrier selection (e.g. env.TELEPHONY_PROVIDER).
  if (!cached) cached = new MockProvider();
  return cached;
}
