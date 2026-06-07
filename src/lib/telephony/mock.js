// Mock telephony provider. Implements the same interface a real carrier
// (Twilio/Telnyx/SignalWire) would, but never touches the phone network — no
// SMS, no calls, no charges. Used until a carrier is deliberately wired in.

import { randomId } from "../crypto.js";
import { classify } from "../phone.js";

export class MockProvider {
  get name() {
    return "mock";
  }

  /** Line-type lookup (a real provider would use a Lookup/HLR API). */
  async lookupLineType(e164) {
    const c = classify(e164);
    return { lineType: c.lineType, country: c.country };
  }

  /**
   * "Deliver" an ownership OTP. The code is generated and owned by us; the
   * provider is only the delivery pipe (SMS for mobile, spoken call for
   * landline). The mock logs it so it can be read during local dev/testing.
   */
  async sendVerification({ e164, channel, code }) {
    console.log(`[mock telephony] ${channel} OTP for ${e164}: ${code} (mock only — not delivered)`);
    return { ok: true, ref: "mock-verify-" + randomId() };
  }

  /** Place an outbound PSTN call. The mock completes instantly at zero cost. */
  async placeCall({ fromE164, toE164 }) {
    console.log(`[mock telephony] would dial ${toE164} presenting ${fromE164}`);
    return {
      callRef: "mock-call-" + randomId(),
      status: "completed",
      durationSec: 0,
      priceMicro: 0,
      currency: "GBP",
    };
  }
}
