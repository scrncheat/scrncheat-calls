// Twilio carrier provider — real PSTN with the audio carried by the browser
// Voice SDK. This class mints Access Tokens, runs the Verified Caller ID flow,
// classifies destinations, and exposes a thin REST helper. Outbound calls are
// placed by the browser SDK and authorized at the TwiML webhook (see dial.js /
// worker.js), so there is no server-side placeCall here — `placesCallsServerSide`
// is false. The Worker never touches RTP.

import { classify } from "../phone.js";
import { base64Encode } from "../crypto.js";
import { mintVoiceAccessToken } from "./twilio-jwt.js";

const API_BASE = "https://api.twilio.com/2010-04-01";

export class TwilioProvider {
  constructor(env) {
    this.env = env;
  }

  get name() {
    return "twilio";
  }

  // Calls originate in the browser (then get authorized at the TwiML webhook),
  // not server-side. dial.js branches on this to use the pre-authorized ticket
  // flow instead of an immediate placeCall.
  get placesCallsServerSide() {
    return false;
  }

  // Ownership is proven by Twilio's Verified Caller ID flow (Twilio owns the
  // code and calls the number), not our in-house OTP. numbers.js branches on
  // this. The proven number is then usable as the caller ID on outbound calls.
  get verificationStyle() {
    return "carrier-callerid";
  }

  /** Line-type lookup. Local classification is free; Twilio Lookup is optional. */
  async lookupLineType(e164) {
    const c = classify(e164);
    return { lineType: c.lineType, country: c.country };
  }

  /** Mint a short-lived Voice Access Token for the browser Device. */
  async createAccessToken(identity, ttlSeconds = 3600) {
    const e = this.env;
    return mintVoiceAccessToken({
      accountSid: e.TWILIO_ACCOUNT_SID,
      apiKeySid: e.TWILIO_API_KEY_SID,
      apiKeySecret: e.TWILIO_API_KEY_SECRET,
      twimlAppSid: e.TWILIO_TWIML_APP_SID,
      identity,
      ttlSeconds,
    });
  }

  /**
   * Thin Twilio REST helper (Basic auth, form-encoded, JSON back). `path` is
   * relative to the account resource, e.g. "/OutgoingCallerIds.json".
   */
  async rest(method, path, form) {
    const e = this.env;
    const init = {
      method,
      headers: { Authorization: `Basic ${base64Encode(`${e.TWILIO_ACCOUNT_SID}:${e.TWILIO_AUTH_TOKEN}`)}` },
    };
    if (form) {
      init.headers["Content-Type"] = "application/x-www-form-urlencoded";
      init.body = new URLSearchParams(form).toString();
    }
    const resp = await fetch(`${API_BASE}/Accounts/${e.TWILIO_ACCOUNT_SID}${path}`, init);
    const text = await resp.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      /* non-JSON error body */
    }
    return { ok: resp.ok, status: resp.status, data };
  }

  /**
   * Begin Twilio's Verified Caller ID validation. Twilio generates the code,
   * places a call to `e164`, and the user keys the code in on their handset.
   * The returned `displayCode` is meant to be SHOWN to the user (it is not a
   * secret like our OTP), so the caller can surface it in the UI.
   * @returns {{ok:boolean, displayCode?:string, ref?:string, status?:number}}
   */
  async startCallerIdValidation({ e164, friendlyName, statusCallbackUrl }) {
    const form = { PhoneNumber: e164 };
    if (friendlyName) form.FriendlyName = friendlyName;
    if (statusCallbackUrl) form.StatusCallback = statusCallbackUrl;
    const r = await this.rest("POST", "/OutgoingCallerIds.json", form);
    if (!r.ok || !r.data) return { ok: false, status: r.status };
    return { ok: true, displayCode: r.data.validation_code, ref: r.data.call_sid };
  }

  /** True once `e164` appears in the account's validated outgoing caller IDs. */
  async isCallerIdValidated(e164) {
    const r = await this.rest(
      "GET",
      `/OutgoingCallerIds.json?PhoneNumber=${encodeURIComponent(e164)}`
    );
    if (!r.ok || !r.data) return false;
    const list = r.data.outgoing_caller_ids || [];
    return list.some((c) => c.phone_number === e164);
  }
}
