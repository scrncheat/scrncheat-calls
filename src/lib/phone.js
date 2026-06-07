// E.164 parsing/validation/classification via libphonenumber-js (pure JS).

import { parsePhoneNumberFromString } from "libphonenumber-js";

// libphonenumber-js getType() -> our normalized line type.
const TYPE_MAP = {
  MOBILE: "mobile",
  FIXED_LINE: "landline",
  FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
  VOIP: "voip",
  TOLL_FREE: "toll_free",
  PREMIUM_RATE: "premium_rate",
  SHARED_COST: "shared_cost",
  PERSONAL_NUMBER: "personal_number",
  PAGER: "pager",
  UAN: "uan",
  VOICEMAIL: "voicemail",
};

/** Normalise arbitrary input to strict E.164, or null if invalid. */
export function normalizeE164(input) {
  const parsed = parsePhoneNumberFromString(String(input || "").trim());
  return parsed && parsed.isValid() ? parsed.number : null;
}

/**
 * Classify a number. Returns { e164, country, lineType }; e164 is null when the
 * input is not a valid phone number. lineType is "unknown" when the type cannot
 * be determined (many valid numbers, e.g. some geographic ranges, report no
 * type — these are treated as normal/callable, not blocked).
 */
export function classify(input) {
  const parsed = parsePhoneNumberFromString(String(input || "").trim());
  if (!parsed || !parsed.isValid()) return { e164: null, country: null, lineType: "unknown" };
  return {
    e164: parsed.number,
    country: parsed.country || null,
    lineType: TYPE_MAP[parsed.getType()] || "unknown",
  };
}
