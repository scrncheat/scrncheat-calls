// E.164 parsing/validation/classification via libphonenumber-js (pure JS).

import { parsePhoneNumberFromString } from "libphonenumber-js";

/** Normalise arbitrary input to strict E.164, or null if invalid. */
export function normalizeE164(input) {
  const parsed = parsePhoneNumberFromString(String(input || "").trim());
  return parsed && parsed.isValid() ? parsed.number : null;
}

/**
 * Classify a number. Returns { e164, country, lineType } with e164 === null when
 * the input is not a valid phone number.
 */
export function classify(input) {
  const parsed = parsePhoneNumberFromString(String(input || "").trim());
  if (!parsed || !parsed.isValid()) return { e164: null, country: null, lineType: "unknown" };

  const type = parsed.getType();
  let lineType = "unknown";
  if (type === "MOBILE") lineType = "mobile";
  else if (type === "FIXED_LINE") lineType = "landline";
  else if (type === "VOIP") lineType = "voip";

  return { e164: parsed.number, country: parsed.country || null, lineType };
}
