// Outbound-dial authorization. The single decision point for whether a PSTN
// call is permitted. Pure function so every branch is trivially testable.
//
// Policy (per the product intent):
//   - Call ANY country — no geographic restriction by default.
//   - Block premium-rate / special-rate / non-standard number TYPES so only
//     normal landline/mobile-style numbers are dialable.
//   - A prefix block-list backstops cases where the line type can't be read.
//   - An OPTIONAL per-user country allow-list (off by default).
//   - Velocity cap + kill-switch as toll-fraud safety nets.

// Number types that must never be dialed (premium / special / non-standard).
export const BLOCKED_LINE_TYPES = new Set([
  "premium_rate",
  "personal_number",
  "shared_cost",
  "pager",
  "uan",
  "voicemail",
]);

// Backstop premium / high-cost prefixes for when the line type is unknown.
export const DEFAULT_BLOCKED_PREFIXES = [
  "+449", // UK premium rate (09)
  "+4487", // UK personal/premium (087)
  "+4484", // UK special services (084)
  "+4470", // UK personal numbers (070)
  "+1900", // US premium
  "+882", // international networks
  "+883", // international networks
  "+979", // international premium-rate
  "+808", // shared-cost
];

export function parsePrefixes(str) {
  return String(str || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * @param {object} o
 * @param {boolean} o.enabled            telephony kill-switch
 * @param {string|null} o.toE164         normalised destination (null if invalid)
 * @param {string} [o.destinationType]   classified line type of the destination
 * @param {object|null} o.verifiedNumber caller-id row (must belong to user + verified)
 * @param {string} o.userId
 * @param {string[]} [o.allowedPrefixes] optional country allow-list (empty = all)
 * @param {string[]} [o.blockedPrefixes]
 * @param {number} [o.hourlyCount]
 * @param {number} [o.hourlyLimit]
 * @returns {{allowed: boolean, reason?: string, fromE164?: string}}
 */
export function evaluateDialPolicy(o) {
  if (!o.enabled) return { allowed: false, reason: "telephony_disabled" };

  if (!o.toE164 || !/^\+[1-9]\d{6,14}$/.test(o.toE164)) {
    return { allowed: false, reason: "invalid_destination" };
  }

  // Caller-ID must belong to this user AND be verified — never trust a raw From.
  if (
    !o.verifiedNumber ||
    o.verifiedNumber.user_id !== o.userId ||
    o.verifiedNumber.status !== "verified"
  ) {
    return { allowed: false, reason: "caller_id_not_verified" };
  }

  // Block premium/special number types in ANY country.
  if (o.destinationType && BLOCKED_LINE_TYPES.has(o.destinationType)) {
    return { allowed: false, reason: "destination_blocked" };
  }
  const blocked = o.blockedPrefixes || DEFAULT_BLOCKED_PREFIXES;
  if (blocked.some((p) => o.toE164.startsWith(p))) {
    return { allowed: false, reason: "destination_blocked" };
  }

  // Optional country allow-list (off by default => call anywhere).
  if (o.allowedPrefixes && o.allowedPrefixes.length && !o.allowedPrefixes.some((p) => o.toE164.startsWith(p))) {
    return { allowed: false, reason: "destination_not_allowed" };
  }

  if (
    typeof o.hourlyCount === "number" &&
    typeof o.hourlyLimit === "number" &&
    o.hourlyCount > o.hourlyLimit
  ) {
    return { allowed: false, reason: "rate_limited" };
  }

  // Daily spend cap (toll-fraud backstop). Off unless a cap is configured. Cost
  // is an estimate accrued from call duration, so the cap can be exceeded by at
  // most one in-flight call (bounded by the per-call time limit).
  if (
    typeof o.dailyCapMicro === "number" &&
    o.dailyCapMicro >= 0 &&
    typeof o.dailySpentMicro === "number" &&
    o.dailySpentMicro >= o.dailyCapMicro
  ) {
    return { allowed: false, reason: "spend_cap" };
  }

  return { allowed: true, fromE164: o.verifiedNumber.e164 };
}
