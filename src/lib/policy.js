// Toll-fraud authorization: the single decision point for whether an outbound
// PSTN call is permitted. Kept as a PURE function so every branch is trivially
// testable without a database or network.

// Conservative default block-list: premium-rate / high-cost ranges that are a
// common toll-fraud target. Tunable per-user via dial_policy.blocked_prefixes.
export const DEFAULT_BLOCKED_PREFIXES = [
  "+449", // UK premium rate (09)
  "+4487", // UK personal/premium (087)
  "+4484", // UK special services (084)
  "+4470", // UK personal numbers (070) — often expensive
  "+1900", // US premium
  "+1809", // Dominican Republic (classic one-ring scam target)
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
 * Decide whether a dial is allowed.
 * @param {object} o
 * @param {boolean} o.enabled            global/telephony kill-switch
 * @param {string|null} o.toE164         normalised destination (null if invalid)
 * @param {object|null} o.verifiedNumber the caller-id row (must belong to user + be verified)
 * @param {string} o.userId
 * @param {string[]} o.allowedPrefixes
 * @param {string[]} o.blockedPrefixes
 * @param {number} [o.hourlyCount]       post-increment count this hour
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

  // Block-list wins over allow-list.
  if ((o.blockedPrefixes || []).some((p) => o.toE164.startsWith(p))) {
    return { allowed: false, reason: "destination_blocked" };
  }
  if (!(o.allowedPrefixes || []).some((p) => o.toE164.startsWith(p))) {
    return { allowed: false, reason: "destination_not_allowed" };
  }

  if (
    typeof o.hourlyCount === "number" &&
    typeof o.hourlyLimit === "number" &&
    o.hourlyCount > o.hourlyLimit
  ) {
    return { allowed: false, reason: "rate_limited" };
  }

  return { allowed: true, fromE164: o.verifiedNumber.e164 };
}
