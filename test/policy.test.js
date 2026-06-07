import { describe, it, expect } from "vitest";
import { evaluateDialPolicy, DEFAULT_BLOCKED_PREFIXES } from "../src/lib/policy.js";

const verified = { user_id: "u1", status: "verified", e164: "+447400123456" };
const base = {
  enabled: true,
  toE164: "+12025550123", // a US number — any country is allowed by default
  destinationType: "fixed_or_mobile",
  verifiedNumber: verified,
  userId: "u1",
  allowedPrefixes: [], // no geographic restriction
  blockedPrefixes: DEFAULT_BLOCKED_PREFIXES,
  hourlyCount: 1,
  hourlyLimit: 20,
};

describe("dial policy — the toll-fraud gate", () => {
  it("allows a normal number in ANY country with an owned, verified caller id", () => {
    const d = evaluateDialPolicy(base);
    expect(d.allowed).toBe(true);
    expect(d.fromE164).toBe("+447400123456");
  });

  it("allows an unknown-but-valid line type (does not over-block)", () => {
    expect(evaluateDialPolicy({ ...base, destinationType: "unknown", toE164: "+33123456789" }).allowed).toBe(true);
  });

  it("blocks everything when telephony is disabled (kill-switch)", () => {
    expect(evaluateDialPolicy({ ...base, enabled: false })).toMatchObject({ allowed: false, reason: "telephony_disabled" });
  });

  it("rejects an invalid destination", () => {
    expect(evaluateDialPolicy({ ...base, toE164: null }).reason).toBe("invalid_destination");
    expect(evaluateDialPolicy({ ...base, toE164: "+44abc" }).reason).toBe("invalid_destination");
  });

  it("rejects a caller id the user does not own", () => {
    expect(evaluateDialPolicy({ ...base, verifiedNumber: { ...verified, user_id: "someone-else" } }).reason).toBe("caller_id_not_verified");
  });

  it("rejects an unverified or missing caller id", () => {
    expect(evaluateDialPolicy({ ...base, verifiedNumber: { ...verified, status: "pending" } }).reason).toBe("caller_id_not_verified");
    expect(evaluateDialPolicy({ ...base, verifiedNumber: null }).reason).toBe("caller_id_not_verified");
  });

  it("blocks premium-rate / special number TYPES in any country", () => {
    for (const t of ["premium_rate", "personal_number", "shared_cost", "pager", "uan", "voicemail"]) {
      expect(evaluateDialPolicy({ ...base, destinationType: t }).reason).toBe("destination_blocked");
    }
  });

  it("blocks premium prefixes even when the line type is unknown (backstop)", () => {
    expect(evaluateDialPolicy({ ...base, destinationType: "unknown", toE164: "+449001234567" }).reason).toBe("destination_blocked");
  });

  it("enforces a country allow-list only when one is configured", () => {
    // configured to UK only -> a US number is rejected
    expect(evaluateDialPolicy({ ...base, allowedPrefixes: ["+44"] }).reason).toBe("destination_not_allowed");
    // configured to US -> allowed
    expect(evaluateDialPolicy({ ...base, allowedPrefixes: ["+1"] }).allowed).toBe(true);
  });

  it("blocks when the hourly velocity cap is exceeded", () => {
    expect(evaluateDialPolicy({ ...base, hourlyCount: 21 }).reason).toBe("rate_limited");
  });
});
