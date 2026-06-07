import { describe, it, expect } from "vitest";
import { evaluateDialPolicy, DEFAULT_BLOCKED_PREFIXES } from "../src/lib/policy.js";

const verified = { user_id: "u1", status: "verified", e164: "+447700900123" };
const base = {
  enabled: true,
  toE164: "+33123456789",
  verifiedNumber: verified,
  userId: "u1",
  allowedPrefixes: ["+44", "+33"],
  blockedPrefixes: DEFAULT_BLOCKED_PREFIXES,
  hourlyCount: 1,
  hourlyLimit: 20,
};

describe("dial policy — the toll-fraud gate", () => {
  it("allows a permitted destination with an owned, verified caller id", () => {
    const d = evaluateDialPolicy(base);
    expect(d.allowed).toBe(true);
    expect(d.fromE164).toBe("+447700900123");
  });

  it("blocks everything when telephony is disabled (kill-switch)", () => {
    expect(evaluateDialPolicy({ ...base, enabled: false })).toMatchObject({
      allowed: false,
      reason: "telephony_disabled",
    });
  });

  it("rejects an invalid destination", () => {
    expect(evaluateDialPolicy({ ...base, toE164: null }).reason).toBe("invalid_destination");
    expect(evaluateDialPolicy({ ...base, toE164: "+44abc" }).reason).toBe("invalid_destination");
  });

  it("rejects a caller id the user does not own", () => {
    const d = evaluateDialPolicy({ ...base, verifiedNumber: { ...verified, user_id: "someone-else" } });
    expect(d.reason).toBe("caller_id_not_verified");
  });

  it("rejects an unverified caller id", () => {
    const d = evaluateDialPolicy({ ...base, verifiedNumber: { ...verified, status: "pending" } });
    expect(d.reason).toBe("caller_id_not_verified");
  });

  it("rejects a missing caller id", () => {
    expect(evaluateDialPolicy({ ...base, verifiedNumber: null }).reason).toBe("caller_id_not_verified");
  });

  it("blocks premium-rate / high-cost destinations (block-list wins)", () => {
    expect(evaluateDialPolicy({ ...base, toE164: "+449001234567" }).reason).toBe("destination_blocked");
    expect(evaluateDialPolicy({ ...base, toE164: "+18091234567" }).reason).toBe("destination_blocked");
    expect(evaluateDialPolicy({ ...base, toE164: "+8821234567" }).reason).toBe("destination_blocked");
  });

  it("blocks destinations outside the allow-list", () => {
    expect(evaluateDialPolicy({ ...base, toE164: "+15551234567" }).reason).toBe("destination_not_allowed");
  });

  it("blocks when the hourly velocity cap is exceeded", () => {
    expect(evaluateDialPolicy({ ...base, hourlyCount: 21 }).reason).toBe("rate_limited");
  });
});
