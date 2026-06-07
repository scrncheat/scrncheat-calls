// Authoritative, atomic rate limiting backed by D1 (rate_counters table).
//
// A single upsert with RETURNING gives us the post-increment count without a
// read-modify-write race: if the current window has expired we reset to 1,
// otherwise we increment. This is the security-critical limiter (OTP issuance,
// verification attempts, future spend caps).

/**
 * Increment `bucket` within a sliding fixed window and return the new count.
 * @returns {Promise<number>} count within the active window
 */
export async function incrementCounter(env, bucket, windowSeconds, now = Date.now()) {
  const cutoff = now - windowSeconds * 1000;
  const row = await env.DB.prepare(
    `INSERT INTO rate_counters (bucket, count, window_start, updated_at)
     VALUES (?1, 1, ?2, ?2)
     ON CONFLICT(bucket) DO UPDATE SET
       count = CASE WHEN rate_counters.window_start <= ?3 THEN 1 ELSE rate_counters.count + 1 END,
       window_start = CASE WHEN rate_counters.window_start <= ?3 THEN ?2 ELSE rate_counters.window_start END,
       updated_at = ?2
     RETURNING count`
  )
    .bind(bucket, now, cutoff)
    .first();
  return row ? row.count : 1;
}

/**
 * Increment and report whether the limit has been exceeded.
 * @returns {Promise<{allowed: boolean, count: number}>}
 */
export async function checkRateLimit(env, bucket, limit, windowSeconds, now = Date.now()) {
  const count = await incrementCounter(env, bucket, windowSeconds, now);
  return { allowed: count <= limit, count };
}
