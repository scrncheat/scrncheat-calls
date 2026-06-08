import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          compatibilityDate: "2025-08-13",
          // Test-only values. Real secrets are set in the Cloudflare dashboard.
          bindings: {
            OTP_PEPPER: "test-pepper",
            EXPOSE_CODES: "1",
            TEST_MIGRATIONS: migrations,
            // Force the mock provider + kill-switch-off in tests, overriding
            // wrangler.toml's live TELEPHONY_* values (tests must never hit the
            // real carrier; individual tests opt in via { enabled: true }).
            TELEPHONY_PROVIDER: "mock",
            TELEPHONY_ENABLED: "false",
            // Test-only carrier creds so the webhook signature gate can be exercised.
            TWILIO_AUTH_TOKEN: "test-twilio-token",
          },
        },
      }),
    ],
    test: {
      include: ["test/**/*.test.js"],
      setupFiles: ["./test/apply-migrations.js"],
    },
  };
});