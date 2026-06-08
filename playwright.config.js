import { defineConfig, devices } from "@playwright/test";

// E2E runs against a local `wrangler dev` with dev-only flags:
//   EXPOSE_CODES=1          -> OTP codes returned over HTTP so tests can read them
//   TELEPHONY_ENABLED       -> exercise the dial path end-to-end
//   TELEPHONY_PROVIDER=mock -> force the mock carrier, overriding wrangler.toml's
//                              live "twilio" so the suite never hits the network
// None of these override production.
export default defineConfig({
  testDir: "./e2e",
  timeout: 45000,
  expect: { timeout: 15000 },
  fullyParallel: false,
  workers: 1,
  reporter: "list",
  use: {
    baseURL: "http://localhost:8787",
    trace: "on-first-retry",
    launchOptions: {
      args: [
        "--use-fake-ui-for-media-stream",
        "--use-fake-device-for-media-stream",
        "--autoplay-policy=no-user-gesture-required",
      ],
    },
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command:
      "npm run migrate:local && npx wrangler dev --port 8787 --var EXPOSE_CODES:1 --var OTP_PEPPER:e2e-pepper --var TELEPHONY_ENABLED:true --var TELEPHONY_PROVIDER:mock",
    url: "http://localhost:8787",
    timeout: 120000,
    reuseExistingServer: !process.env.CI,
  },
});
