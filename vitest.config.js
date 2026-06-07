import { defineWorkersConfig, readD1Migrations } from "@cloudflare/vitest-pool-workers/config";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineWorkersConfig(async () => {
  const migrations = await readD1Migrations(path.join(__dirname, "migrations"));

  return {
    test: {
      include: ["test/**/*.test.js"],
      setupFiles: ["./test/apply-migrations.js"],
      poolOptions: {
        workers: {
          singleWorker: true,
          wrangler: { configPath: "./wrangler.toml" },
          miniflare: {
            compatibilityDate: "2025-08-13",
            // Test-only values. Real secrets are set in the Cloudflare dashboard.
            bindings: {
              OTP_PEPPER: "test-pepper",
              EXPOSE_CODES: "1",
              TEST_MIGRATIONS: migrations,
            },
          },
        },
      },
    },
  };
});
