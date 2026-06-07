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
          // Durable Object stub fetches from the Worker (the presence /control
          // API) are incompatible with per-test isolated storage in this pool
          // version (it leaves a .sqlite-shm WAL file the cleanup rejects).
          // Our tests use unique keys per test, so they don't rely on rollback.
          isolatedStorage: false,
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
