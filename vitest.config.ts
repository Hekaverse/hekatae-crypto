import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    setupFiles: ["tests/setup.ts"],
    coverage: {
      provider: "v8",
      // Ratchet thresholds: set ~5% below the measured baseline
      // (2026-08-02: 88.06% stmts / 98.26% branch / 100% funcs / 88.06% lines).
      // Raise these as coverage improves — never lower them.
      thresholds: {
        statements: 83,
        branches: 93,
        functions: 95,
        lines: 83,
      },
    },
  },
});
