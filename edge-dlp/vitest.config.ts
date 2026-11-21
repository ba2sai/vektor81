import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "cloudflare:workers": resolve(import.meta.dirname, "tests/stubs/cloudflare-workers.ts"),
    },
  },
  test: {
    server: {
      deps: {
        inline: ["@cloudflare/zt-types"],
      },
    },
  },
});
