import { defineConfig } from "vitest/config";
import path from "path";

const templateRoot = path.resolve(import.meta.dirname);

export default defineConfig({
  root: templateRoot,
  resolve: {
    alias: {
      "@": path.resolve(templateRoot, "client", "src"),
      "@shared": path.resolve(templateRoot, "shared"),
      "@assets": path.resolve(templateRoot, "attached_assets"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    // [Phase 31] CI/CD パイプラインでは、環境に依存しないテストのみを実行
    // server/*.test.ts はデータベース接続が必要なため、除外
    include: ["tests/**/*.test.ts"],
    exclude: [
      "node_modules/",
      "dist/",
      "server/**/*.test.ts",  // DB 依存的なテストを除外
    ],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "tests/",
        "dist/",
      ],
    },
  },
});
