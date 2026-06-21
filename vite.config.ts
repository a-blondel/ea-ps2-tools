import { defineConfig } from "vite";

// Relative base so the build works at any GitHub Pages sub-path
// (https://user.github.io/repo/) without further configuration.
export default defineConfig({
  base: "./",
  build: {
    target: "es2020",
    outDir: "dist",
  },
});
