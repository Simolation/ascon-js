import { defineConfig } from "vite";
import { resolve } from "path";
import dts from "vite-plugin-dts";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [dts()],
  resolve: {
    alias: {
      "@/": "/src/",
    },
  },
  build: {
    target: "esnext",
    sourcemap: true,
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "AsconJS",
      formats: ["es", "umd"],
    },
    rollupOptions: {
      output: {
        // Provide global variables to use in the UMD build
        // for externalized deps
        exports: "named",
        // inlineDynamicImports: true,
      },
    },
  },
});
