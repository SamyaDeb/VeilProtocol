import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// Veil browser app.
//
// Notes on the toolchain:
// - `nodePolyfills` supplies `Buffer` + `process`, which the shared crypto core
//   (client/src/prover/*.js, client/src/viewkey/encrypt.js) relies on. Those
//   modules are ALSO imported by the Node e2e suites, so they stay plain JS and
//   are never converted to TS — this build wraps them, it does not replace them.
// - `server.fs.allow: ['..']` lets us import the canonical deployment configs
//   from ../deployments/*.json instead of duplicating contract IDs in the app.
export default defineConfig({
  plugins: [
    react(),
    nodePolyfills({
      globals: { Buffer: true, process: true },
      protocolImports: true,
    }),
  ],
  server: {
    fs: { allow: ['..'] },
  },
  worker: {
    format: 'es',
    // Prover JS files use top-level await in their Node.js detection branch.
    // We shim `window` before importing them so that branch never runs,
    // but esbuild still parses the syntax. esnext target allows top-level await
    // in workers (all browsers that support SharedArrayBuffer/WASM also support
    // top-level await).
    rollupOptions: {
      output: { format: 'es' },
    },
    plugins: () => [],
  },
  build: {
    target: 'esnext',
  },
  optimizeDeps: {
    // snarkjs + circomlibjs are large CJS bundles; pre-bundle them once.
    include: ['snarkjs', 'circomlibjs'],
  },
});
