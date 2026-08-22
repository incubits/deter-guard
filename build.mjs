// Bundle the CLI to a single file.
//
// Uses esbuild's JS API rather than its `esbuild` bin. The bin is a shim that pnpm sometimes links
// straight to the platform binary, which Node then tries to parse as JavaScript — it fails
// differently depending on hoisting, and this build runs both on a developer's machine and inside
// Alpine in CI. The API has no such ambiguity.

import { build } from "esbuild";

await build({
  entryPoints: ["src/cli.ts"],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outfile: "dist/cli.js",
  // The shebang lives here, not in the source: two of them puts a second `#!` on line 2 of the
  // output, which is a syntax error.
  banner: { js: "#!/usr/bin/env node" },
  // Nothing is marked external: the runtime image ships this file alone, with no node_modules.
  logLevel: "info",
});
