// Regenerates testdata/console-document.txt — the fixture in supplychain_console_test.go.
//
// The point of generating it is that NOBODY writes this format by hand. The guard spent a release
// reading `:` while the console wrote `|`, and every fixture in the Go tests was hand-written in the
// old grammar, so the whole suite stayed green while CI enforced almost nothing. A fixture produced
// by the console's own compiler cannot drift from the console quietly: regenerate, and a changed
// grammar shows up as a failing test rather than as a silent hole in production.
//
// Run from a deter-console checkout (it imports the compiler directly):
//
//   cd deter-console/packages/server
//   ./node_modules/.bin/tsx /path/to/deter-guard/testdata/generate.mts > \
//       /path/to/deter-guard/testdata/console-document.txt
//
// The compiler is imported from `$DETER_CONSOLE_SERVER/src/supplychain` (default: the working
// directory), rather than by a path relative to this file, so this script can live in this repo and
// still load the other one's source.
//
// Generated 2026-09-13 from deter-console 665dca2 (packages/server/src/supplychain/compile.ts).

import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(process.env.DETER_CONSOLE_SERVER ?? process.cwd());
const from = async (m: string) => import(pathToFileURL(resolve(root, "src/supplychain", m)).href);
const { compile } = await from("compile.ts");
const { DEFAULT_POLICY } = await from("model.ts");

type Corpus = Parameters<typeof compile>[0];

// A small corpus covering every line shape and a spread of ecosystems, run through the console's
// real compiler so the fixture is the console's output rather than someone's memory of it.
const corpus: Corpus = {
  modifiedAt: new Date("2026-09-13T09:00:00.000Z"),
  sources: ["osv", "cisa-kev", "epss"],
  malware: [
    { advisoryId: "MAL-2025-0001", ecosystem: "npm", packageName: "evil-typosquat", version: null },
    { advisoryId: "MAL-2025-47141", ecosystem: "npm", packageName: "@ctrl/tinycolor", version: "4.1.1" },
    { advisoryId: "MAL-2025-0002", ecosystem: "PyPI", packageName: "Requests-Toolbelt-Evil", version: null },
    { advisoryId: "MAL-2025-0003", ecosystem: "NuGet", packageName: "Newtonsoft.Json.Evil", version: "1.0.0" },
  ],
  vulns: [
    { advisoryId: "GHSA-4r4m-qw57-chr8", ecosystem: "npm", packageName: "vite", introduced: "6.2.0",
      fixed: "6.2.4", lastAffected: null, version: null, severity: "moderate", kev: true, epss: 0.42,
      hasFix: true, fixedIn: "6.2.4" },
    { advisoryId: "GHSA-35jh-r3h4-6jhm", ecosystem: "npm", packageName: "lodash", introduced: null,
      fixed: null, lastAffected: null, version: "4.17.20", severity: "high", kev: false, epss: null,
      hasFix: true, fixedIn: "4.17.21" },
    { advisoryId: "GHSA-abandoned", ecosystem: "npm", packageName: "abandoned-pkg", introduced: "1.0.0",
      fixed: null, lastAffected: null, version: null, severity: "critical", kev: false, epss: null,
      hasFix: false, fixedIn: null },
    { advisoryId: "GHSA-mvn-1", ecosystem: "Maven", packageName: "org.apache.logging.log4j:log4j-core",
      introduced: "2.0.0", fixed: "2.17.1", lastAffected: null, version: null, severity: "critical",
      kev: true, epss: 0.97, hasFix: true, fixedIn: "2.17.1" },
    { advisoryId: "GHSA-py-1", ecosystem: "PyPI", packageName: "Requests", introduced: "2.0.0",
      fixed: "2.31.0", lastAffected: null, version: null, severity: "high", kev: false, epss: null,
      hasFix: true, fixedIn: "2.31.0" },
  ],
};

const out = compile(corpus, {
  scope: "ci",
  policy: DEFAULT_POLICY,
  exceptions: [],
  generatedAt: new Date("2026-09-13T10:00:00.000Z"),
});
process.stdout.write(out.doc);
process.stderr.write(`entries=${out.entryCount} malware=${out.malwareCount} vuln=${out.vulnCount}\n`);
