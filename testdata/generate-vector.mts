import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
const root = resolve(process.env.DETER_CONSOLE_SERVER ?? process.cwd());
const from = async (p: string) => import(pathToFileURL(resolve(root, "src", p)).href);
const { compile, SUPPLY_CHAIN_DOMAIN } = await from("supplychain/compile.ts");
const { DEFAULT_POLICY } = await from("supplychain/model.ts");
const { signWithDomain } = await from("policy/sign.ts");

// RFC 8032 §7.1 test key — the same one rules_vector_test.go uses.
const PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const VERSION = 1789234440;

const corpus = {
  modifiedAt: new Date("2026-09-12T16:00:00.000Z"),
  sources: ["osv", "cisa-kev"],
  malware: [
    { advisoryId: "MAL-2025-0000", ecosystem: "npm", packageName: "reqeusts", version: null },
    { advisoryId: "MAL-2025-47141", ecosystem: "npm", packageName: "@ctrl/tinycolor", version: "4.1.1" },
  ],
  vulns: [
    { advisoryId: "GHSA-0000-nofix-0000", ecosystem: "npm", packageName: "abandoned-pkg",
      introduced: "1.0.0", fixed: null, lastAffected: null, version: null, severity: "critical",
      kev: false, epss: null, hasFix: false, fixedIn: null },
    { advisoryId: "GHSA-35jh-r3h4-6jhm", ecosystem: "npm", packageName: "lodash",
      introduced: null, fixed: null, lastAffected: "4.17.20", version: null, severity: "high",
      kev: false, epss: null, hasFix: true, fixedIn: "4.17.21" },
    { advisoryId: "GHSA-4r4m-qw57-chr8", ecosystem: "npm", packageName: "vite",
      introduced: "4.0.0", fixed: "4.5.11", lastAffected: null, version: null, severity: "moderate",
      kev: true, epss: 0.412, hasFix: true, fixedIn: "4.5.11" },
    { advisoryId: "GHSA-4r4m-qw57-chr8", ecosystem: "npm", packageName: "vite",
      introduced: "6.2.0", fixed: "6.2.4", lastAffected: null, version: null, severity: "moderate",
      kev: true, epss: 0.412, hasFix: true, fixedIn: "6.2.4" },
  ],
};

const { doc } = compile(corpus, {
  scope: "ci",
  policy: DEFAULT_POLICY,
  exceptions: [],
  registries: ["registry.npmjs.org", "registry.yarnpkg.com", "npm.pkg.github.com"],
  generatedAt: new Date("2026-09-12T16:34:00.000Z"),
});
const sig = signWithDomain(SUPPLY_CHAIN_DOMAIN, `${VERSION}\n${doc}`, PRIV);
console.log(JSON.stringify({ version: VERSION, sig, doc }, null, 0));
