#!/usr/bin/env node
// Drift guard between the Renovate custom-manager regexes in renovate.json and
// the inventory schema: compiles the exact managerFilePatterns/matchStrings
// with the same regex engine Renovate uses (JS) and asserts every
// inventory/<app>/image.yaml is extracted by at least one manager with
// non-empty depName, currentValue and currentDigest captures. A green run
// proves extraction cannot silently return empty. Stdlib only. Exit 0 = all
// entries extracted; exit 1 = miss.

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const config = JSON.parse(readFileSync(join(root, "renovate.json"), "utf8"));

// managerFilePatterns are "/body/flags" delimited; matchStrings are raw regex sources.
const compileFilePattern = (p) => {
  if (!p.startsWith("/")) return new RegExp(p);
  const end = p.lastIndexOf("/");
  return new RegExp(p.slice(1, end), p.slice(end + 1));
};

const entries = readdirSync(join(root, "inventory"), { withFileTypes: true })
  .filter((d) => d.isDirectory())
  .map((d) => `inventory/${d.name}/image.yaml`)
  .sort();
if (entries.length === 0) {
  console.error("miss: no inventory/<app>/image.yaml entries found");
  process.exit(1);
}

const managers = config.customManagers ?? [];
if (managers.length === 0) {
  console.error("miss: renovate.json has no customManagers");
  process.exit(1);
}

const CAPTURES = ["depName", "currentValue", "currentDigest"];
let failures = 0;
for (const rel of entries) {
  const content = readFileSync(join(root, rel), "utf8");
  let match = null;
  for (const manager of managers) {
    const filePatterns = (manager.managerFilePatterns ?? []).map(compileFilePattern);
    if (!filePatterns.some((re) => re.test(rel))) continue;
    for (const ms of manager.matchStrings ?? []) {
      const m = new RegExp(ms).exec(content);
      if (m && CAPTURES.every((g) => m.groups?.[g])) {
        match = m;
        break;
      }
    }
    if (match) break;
  }
  if (!match) {
    console.error(`miss: ${rel} extracted by no custom manager (regex/schema drift?)`);
    failures++;
    continue;
  }
  const digestShort = match.groups.currentDigest.slice(0, 19);
  console.log(`match: ${rel} -> ${match.groups.depName} @ ${match.groups.currentValue} ${digestShort}`);
}

if (failures > 0) {
  console.error(`${failures} mismatch(es) — regex/schema drift detected`);
  process.exit(1);
}
