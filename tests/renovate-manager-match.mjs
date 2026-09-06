#!/usr/bin/env node
// Drift guard between the Renovate custom-manager regexes in renovate.json and
// the inventory schema: compiles the exact managerFilePatterns/matchStrings
// with the same regex engine Renovate uses (JS) and asserts every
// inventory/<app>/image.yaml is matched with non-empty depName, currentValue
// and currentDigest captures. A green run proves extraction cannot silently
// return empty (the "silent blind mode" failure: regex drifts from the YAML
// field names, Renovate reports nothing, the dashboard goes quiet).
// Stdlib only (fs, path, url). Exit 0 = all entries extracted; exit 1 = miss.

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

let failures = 0;
for (const [i, manager] of managers.entries()) {
  const label = `customManagers[${i}]`;
  const filePatterns = (manager.managerFilePatterns ?? []).map(compileFilePattern);
  if (filePatterns.length === 0) {
    console.error(`miss: ${label} has no managerFilePatterns`);
    failures++;
    continue;
  }
  const matchStrings = manager.matchStrings ?? [];
  if (matchStrings.length === 0) {
    console.error(`miss: ${label} has no matchStrings`);
    failures++;
    continue;
  }

  for (const rel of entries) {
    const content = readFileSync(join(root, rel), "utf8");
    if (!filePatterns.some((re) => re.test(rel))) {
      console.error(`miss: ${rel} matches no managerFilePatterns of ${label}`);
      failures++;
      continue;
    }
    let match = null;
    for (const ms of matchStrings) {
      match = new RegExp(ms).exec(content);
      if (match) break;
    }
    if (!match) {
      console.error(`miss: ${rel} matched no matchStrings regex of ${label}`);
      failures++;
      continue;
    }
    const missing = ["depName", "currentValue", "currentDigest"].filter(
      (g) => !match.groups?.[g],
    );
    if (missing.length > 0) {
      console.error(`miss: ${rel} empty/missing capture group(s): ${missing.join(", ")}`);
      failures++;
      continue;
    }
    const digestShort = match.groups.currentDigest.slice(0, 19);
    console.log(`match: ${rel} -> ${match.groups.depName} @ ${match.groups.currentValue} ${digestShort}`);
  }
}

if (failures > 0) {
  console.error(`${failures} mismatch(es) — regex/schema drift detected`);
  process.exit(1);
}
