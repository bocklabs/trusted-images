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

// D-05 negative fixture: nothing may sit between the ref/tag/digest lines the
// custom manager binds — an inserted field breaks extraction AND Renovate's
// auto-replace would destroy the insertion on the next upstream bump. The
// fixture is v2-shaped with a field between tag: and digest:; asserted to be
// extracted by NO manager.
const negativeFixture = [
  "apiVersion: trusted-images.bocklabs.dev/v1",
  "kind: Image",
  "metadata:",
  "  name: app-negative",
  "spec:",
  "  upstream:",
  "    ref: quay.io/example/app-negative",
  "    tag: v1.2.3",
  "    note: field inserted between tag and digest",
  "    digest: sha256:" + "a".repeat(64),
  "  destination:",
  "    package: ghcr.io/bocklabs/app-negative",
  "  patchPolicy: enabled",
  "  validation:",
  "    type: http",
  "    port: 9187",
  "  version: 2",
].join("\n");

let negativeMatched = false;
for (const manager of managers) {
  for (const ms of manager.matchStrings ?? []) {
    const m = new RegExp(ms).exec(negativeFixture);
    if (m && CAPTURES.every((g) => m.groups?.[g])) {
      negativeMatched = true;
      break;
    }
  }
  if (negativeMatched) break;
}
if (negativeMatched) {
  console.error(
    "match: negative fixture WAS extracted by a custom manager — the between-lines invariant is broken",
  );
  process.exit(1);
}
console.log(
  "negative: between-lines fixture missed by all managers as expected — ref/tag/digest adjacency enforced",
);

if (failures > 0) {
  console.error(`${failures} mismatch(es) — regex/schema drift detected`);
  process.exit(1);
}

const tools = [
  { files: [".github/workflows/promote-publish.yaml", ".github/workflows/validate.yaml"], cliFiles: [".github/workflows/promote-publish.yaml"], action: "sigstore/cosign-installer", cli: "sigstore/cosign" },
  { files: [".github/workflows/promote-candidate.yaml"], cliFiles: [".github/workflows/promote-candidate.yaml"], action: "aquasecurity/trivy-action", cli: "aquasecurity/trivy" },
];
for (const tool of tools) {
  const manager = managers.find((item) => item.depNameTemplate === tool.cli &&
    tool.cliFiles.every((file) => item.managerFilePatterns?.some((pattern) => compileFilePattern(pattern).test(file))));
  if (!manager) throw new Error(`miss: ${tool.cli} CLI pin extraction`);
  const rule = config.packageRules.find((item) => item.automerge === true &&
    item.matchPackageNames?.length === 2 &&
    item.matchPackageNames.includes(tool.action) && item.matchPackageNames.includes(tool.cli));
  if (!rule || JSON.stringify([...rule.matchFileNames].sort()) !== JSON.stringify([...tool.files].sort()) ||
      entries.some((entry) => rule.matchFileNames.includes(entry))) throw new Error(`miss: tool-only automerge for ${tool.cli}`);
  const actionHashes = new Set();
  const releaseVersions = new Set();
  for (const file of tool.files) {
    const content = readFileSync(join(root, file), "utf8");
    const actions = [...content.matchAll(new RegExp(`uses: ${tool.action}@([a-f0-9]{40}) # v\\d+`, "g"))];
    const releases = manager.matchStrings.flatMap((source) => [...content.matchAll(new RegExp(source, "g"))]);
    actions.forEach((match) => actionHashes.add(match[1]));
    releases.forEach((match) => releaseVersions.add(match.groups?.currentValue));
    if (!actions.length || releases.length !== (tool.cliFiles.includes(file) ? actions.length : 0) ||
        releases.some((match) => !/^v\d+\.\d+\.\d+$/.test(match.groups?.currentValue))) {
      throw new Error(`miss: ${tool.action} digest or ${tool.cli} release in ${file}`);
    }
  }
  if (actionHashes.size !== 1) throw new Error(`miss: ${tool.action} installer SHA pins diverged`);
  if (releaseVersions.size !== 1) throw new Error(`miss: ${tool.cli} release pins diverged`);
  console.log(`tool: ${tool.action} digest and ${tool.cli} ${[...releaseVersions][0]} -> automerge`);
}
if (config.automerge !== false || !config.platformAutomerge || config.automergeStrategy !== "merge") {
  throw new Error("miss: required-check automerge defaults drifted");
}
