# The promotion pipeline

How one generic inventory entry becomes one immutable image in the public
destination namespace, and what a completed `promote` run proves. This is the
producer runbook. It contains no deployment-side configuration or private
infrastructure details.

## Operator dispatch modes

The `promote` workflow is dispatch-only. Choose exactly one mode; normal, force,
recovery, and accepted-resume use the same validation, scanning, policy, artifact,
publication, and provenance gates. A manual run is initiated by an authorized
operator; these commands describe the interface, not a claim of authorization.

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app>
```

Use `force_repromote=true` only when unchanged bytes must occupy the next
append-only revision. Use `recover_tag=<tag>-bocklabs.<N>` to repair one existing
revision, adding `recovery_run_id=<original-numeric-run-id>` when that tag has no
merged provenance record. Use `accepted_candidate_run_id=<original-numeric-run-id>`
to resume one exact KEV-blocked candidate after its risk record merges.

`force_repromote`, `recover_tag`, and `accepted_candidate_run_id` are mutually
exclusive. Recovery and accepted resume revalidate identity and evidence; they
never relabel an old run or mutate an existing tag.

## Daily published-image monitoring

`daily-rescan.yaml` queues each current inventory app once daily, or on manual
dispatch, using the existing release App with **actions write on this repository
only**. No external verdict or receipt is required. The App installation must
grant that permission; enabling it is an operator action.

Each `promote.yaml` run with `automatic_rescan=true` selects the latest eligible,
signed published record from merged `main` **after acquiring the existing app
concurrency lock**. Its checkout must still equal current `main`; a stale queued
run fails closed and needs a fresh dispatch. Apps without a merged published
record skip monitoring; daily runs never perform first publication.

The exact public tag and digest receive a full Trivy report with all severities,
unfixed vulnerabilities, and package inventory. Immutable run/attempt artifacts
retain selection, full report, decision counts and SHA256SUMS for 30 days.
No-action monitoring also exports `trivy-full-report` with the existing generic
CycloneDX and import-manifest layout. Its legacy `upstream_ref`/`upstream_tag`
fields identify the actual scanned public package/tag/digest. Remediation runs
leave that artifact name to the existing publisher, avoiding an artifact collision.
Missing scanner/package coverage is unsupported, never evidence of a clean image.
No-fix and unsupported findings stay visible without attempting publication.

Reviewed `inventory/<app>/go-file-build*.json` records can identify versionless
Go packages in one or more binaries. Each record binds one binary target and
layer to the recorded published tag/digest, image config, upstream child,
source repository and revision. A record's module also covers packages below
that module path, which handles first-party subpackages in one binary.
Bundled binaries may use a separate source repository only when their embedded
VCS revision matches the reviewed source revision.
If the image has no revision label, the reviewed source tag must match the
image version or upstream base tag.

The review records the binary hash and embedded build metadata as audit
evidence. Trivy JSON provides no binary hash for a direct comparison. Runtime
matching uses the immutable image/config identity and the package's
`Layer.Digest` and `Layer.DiffID`, plus the reviewed target and module.
Malformed or stale evidence fails with an explicit validation error.
Inventory CI and rescans use the same parser for required binding fields.
Inventory CI also rejects invalid JSON and unknown top-level, layer or source
keys. The rescan decision retains every review hash and an explicit unknown
application-version limitation. Raw scan rows and findings remain unchanged.
Other versionless dependencies still fail coverage. A changed image requires
new reviews. This exception proves inventory coverage for the reviewed builds,
not vulnerability coverage for the unversioned packages.

The existing daily promotion workflow generates evidence once per automatic
published-image scan. It retains a checksummed patch for a scoped evidence PR
against the same source commit. A changed main branch stops the write-back.
If the reviewed targets, modules, source repositories, and main modules are
unchanged, the PR
auto-merges through the normal required checks. Any structural change stays
open for manual review.

Monitoring always runs; automatic remediation requires repository variable
`REMEDIATION_ENABLED=true` and defaults to disabled. Enabled patch policy permits
fixable OS findings at any severity. Language findings require a reviewed upstream
inventory change; Copa remains in stable OS scope. An actionable scan emits its
canonical finding hash internally and forces the next append-only revision through
the existing complete candidate and publication gates. Requested CVEs must disappear
in their ecosystem scope from the final full report. Historical acceptance may be
monitored, but monitoring never renews it or changes eligibility; the new candidate
still needs valid current KEV evidence and acceptance. Historical provenance is never
rewritten. Signed publication records use release-App auto-merge after required
checks; quarantine artifacts remain available for operator review.

## Fixed run order

Each gate fails the run before downstream work.

Producer-owned automatic remediation carries the canonical requested finding set
and hash into the final full-report evaluator and forces a fresh immutable
revision from the reviewed original upstream child. Every supplied finding must
be absent in its ecosystem scope; package/version changes or moving a result
cannot conceal an unresolved CVE. This gate also covers supplied language
findings, while Copa stays within stable OS scope. Existing residual/no-fix and
KEV policy still applies; remediation promises no zero-CVE result.

1. **Validate inventory and candidate** in a read-only validation job. The job
   has no network egress for the container and only read GitHub/registry scope.
   Static checks select the pinned root's exact `linux/amd64` image and record
   runtime configuration. Live validation follows the inventory `http`, `process`,
   or `oneshot` profile and observes an image-defined healthcheck when present.
   HTTP probes use runner curl through `sudo -n nsenter` in the candidate's network
   namespace. CI checks these host tools before validation. No probe image or
   published host port is required.
2. **Resolve immutable identities**: the pinned upstream index or image manifest,
   its exact `linux/amd64` image, the append-only internal tag, and any existing
   same-candidate revision.
3. **Scan the child twice with one frozen scanner database**: a full report with
   every severity and unfixed finding, plus a fixable-OS-only report. Their
   receipts must match the same scanner, database, artifact, image ID, manifest
   digest, and report bytes.
4. **Patch when policy is enabled and the fixable-OS report is nonempty**, from
   the original child only. Digest-pinned Copa v0.15.0 performs stable comprehensive
   OS updates without a report argument; the fixable report remains trigger and
   evidence, with no severity cutoff. Add only `base.digest`, `base.name`, `source`, and `version`
   labels; all pre-existing runtime configuration and labels must be preserved.
   Rescan the exact patched bytes with the frozen database.
5. **Evaluate one strict candidate decision.** Validation, Copa classification,
   CVE delta, package delta, scanner-severity evidence, KEV evidence, exact
   acceptance evidence, and identity must pass. A failed decision is retained with
   its artifact after every downstream publication gate has been withheld.
6. **Publish only the final candidate manifest** digest-preservingly from the
   checksum-bound artifact. Assert the pushed digest, byte-identical non-index
   manifest, and anonymous read. The publisher is the only write-capable job.
7. **Generate, merge, and re-read new provenance**, then publish the final decision
   only after the public record on `main` matches the run, tag, digest, policy,
   scan, validation, and artifact identities. Reuse retains and reverifies the
   existing record instead of replacing it.

## Stable Copa v0.15.0 capability reference

The reviewed release is [v0.15.0](https://github.com/project-copacetic/copacetic/releases/tag/v0.15.0),
commit `bce7b4305e378558f20420aa2ca48686cec850d0` (2026-09-04).
Its [dispatcher](https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/pkgmgr/pkgmgr.go)
recognizes exactly `alpine`, `debian`, `ubuntu`, `cbl-mariner`, `azurelinux`,
`centos`, `oracle`, `redhat`, `rocky`, `amazon`, `alma`, `almalinux`, `sles`,
`opensuse-leap`, `opensuse-tumbleweed`, and `archlinux`.

| Distribution / package layout | Stable comprehensive route | Limits and evidence |
|---|---|---|
| Alpine native apk | Native manager | Missing target tools unsupported. |
| Debian / Ubuntu native apt and dpkg | Native manager | Full independent inventory and current repositories required. |
| Debian external status directory | External archives and encoded status entries | Preserve scanner-visible status representation. |
| Ubuntu apt-less full dpkg status | External archives, scripts/triggers disabled | Residual administrative state and lifecycle-dependent updates rejected. |
| Ubuntu native Chisel manifest | Re-cut slices, preserve unmanaged paths | Native inventory capsules bind real OCI files and manifest rows to signed Ubuntu package indexes and a frozen-DB Trivy SBOM scan. Empty image scans alone cannot qualify this route. Only public archives; Pro/ESM/FIPS/private archives unsupported. |
| CBL-Mariner / Azure Linux / CentOS / Oracle / Red Hat / Rocky / Amazon / AlmaLinux native RPM | tdnf/dnf/yum/microdnf | Selected tooling routes require real full-gate evidence. |
| RPM DB present, manager absent | dnf chroot with target repositories | Compatible tooling and complete independent scan inventory required. |
| RPM external manifests | External archive merge and metadata | Independently verify actual package identity and versions. |
| SLES / openSUSE Leap / Tumbleweed | zypper chroot | Each selected layout requires a compatible real receipt. |
| Oracle report input | Comprehensive exists; targeted rejected | Do not enable ignore-errors to bypass report-driven rejection. |
| Arch Linux native pacman | Native manager | Exact scanner ecosystem and epoch/release comparison need retained real receipts before admission. |
| Scratch / missing supported package metadata | No package-manager route | Unresolved application/binary findings remain in the full report and policy. |

Source contracts: [dpkg](https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/pkgmgr/dpkg.go),
[RPM](https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/pkgmgr/rpm.go),
[apk](https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/pkgmgr/apk.go),
[pacman](https://github.com/project-copacetic/copacetic/blob/v0.15.0/pkg/pkgmgr/pacman.go),
and [Chisel layouts](https://github.com/project-copacetic/copacetic/blob/v0.15.0/website/docs/chiseled-images.md).
This release matrix is reference material. Qualify only routes required by admitted images.
Source support is not qualification. No generic targeted fallback is enabled:
all recognized managers have a comprehensive route, and unsafe failures block.
A future targeted-only route needs an observed exact-release limitation and a
retained reason before enabling report input. Experimental application/library,
Go rebuild and Helm flags remain disabled; stable OS scope is the default.

The shared candidate seam uses the existing digest-pinned action runtime with its
reviewed `/usr/local/bin/copa`, Docker socket and isolated `buildx://copa-action`
connection, an explicit Docker loader, `copa:candidate`, and a 30-minute timeout.
The report-only entrypoint is overridden; CLI version and runtime identity are
checked before/after. No retry switches modes. Full reports, frozen DB receipts,
package/CVE/config/functional validation, KEV, SBOM and signing gates remain mandatory.
Claimed patch success requires nonempty independent before/after OS inventories
and every original package identity retained. Clean, unchanged package-free
images retain their existing acceptance handling.

Real immutable-child Trivy 0.74.0 scans establish RPM package components for
`cbl-mariner` (69 packages), `azurelinux` (79) and `sles` 16.0 (105); these exact
identifiers use the existing RPM comparator. The observed SLES 15.6 scan is EOL
and remains blocked. SLES 16 signing keys retain their actual version, architecture
and PURL under immutable RPM key identities. Every key remains in the inventory;
key removal, duplicate corruption and ordinary package ambiguity still block.
Epoch/release components, unchanged versions and downgrades are checked independently. These inventory scans establish comparator inputs,
not successful patch qualification. No guessed openSUSE aliases are admitted.
Arch scanner admission is unavailable. Arch OS reports fail closed without dedicated independent evidence.
Unknown evidence and incomplete patch coverage fail closed; upstream recognition
or synthetic fixtures do not count as family qualification.
The pinned runtime/BuildKit execution and each live layout still require isolated
hosted qualification; local command-contract checks do not establish that proof.

Native inventory capsules remain mandatory when a report claims SBOM-derived OS packages.
The evaluator, publisher and accepted-candidate resume verify their OCI, package,
scanner and frozen-database bindings. Missing or tampered evidence blocks admission.
Native Chisel scan orchestration is unavailable. An empty OS scan cannot establish clean inventory.

## Identity and reuse

New records are exactly `linux/amd64`. Inventory keeps the upstream root digest
so Renovate continues to see upstream changes. An index must contain exactly one
selected child. A single image manifest is its own selected child, with identical
original bytes. Both paths verify the manifest/config hashes and sizes and require
a `linux/amd64` config before image execution. A clean promotion's internal manifest digest equals
the selected child. A patched promotion is the new manifest produced from that
child.

If the upstream index digest changes while the selected child remains unchanged,
normal dispatch reuses the existing revision, refreshes evidence, and does not
copy or sign the child again. An eligible signed revision is strictly reverified
against its existing public record, which retains its original successful run and
SBOM; refreshed current reports remain run artifacts. After current candidate
checks pass, normal reuse of an unsigned or quarantined revision warns and skips
the publisher without changing eligibility or public evidence. Use
`force_repromote=true` to allocate a new revision. Malformed evidence and actual
policy, validation or cryptographic failures still fail the run.
A newer upstream release outranks an older local patched
revision; the controlled seven-day fallback below is the explicit backup when
real Renovate detection has not appeared.

Existing image tags/manifests and Git audit history remain immutable. Each app
has one `provenance/<app>/current.json`, replaced only by a valid new signed
publication. Exact older records remain available through merged Git history.

## Policy truth table

| Candidate result | Outcome |
| --- | --- |
| No fixable OS finding and no KEV match | Eligible as clean. |
| One or more fixable OS findings, policy enabled | Run Copa from the original child regardless of severity. Eligible only when every supplied finding disappears, no CVE is introduced, no OS package is downgraded, and validation passes. |
| No-fix finding at any severity, no KEV match | Eligible with a prominent warning retaining CVE, package, severity, and `SeveritySource`. |
| Any final KEV match | Eligible only with an exact, unexpired, merged risk record; otherwise blocked. |
| Disabled policy and a structured `unsupported` or `no-fix` reason | Eligible with warnings after all other gates pass. |
| EOL, GPG failure, unknown Copa failure, pending fixable work, or any other unsafe classification | Blocked. |
| Newly introduced CVE, unresolved supplied fixable CVE, OS-package downgrade, or failed validation | Blocked. This is the patched-image-broken / invalid-candidate branch. |

Fail-open patching is not implemented. Scanner `SeveritySource` is retained;
policy does not recompute severity from another score source.

## Risk acceptance lifecycle

KEV evidence comes from the canonical CISA catalog fetched in the run, validated
for schema, count, unique CVEs, hash, and a maximum receipt age of 24 hours.
Any match blocks promotion until the following record exists and is still valid.

Store one JSON record at
`risk-acceptances/<app>/<sha256(candidateDigest)>-<sha256(newline-joined-sorted-kevs)>.json`.
Its exact fields are:

- `schema`: `trusted-images.bocklabs.dev/risk-acceptance-v1`
- `candidateDigest`: exact candidate `sha256:...`
- `kevs`: nonempty, sorted, unique, exact matched CVE IDs
- `reason`: nonempty rationale
- `expiresAt`: strict UTC timestamp
- `likelihood`: `LOW`, `MEDIUM`, or `HIGH` plus rationale
- `impact`: `LOW`, `MEDIUM`, or `HIGH` plus rationale
- `owner`: accountable owner
- `reviewNotes`: nonempty string array
- `trackingIssue`: positive issue number

Merge the record by PR to `main`. Any collaborator with merge rights, including
the author, may perform the merge; GitHub's merge identity is authoritative. The
record may be at most seven days old at expiry, so a `seven-day` maximum starts at
merge time and a shorter period is allowed. The tracking issue must exist, be a
real issue rather than a PR, and remain open.

Renew by editing the same path through a new PR after a fresh scan confirms the
same digest and KEV set; old history remains. Revoke early by PR-removing the
record. A missing record is treated as revocation only for a GitHub Contents 404;
every other lookup failure blocks. Acceptance clears only the KEV gate. It never
clears validation, patch integrity, platform mismatch, classification, or
publication-integrity failure.

To resume, run with `accepted_candidate_run_id`. The workflow independently
verifies the original run, attempt, source SHA, artifact, checksums, OCI bytes,
inventory/index/child/tag/decision bindings, current acceptance, fresh scans,
fresh KEV evidence, and validation before the write-capable publisher receives it.

## Evidence and provenance

The candidate decision is `candidate-decision-v1` with strict top-level groups:
identity (`app`, `source_sha`, run, attempt, proposed tag, index, selected child,
candidate digest), `before.fixable_os`, `copa`, `delta`, `packages`,
`patching`, `policy`, `validation`, `resume`, `published`, `provenance`, and
`supersedes`. Delta identities are `platform|package|CVE`; language findings scope
the middle field as colon-separated percent-encoded class, ecosystem, target and
package. OS identities stay unchanged; provenance retains the raw package name.
Grouped CVE summaries name resolved, remaining, introduced, and unresolved-fixable sets. Package
changes carry ecosystem, name, direction, and both versions.

Retained artifacts include validation context/evidence and container logs; the
full report, fixable-OS report, before/final report identities, converted report,
KEV report, upload manifest, Copa diagnostics when applicable; the checksum-bound
OCI candidate and decision; publication digest; and the final candidate decision.

Provenance is one machine-generated `provenance/<app>/current.json` per app.
Verified new publication opens or updates the release-App-owned
`provenance/current/<app>` branch and PR, enables exact-head auto-merge through
genuine required checks, and then
releases the application workflow lock. The retained decision stays
`provenance.merged=false`; a green publication handoff is pending merge and
ineligible for consumption. Only exact generated bytes already on public `main`
permit the final merged-decision assertion. Deployment is a separate operator
action. Same current tag/digest still passes the existing publisher cryptographic
verification, but changing daily run/database/Copa/no-fix metadata creates no
record write or PR. Historical `recover_tag` and reuse resolve exact original
records from an immutable merged-main commit and its ancestors; they cannot
replace newer current. Failed/quarantined runs retain full generated provenance
in run artifacts and never replace good current or create auto-merging PRs.
Legacy unsigned current bytes remain explicitly unverified, without fabricated
signing eligibility. Signing failures stay red.
It binds upstream
index and selected child, internal package/tag/digest/platform, run and dispatch
identity, tools and scanner database, report/decision hashes, generic findings
service upload identity, complete policy and KEV catalog, exact acceptance fields,
CVE/package delta, validation evidence and baseline, recovery linkage when
applicable, and final publication state. Acceptance evidence in provenance carries
candidate digest, exact KEV set, record path/commit, merged PR and approver,
tracking issue, and `expires_at`. After expiry, the image and history remain, but
new promotion and current eligibility require a fresh valid acceptance.

New records also retain Copa mode (`not-required`, `comprehensive`, or `targeted`)
and the exact release, CLI source commit and runtime digest from candidate evidence.
Targeted mode requires its exact-release limitation; no targeted fallback is
enabled. Automatic records bind the canonical need hash. Historical record bytes
remain immutable; a resumed patched candidate lacking actual mode evidence cannot
create a new record by inventing execution evidence.

Publication-integrity assertions require exact manifest bytes and anonymous
readability. If the registry creates a package private by default, the anonymous
probe fails by design; make the one-time package visibility change, then rerun.

## Inventory promotion

Dispatch only reviewed inventory entries under the applicable authorization.

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app>
```

For a real KEV-blocked candidate, the post-acceptance resume uses:

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app> -f accepted_candidate_run_id=<original-run-id>
```

## Credentials and configuration

The validation job is read-only for contents, actions, packages, pull requests,
and issues. The promotion job alone holds package and provenance write scope and
uses the configured release App to open/merge provenance PRs. Candidate artifacts
cross that boundary only through checksum-verified artifact handoff; scans and
candidate work never receive publisher credentials.

Optional read-only Docker Hub credentials apply to upstream pulls. Optional
generic findings-service configuration supplies only a public link in the run
summary; no findings-service credential is used by this workflow.

## Python tooling

`.python-version` pins the repository tooling interpreter to Python 3.14.
The `pyenv` Renovate rule disables interpreter updates to preserve Python 3.14.
`inventory/python/image.yaml` independently pins the Python 3.14 Alpine image and
its native version check. Signed provenance describes the image actually published
and changes only through promotion, not when the tooling interpreter changes.

`pyproject.toml` declares runtime and development dependencies; `uv.lock` pins
resolved versions. Run `uv sync --locked`, then `uv run --locked pre-commit run
--all-files`. CI uses the same environment. Renovate updates project dependencies
and their lockfile; no Python package versions are declared in workflow steps.
