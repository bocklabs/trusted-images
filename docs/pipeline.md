# The promotion pipeline

How one generic inventory entry becomes one immutable image in the public
destination namespace, and what a completed `promote` run proves. This is the
producer runbook. It contains no deployment-side configuration or private
infrastructure details.

## Operator dispatch modes

The `promote` workflow is dispatch-only. Choose exactly one mode; normal, force,
recovery, and accepted-resume use the same validation, scanning, policy, artifact,
publication, and provenance gates. A run is initiated only by an authorized
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

## Fixed run order

Each gate fails the run before downstream work.

1. **Validate inventory and candidate** in a read-only validation job. The job
   has no network egress for the container and only read GitHub/registry scope.
   Static checks select the upstream index's exact `linux/amd64` child and record
   runtime configuration. Live validation follows the inventory `http`, `process`,
   or `oneshot` profile and observes an image-defined healthcheck when present.
2. **Resolve immutable identities**: the pinned upstream index, its exactly one
   selected `linux/amd64` child, the append-only internal tag, and any existing
   same-candidate revision.
3. **Scan the child twice with one frozen scanner database**: a full report with
   every severity and unfixed finding, plus a fixable-OS-only report. Their
   receipts must match the same scanner, database, artifact, image ID, manifest
   digest, and report bytes.
4. **Patch when policy is enabled and the fixable-OS report is nonempty**, from
   the original child only. Pinned Copa receives every supplied finding without a
   severity cutoff. Add only `base.digest`, `base.name`, `source`, and `version`
   labels; all pre-existing runtime configuration and labels must be preserved.
   Rescan the exact patched bytes with the frozen database.
5. **Evaluate one strict candidate decision.** Validation, Copa classification,
   CVE delta, package delta, scanner-severity evidence, KEV evidence, exact
   acceptance evidence, and identity must pass. A failed decision is retained with
   its artifact after every downstream publication gate has been withheld.
6. **Publish only the final candidate manifest** digest-preservingly from the
   checksum-bound artifact. Assert the pushed digest, byte-identical non-index
   manifest, and anonymous read. The publisher is the only write-capable job.
7. **Generate, merge, and re-read provenance**, then publish the final decision
   only after the public record on `main` matches the run, tag, digest, policy,
   scan, validation, and artifact identities.

## Identity and reuse

New records are exactly `linux/amd64`. Inventory keeps the upstream index digest
so Renovate continues to see upstream changes; the workflow resolves and records
the selected child as well. A clean promotion's internal manifest digest equals
the selected child. A patched promotion is the new manifest produced from that
child.

If the upstream index digest changes while the selected child remains unchanged,
normal dispatch reuses the existing revision, refreshes evidence, and does not
copy the child again. A newer upstream release outranks an older local patched
revision; the controlled seven-day fallback below is the explicit backup when
real Renovate detection has not appeared.

Existing tags, manifests, provenance records, and audit history are immutable.
No retention policy in this repository deletes or overwrites them.

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
`supersedes`. Delta identities are `platform|package|CVE`; grouped CVE summaries
name resolved, remaining, introduced, and unresolved-fixable sets. Package
changes carry ecosystem, name, direction, and both versions.

Retained artifacts include validation context/evidence and container logs; the
full report, fixable-OS report, before/final report identities, converted report,
KEV report, upload manifest, Copa diagnostics when applicable; the checksum-bound
OCI candidate and decision; publication digest; and the final candidate decision.

Provenance is one machine-generated JSON record per internal tag, merged to
public `main` before the final run decision is marked complete. It binds upstream
index and selected child, internal package/tag/digest/platform, run and dispatch
identity, tools and scanner database, report/decision hashes, generic findings
service upload identity, complete policy and KEV catalog, exact acceptance fields,
CVE/package delta, validation evidence and baseline, recovery linkage when
applicable, and final publication state. Acceptance evidence in provenance carries
candidate digest, exact KEV set, record path/commit, merged PR and approver,
tracking issue, and `expires_at`. After expiry, the image and history remain, but
new promotion and generic consumer eligibility require a fresh valid acceptance.

Publication-integrity assertions require exact manifest bytes and anonymous
readability. If the registry creates a package private by default, the anonymous
probe fails by design; make the one-time package visibility change, then rerun.

## Qualification run sequence

Live dispatches are separate operator checkpoints. Review each run and public
receipt before proceeding; these commands do not themselves authorize a run.

1. Prove the deliberately stale `nginx-qualification` patch path:

   ```sh
   gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
     -f app=nginx-qualification
   ```

2. Run `distroless-static` while patching is temporarily enabled to capture its
   real unsupported/no-fix classification. Review and merge its structured
   disabled reason, then dispatch it again to prove the successful disabled-policy
   path. The two runs and their outcomes are distinct evidence.
3. Run the current `postgres-exporter` through the same producer policy after
   qualification passes.
4. Promote a genuinely newer nginx release when Renovate detects one. If no real
   update appears within the locked `seven-day` fallback window—and only after all
   other phase work is ready—use the separately reviewed controlled update to a
   known newer fixed release.

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
