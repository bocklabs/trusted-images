# The promotion pipeline

How an inventory entry becomes a published image in
`ghcr.io/bocklabs/*`, and what one run of the `promote` workflow
guarantees. Operator-facing; nothing here is required reading to
consume a promoted image — only to produce one.

## Dispatching a promotion

Open the repository's **Actions** tab, select the **promote** workflow,
and run it with one input: the inventory folder name (the app). Every
inventory entry is promotable — the workflow is fully parameterized,
not specific to any image. Dispatching a promotion **is** the
acceptance decision: there is no separate approval stage and no
scan-only dry-run mode. One dispatch runs the complete pipeline once,
end to end, and the run either succeeds completely or fails with the
reason named in its log and summary.

## What one run does

The steps run in a fixed order; each one's failure stops the run
before anything downstream happens.

1. **Validate the candidate** — a separate job that runs first: the
   image is checked statically and executed live according to its
   validation profile (see Validation below). A failed validation ends
   the run before any of the steps below start.
2. **Resolve** the inventory entry for the dispatched app — upstream
   registry/repository, tracked tag, pinned digest, destination
   package.
3. **Fetch the upstream index** at the pinned digest and record its
   media type and platform set (the expected values for later
   assertions).
4. **Compute the internal tag** — the next `<tag>-bocklabs.N` revision
   on the destination package. Never-promoted versions start at `.1`;
   existing tags are never overwritten or moved.
5. **Scan twice with one scanner database**: a full vulnerability
   report (all severities, unfixed included) and a fixable-OS-only
   report. Both scans use the same pinned scanner version and the same
   database, which is asserted by comparing database metadata captured
   after each scan. The full report is converted to the findings
   service's import format with a conversion-parity check.
6. **Upload the full report** to the findings service under the
   candidate identity — **before** anything is pushed. A promoted
   image with no scan evidence cannot exist.
7. **Copy the image** digest-preserving, registry to registry, into
   the destination package under the computed tag.
8. **Verify** that the pushed digest equals the upstream pinned digest
   and that the pushed platform set matches the upstream platform set.
9. **Probe** the published package anonymously — a manifest fetch
   without any credentials must succeed and return the expected
   digest.

## Invariants

Each invariant is enforced by a fail-closed assertion that names the
invariant when it fails. A run that ends green has all of them:

- **Digest equality** — the published package's digest is exactly the
  upstream pinned digest.
- **Platform-set equality** — every upstream platform is present, and
  nothing extra.
- **Single-DB scan evidence** — both reports were produced by the same
  pinned scanner database.
- **Anonymous readability** — the published package pulls without any
  credential; public visibility is part of the promotion contract.

## Validation

Every dispatch validates the candidate image before the promotion job
starts. Validation is its own job with a minimal environment: the
candidate container runs with no network egress, and the job holds
nothing but optional read-only pull credentials for the upstream
registry. A failed validation ends the run right there — no scan, no
report upload, no copy; nothing downstream happens.

Validation has a static half and a live half.

The static half checks the image index and the image configuration.
The platform expectation uses subset semantics: every expected platform
must be present in the image's platform set, and additional platforms
are allowed — which is what makes a multi-arch image promotable against
a single-platform expectation. The image configuration must parse, and
its entrypoint, command, and environment are recorded into the
provenance record as the baseline for the promotion.

The live half executes the image. One liveness contract covers all
three profiles, and the profile is selected per image in the inventory
entry's `validation` block — the entry names the type plus only the
deviations from the defaults:

- **http** — a web-serving image must answer on its port within the
  timeout and still be running at the end of the window.
- **process** — a long-running image must still be running through the
  window.
- **oneshot** — a one-shot image must exit within its timeout with
  exactly the expected exit code.

Health is observed, not assumed. When the image defines its own
healthcheck, the container must become healthy within the window or
validation fails. When it defines none, the profile check alone gates,
and the validation evidence says so rather than inventing a health
expectation.

## Re-running a promotion

Dispatches are idempotent. If the destination package already holds
the exact upstream digest under an existing `<tag>-bocklabs.N` tag,
the run verifies it and refreshes the evidence (scans, upload,
provenance) without re-copying anything. Re-dispatching after a
partial failure is always safe.

## If the first push arrives private

The registry creates a package private by default; the anonymous-pull
probe fails the run **by design**. This is the one designed manual
step: perform the one-time visibility flip to public in the package
settings, then re-dispatch. The re-run takes the idempotent-skip path
and the probe passes. The flip is permanent — it happens at most once
per package.

## Provenance

Every successful promotion ends with a pull request adding one JSON
record per internal tag under `provenance/`. The record is
machine-generated by the run and carries: the upstream ref, tag, and
digest; the internal package, tag, digest, and platform list; the
promotion run URL; tool versions (scanner, scanner action, copy tool);
the scanner database digest; SHA-256 hashes of both scan reports; and
the findings-service identity the report was uploaded under. The pull
request merges automatically once its inventory-validity check passes.

## Configuration

The workflow expects four names to exist on the repository — no other
setup:

| Name | Kind | Purpose |
| ---- | ---- | ------- |
| `SECOBSERVE_API_TOKEN` | secret | Upload to the findings service (SecObserve) |
| `DOCKERHUB_USERNAME` | secret | Read-only pulls when an upstream lives on Docker Hub |
| `DOCKERHUB_TOKEN` | secret | Read-only pulls when an upstream lives on Docker Hub |
| `SECOBSERVE_API_BASE_URL` | variable | Findings service API base URL |

The Docker Hub credentials need read-pull scope only; the token is
used exclusively for scanning and copying upstream images.
