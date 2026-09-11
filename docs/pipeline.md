# The promotion pipeline

How an inventory entry becomes a published image in
`ghcr.io/bocklabs/*`, and what one run of the `promote` workflow
guarantees. Operator-facing; nothing here is required reading to
consume a promoted image — only to produce one.

## Dispatching a promotion

Every inventory entry is promotable. Choose exactly one of these modes;
all three run the same validation, scans, verification, artifact export,
and provenance path.

**Normal** tracks the inventory's current pinned content. If that digest
already has an internal revision, the workflow verifies and reuses the
newest matching revision without copying it again. Otherwise it publishes
the next append-only revision.

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app>
```

**Force repeat** explicitly publishes the same pinned content under the
next append-only revision. It changes allocation only; it never moves an
existing tag.

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app> -f force_repromote=true
```

**Recovery** repairs one exact published revision after a partial run. It
never copies or rewrites the tag. The workflow obtains the original run
and immutable inventory snapshot from the revision's merged provenance.
If publication succeeded before provenance was created, supply that
original numeric run ID explicitly.

```sh
gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app> -f recover_tag=<tag>-bocklabs.<N>

gh workflow run promote.yaml --repo bocklabs/trusted-images --ref main \
  -f app=<app> -f recover_tag=<tag>-bocklabs.<N> -f recovery_run_id=<run-id>
```

`force_repromote` and `recover_tag` are mutually exclusive. Dispatching
a promotion is the acceptance decision: there is no separate approval
stage or scan-only mode.

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
4. **Select the internal tag** — normal mode reuses the newest revision
   already carrying the pinned digest, force mode allocates the next
   numeric revision, and recovery selects the requested existing revision.
   Complete paginated registry observations and valid manifest digest
   responses are required; failures never become an empty package.
5. **Scan twice with one scanner database**: a full vulnerability
   report (all severities, unfixed included) and a fixable-OS-only
   report. Both scans use the same pinned scanner version and the same
   database, which is asserted by comparing database metadata captured
   after each scan. The full report is converted to the findings
   service's import format with a conversion-parity check.
6. **Export candidate evidence** — the full report, converted report,
   fixable-OS report, and `secobserve-upload.json` manifest are retained as
   run artifacts for the existing evidence bridge. The workflow does not
   perform an inline findings-service upload.
7. **Copy the image** digest-preserving, registry to registry, into
   the destination package under the computed tag.
8. **Verify** that the selected destination digest equals the upstream
   pinned digest and that its platform set matches the upstream platform
   set. These checks also run when copy is skipped or a revision is recovered.
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

Ordinary dispatches are idempotent. If the destination package already
holds the exact upstream digest under an existing `<tag>-bocklabs.N`
tag, the run verifies it and refreshes the scans, artifacts, and
provenance without re-copying anything. Use `force_repromote=true` only
when a distinct next revision is required for unchanged content.

Recovery is also append-only: it requires the requested public tag to
exist at the original pinned digest, reruns current trusted workflow code
against the original immutable inventory data, and records a new run as
the successful evidence. The old run is retained as linkage; it is never
relabelled successful. Eligibility begins only after the new run succeeds
and its updated provenance record merges into `main`.

## If the first push arrives private

The registry creates a package private by default; the anonymous-pull
probe fails the run **by design**. This is the one designed manual
step: perform the one-time visibility flip to public in the package
settings, then re-dispatch. The re-run takes the idempotent-skip path
and the probe passes. The flip is permanent — it happens at most once
per package.

## Provenance

Every successful promotion ends with a pull request adding or updating the
single JSON record for its internal tag under `provenance/`. The record is
machine-generated by the run and carries: the upstream ref, tag, and
digest; the internal package, tag, digest, and platform list; the
promotion run URL; tool versions (scanner, scanner action, copy tool);
the scanner database digest; SHA-256 hashes of both scan reports; and
the generic candidate-evidence identity. Recovery records additionally
retain the original run URL and source commit plus the recovered tag and
digest, while `pipeline.run_url` identifies the new recovery run. Existing
open provenance branches and pull requests are updated under a verified
lease; already-merged or no-diff records are handled without broad staging.
The pull request merges automatically once its inventory-validity check passes.

## Configuration

The workflow uses these existing repository settings:

| Name | Kind | Purpose |
| ---- | ---- | ------- |
| `RELEASE_CLIENT_ID` | secret | Existing release App client ID for provenance pull requests |
| `RELEASE_APP_KEY` | secret | Existing release App private key for provenance pull requests |
| `DOCKERHUB_USERNAME` | variable | Read-only pulls when an upstream lives on Docker Hub |
| `DOCKERHUB_TOKEN` | secret | Read-only pulls when an upstream lives on Docker Hub |
| `SECOBSERVE_API_BASE_URL` | variable | Optional findings-service link in the run summary |

The Docker Hub credentials need read-pull scope only; the token is
used exclusively for scanning and copying upstream images. Candidate
evidence leaves this workflow only through its generic artifacts; no
findings-service credential is used here.
