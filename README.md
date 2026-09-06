<div align="center">

# trusted-images

**A declarative, digest-pinned inventory and promotion pipeline — external images are untrusted until promoted**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

</div>

## What this repo is

This repository is a supply-chain control plane. It holds a declarative,
digest-pinned inventory of every consumed upstream container image — one
folder per image under `inventory/`, each entry at `image.yaml` — and the
configuration that tracks those upstreams for version bumps and same-tag
digest drift. External images are untrusted until promoted: promotion
means an image has passed the security pipeline and been published to
`ghcr.io/bocklabs/*`. An inventory entry is a statement that an upstream
image is *tracked*, never that it is trustworthy (see
[ADR-001](docs/adr/001-trusted-images-repo-purpose.md)).

## How promotion works

The promotion path for every inventory entry is:

```
upstream ref (digest-pinned)
  -> pull
  -> security scan (Trivy)
  -> optional automated patch (Copacetic) + rescan verification
  -> generic validation (start, stay running, healthcheck, architecture)
  -> promote to ghcr.io/bocklabs/<app> (public)
  -> anonymous-pull probe (a package not publicly readable fails the run)
```

Upstream tracking is fully live: Renovate watches every inventory entry
and opens pull requests on upstream version bumps and same-tag digest
drift, with no automerge — every bump is reviewed by a human because
each merge gates a future promotion. The automated promotion workflow
itself lands in this repository's next phase; until then the inventory,
the tracking configuration, and the validation CI are live.

## Inventory format

One folder per image, directly under `inventory/`; the entry lives at
`image.yaml` (schema v1). Fields:

| Field | Meaning |
| ----- | ------- |
| `apiVersion` | `trusted-images.bocklabs.dev/v1` |
| `kind` | `Image` |
| `metadata.name` | image name; must equal the folder name |
| `spec.upstream.ref` | upstream registry/repository |
| `spec.upstream.tag` | upstream tag (tracked, never trusted alone) |
| `spec.upstream.digest` | pinned `sha256:` digest of that tag |
| `spec.destination.package` | `ghcr.io/bocklabs/<name>` |
| `spec.patchPolicy` | `enabled` or `disabled` (with recorded reason) |
| `spec.validationProfile` | validation profile name (`process`, `http`, `oneshot`) |
| `spec.version` | schema version; `1` |

Example — the pilot entry, `inventory/postgres-exporter/image.yaml`:

```yaml
apiVersion: trusted-images.bocklabs.dev/v1
kind: Image
metadata:
  name: postgres-exporter
spec:
  upstream:
    ref: quay.io/prometheuscommunity/postgres-exporter
    tag: v0.20.1
    digest: sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e
  destination:
    package: ghcr.io/bocklabs/postgres-exporter
  patchPolicy: enabled
  validationProfile: http
  version: 1
```

Every entry is validated on every pull request by
`scripts/validate_inventory.py` (schema, digest format, enums,
folder-name consistency).

## Policies

- **Public packages, permanently.** Every `ghcr.io/bocklabs/*` package
  is public and anonymously readable, permanently. Each promotion run
  ends with an unauthenticated pull probe — a package left private at
  run end equals a failed promotion
  ([ADR-002](docs/adr/002-ghcr-public-visibility-model.md)).
- **GitHub-hosted runners only.** All CI runs on `ubuntu-latest`;
  untrusted-image work never runs on self-hosted infrastructure, and a
  guard step fails any pull request that introduces a self-hosted runner
  label ([ADR-004](docs/adr/004-github-hosted-runners-permanent.md)).
- **No automerge on inventory PRs.** Every upstream bump is manually
  reviewed because each merge gates a future promotion run.
- **Decisions are recorded.** Every day-one decision is committed as an
  architecture decision record under `docs/adr/` (index below).

## Decision records

| ADR | Decision |
| --- | -------- |
| [ADR-001](docs/adr/001-trusted-images-repo-purpose.md) | Trusted-images repository purpose |
| [ADR-002](docs/adr/002-ghcr-public-visibility-model.md) | GHCR public visibility model |
| [ADR-003](docs/adr/003-internal-tag-scheme-and-renovate-versioning.md) | Internal tag scheme and Renovate versioning |
| [ADR-004](docs/adr/004-github-hosted-runners-permanent.md) | GitHub-hosted runners, permanently |
| [ADR-005](docs/adr/005-secobserve-product-origin-naming.md) | SecObserve product and origin naming |

## License

[MIT](LICENSE)
