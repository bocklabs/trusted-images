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
image is *tracked*, never that it is trustworthy.

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

Upstream tracking is fully live and automated end to end: Renovate
watches every inventory entry and opens pull requests on upstream
version bumps and same-tag digest drift; each PR carries the
`validate / inventory` check, and on green it merges automatically —
no human in the loop.

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

## Usage

**Validate locally** — the same check CI runs on every PR:

```bash
pip install PyYAML==6.0.3
python scripts/validate_inventory.py
```

Output `OK: inventory valid` (exit 0) means every entry passes schema,
digest-format, uniqueness, and folder-name checks.

**Add a tracked image** — create `inventory/<name>/image.yaml` using the
format above (pin the current digest of the tag you track), then open a
pull request. CI validates the entry; once merged, Renovate picks it up
on its next run and keeps it current from then on.

**How updates flow** — when an upstream publishes a new version or
re-points an existing tag, Renovate opens a PR updating the entry's
`tag` and `digest`. The `validate / inventory` check runs on the PR and
it merges automatically on green. Digests are always pinned: an update
is always an explicit, reviewable diff in git history, never a floating
tag.

**Drift guard** — `tests/renovate-manager-match.mjs` fails if the
Renovate manager regex and the inventory schema drift apart (Renovate
silently matching nothing). Run it with `node
tests/renovate-manager-match.mjs`.

## License

[MIT](LICENSE)
