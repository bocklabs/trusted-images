#!/usr/bin/env python3
"""Generate the provenance record for one promoted internal image.

One promotion run renders its full evidence set into a single provenance-v1
JSON file (one file per internal tag under provenance/<app>/).

Fail-closed: every input is validated BEFORE anything is written. All
violations are collected and printed — one line per violation, each prefixed
[provenance] and naming the offending field — and the run exits 1 without
creating or modifying the output file. No value is ever invented: every
field in the record comes from a flag captured during the run that produced
the image.

stdlib only.
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "trusted-images.bocklabs.dev/provenance-v1"
PACKAGE_PREFIX = "ghcr.io/bocklabs/"
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
BARE_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")

# flag -> (kind, required); kind: text | digest (sha256:<64hex>) | sha256 (bare 64-hex)
FLAGS: dict[str, tuple[str, bool]] = {
    "--app": ("text", True),
    "--upstream-ref": ("text", True),
    "--upstream-tag": ("text", True),
    "--upstream-digest": ("digest", True),
    "--media-type": ("text", True),
    "--internal-package": ("text", True),
    "--internal-tag": ("text", True),
    "--internal-digest": ("digest", True),
    "--platforms": ("text", True),
    "--run-url": ("text", True),
    "--workflow": ("text", True),
    "--dispatched-by": ("text", True),
    "--trivy-version": ("text", True),
    "--trivy-action-sha": ("text", True),
    "--skopeo-version": ("text", True),
    "--skopeo-image-digest": ("digest", True),
    "--trivy-db-check-bundle-digest": ("digest", True),
    "--trivy-db-updated-at": ("text", True),
    "--full-report-sha256": ("sha256", True),
    "--copa-report-sha256": ("sha256", True),
    "--secobserve-product": ("text", True),
    "--secobserve-origin": ("text", True),
    "--notes": ("text", False),
    "--out": ("text", True),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write one provenance-v1 record for a promoted internal image.",
    )
    for flag in FLAGS:
        parser.add_argument(flag, default="" if flag == "--notes" else None)
    return parser.parse_args()


def value_of(args: argparse.Namespace, flag: str) -> str:
    value = getattr(args, flag.lstrip("-").replace("-", "_"))
    return value if isinstance(value, str) else ""


def collect_violations(args: argparse.Namespace) -> list[str]:
    """Every rule violation, one line each naming the offending field."""
    violations: list[str] = []

    for flag, (kind, required) in FLAGS.items():
        value = value_of(args, flag)
        if required and not value.strip():
            violations.append(f"missing required value for {flag} ({flag.lstrip('-')})")
            continue
        if kind == "digest" and value.strip() and not DIGEST_RE.fullmatch(value):
            violations.append(
                f"{flag} must be sha256: followed by 64 lowercase hex digits (got {value!r})"
            )
        if kind == "sha256" and value.strip() and not BARE_SHA256_RE.fullmatch(value):
            violations.append(
                f"{flag} must be bare 64-hex sha256sum output, no sha256: prefix (got {value!r})"
            )

    app = value_of(args, "--app")
    package = value_of(args, "--internal-package")
    if app.strip() and package.strip() and package != f"{PACKAGE_PREFIX}{app}":
        violations.append(
            f"--internal-package must be '{PACKAGE_PREFIX}{app}' (got {package!r})"
        )

    upstream_tag = value_of(args, "--upstream-tag")
    internal_tag = value_of(args, "--internal-tag")
    if upstream_tag.strip() and internal_tag.strip():
        tag_re = re.compile(re.escape(upstream_tag) + r"-bocklabs\.\d+")
        if not tag_re.fullmatch(internal_tag):
            violations.append(
                f"--internal-tag must be '{upstream_tag}-bocklabs.N' "
                f"with N a positive integer (got {internal_tag!r})"
            )

    platforms_raw = value_of(args, "--platforms")
    if platforms_raw.strip():
        platforms = [part.strip() for part in platforms_raw.split(",")]
        if not all(platforms):
            violations.append(
                f"--platforms must be a comma-separated list of non-empty platforms "
                f"(got {platforms_raw!r})"
            )

    return violations


def build_record(args: argparse.Namespace, platforms: list[str]) -> dict:
    return {
        "schema": SCHEMA,
        "app": value_of(args, "--app"),
        "upstream": {
            "ref": value_of(args, "--upstream-ref"),
            "tag": value_of(args, "--upstream-tag"),
            "digest": value_of(args, "--upstream-digest"),
            "media_type": value_of(args, "--media-type"),
        },
        "internal": {
            "package": value_of(args, "--internal-package"),
            "tag": value_of(args, "--internal-tag"),
            "digest": value_of(args, "--internal-digest"),
            "platforms": platforms,
        },
        "pipeline": {
            "run_url": value_of(args, "--run-url"),
            "workflow": value_of(args, "--workflow"),
            "dispatched_by": value_of(args, "--dispatched-by"),
        },
        "tools": {
            "trivy": value_of(args, "--trivy-version"),
            "trivy_action": value_of(args, "--trivy-action-sha"),
            "skopeo": value_of(args, "--skopeo-version"),
            "skopeo_image_digest": value_of(args, "--skopeo-image-digest"),
        },
        "scan": {
            "trivy_db": {
                "check_bundle_digest": value_of(args, "--trivy-db-check-bundle-digest"),
                "updated_at": value_of(args, "--trivy-db-updated-at"),
            },
            "full_report_sha256": value_of(args, "--full-report-sha256"),
            "copa_report_sha256": value_of(args, "--copa-report-sha256"),
            "secobserve": {
                "product": value_of(args, "--secobserve-product"),
                "origin": value_of(args, "--secobserve-origin"),
            },
        },
        "promoted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "notes": args.notes,
    }


def main() -> int:
    args = parse_args()

    violations = collect_violations(args)
    if violations:
        for line in violations:
            print(f"[provenance] {line}")
        return 1

    platforms = [part.strip() for part in value_of(args, "--platforms").split(",")]
    record = build_record(args, platforms)

    out = Path(value_of(args, "--out"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
