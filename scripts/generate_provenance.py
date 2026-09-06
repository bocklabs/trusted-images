#!/usr/bin/env python3
"""Generate the provenance record for one promoted internal image.

One promotion run renders its full evidence set into a single provenance-v1
JSON file — the repo-side provenance record for clean promotes (one file per
internal tag under provenance/<app>/). The record carries: upstream ref/tag/
digest/media type, internal package/tag/digest/platforms, pipeline run URL +
workflow + dispatcher, tool versions (Trivy, trivy-action SHA, skopeo,
skopeo image digest), Trivy DB metadata, sha256 of both scan reports,
SecObserve product/origin identity, the promotion timestamp, and free-form
notes (e.g. D1 fallback divergence).

Fail-closed: every input is validated BEFORE anything is written. All
violations are collected and printed — one line per violation, each prefixed
[provenance] and naming the offending field — and the run exits 1 without
creating or modifying the output file. No value is ever invented: every
field in the record comes from a flag captured during the run that produced
the image.

Tag-format rule: --internal-tag must be exactly "<upstream-tag>-bocklabs.N"
(N = one or more digits, ADR-003) and --internal-package must equal
ghcr.io/bocklabs/<app> (day-one naming rule). Digest-valued flags must
match sha256: followed by 64 lowercase hex digits; the report hashes are
bare 64-hex (sha256sum output).

Usage: generate_provenance.py --app APP --upstream-ref REF --upstream-tag TAG
       --upstream-digest DIGEST --media-type TYPE --internal-package PACKAGE
       --internal-tag TAG --internal-digest DIGEST --platforms LIST --run-url URL
       --workflow NAME --dispatched-by USER --trivy-version VERSION
       --trivy-action-sha SHA --skopeo-version VERSION --skopeo-image-digest DIGEST
       --trivy-db-check-bundle-digest DIGEST --trivy-db-updated-at TIMESTAMP
       --full-report-sha256 HEX --copa-report-sha256 HEX --secobserve-product NAME
       --secobserve-origin ORIGIN [--notes TEXT] --out PATH

stdlib only.
"""

from __future__ import annotations

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

REQUIRED_FLAGS = (
    "--app",
    "--upstream-ref",
    "--upstream-tag",
    "--upstream-digest",
    "--media-type",
    "--internal-package",
    "--internal-tag",
    "--internal-digest",
    "--platforms",
    "--run-url",
    "--workflow",
    "--dispatched-by",
    "--trivy-version",
    "--trivy-action-sha",
    "--skopeo-version",
    "--skopeo-image-digest",
    "--trivy-db-check-bundle-digest",
    "--trivy-db-updated-at",
    "--full-report-sha256",
    "--copa-report-sha256",
    "--secobserve-product",
    "--secobserve-origin",
    "--out",
)

DIGEST_FLAGS = {
    "--upstream-digest": "upstream.digest",
    "--internal-digest": "internal.digest",
    "--trivy-db-check-bundle-digest": "scan.trivy_db.check_bundle_digest",
    "--skopeo-image-digest": "tools.skopeo_image_digest",
}
BARE_SHA256_FLAGS = {
    "--full-report-sha256": "scan.full_report_sha256",
    "--copa-report-sha256": "scan.copa_report_sha256",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write one provenance-v1 record for a promoted internal image.",
    )
    parser.add_argument("--app")
    parser.add_argument("--upstream-ref")
    parser.add_argument("--upstream-tag")
    parser.add_argument("--upstream-digest")
    parser.add_argument("--media-type")
    parser.add_argument("--internal-package")
    parser.add_argument("--internal-tag")
    parser.add_argument("--internal-digest")
    parser.add_argument("--platforms")
    parser.add_argument("--run-url")
    parser.add_argument("--workflow")
    parser.add_argument("--dispatched-by")
    parser.add_argument("--trivy-version")
    parser.add_argument("--trivy-action-sha")
    parser.add_argument("--skopeo-version")
    parser.add_argument("--skopeo-image-digest")
    parser.add_argument("--trivy-db-check-bundle-digest")
    parser.add_argument("--trivy-db-updated-at")
    parser.add_argument("--full-report-sha256")
    parser.add_argument("--copa-report-sha256")
    parser.add_argument("--secobserve-product")
    parser.add_argument("--secobserve-origin")
    parser.add_argument("--notes", default="")
    parser.add_argument("--out")
    return parser.parse_args()


def value_of(args: argparse.Namespace, flag: str) -> str:
    value = getattr(args, flag.lstrip("-").replace("-", "_"))
    return value if isinstance(value, str) else ""


def collect_violations(args: argparse.Namespace) -> list[str]:
    """Every rule violation, one line each naming the offending field."""
    violations: list[str] = []

    for flag in REQUIRED_FLAGS:
        if not value_of(args, flag).strip():
            field = {
                "--app": "app",
                "--run-url": "pipeline.run_url",
                "--out": "output path",
            }.get(flag, flag.lstrip("-").replace("-", "_"))
            violations.append(f"missing required value for {flag} ({field})")

    for flag, field in DIGEST_FLAGS.items():
        value = value_of(args, flag)
        if value.strip() and not DIGEST_RE.fullmatch(value):
            violations.append(
                f"{flag} ({field}) must be sha256: followed by 64 lowercase "
                f"hex digits (got {value!r})"
            )

    for flag, field in BARE_SHA256_FLAGS.items():
        value = value_of(args, flag)
        if value.strip() and not BARE_SHA256_RE.fullmatch(value):
            violations.append(
                f"{flag} ({field}) must be bare 64-hex sha256sum output, "
                f"no sha256: prefix (got {value!r})"
            )

    app = value_of(args, "--app")
    package = value_of(args, "--internal-package")
    if app.strip() and package.strip() and package != f"{PACKAGE_PREFIX}{app}":
        violations.append(
            f"--internal-package (internal.package) must be "
            f"'{PACKAGE_PREFIX}{app}' (got {package!r})"
        )

    upstream_tag = value_of(args, "--upstream-tag")
    internal_tag = value_of(args, "--internal-tag")
    if upstream_tag.strip() and internal_tag.strip():
        tag_re = re.compile(re.escape(upstream_tag) + r"-bocklabs\.\d+")
        if not tag_re.fullmatch(internal_tag):
            violations.append(
                f"--internal-tag (internal.tag) must be "
                f"'{upstream_tag}-bocklabs.N' with N a positive integer "
                f"(got {internal_tag!r})"
            )

    platforms_raw = value_of(args, "--platforms")
    if platforms_raw.strip():
        platforms = [part.strip() for part in platforms_raw.split(",")]
        if not all(platforms) or not platforms:
            violations.append(
                f"--platforms (internal.platforms) must be a comma-separated "
                f"list of non-empty platforms (got {platforms_raw!r})"
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
