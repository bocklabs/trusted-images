#!/usr/bin/env python3
"""Validate the trusted-images inventory against schema v1.

Every inventory/<app>/image.yaml is untrusted input (public-repo pull-request
surface): parse with yaml.safe_load only, never yaml.load. Any rule violation
fails the run — one line per violation, each naming the offending file and the
violated rule. Exit 0 prints "OK: inventory valid"; exit 1 means invalid.

Schema v1 rules (field names are locked — the Renovate custom manager and CI
bind to these exact strings):
  apiVersion              == trusted-images.bocklabs.dev/v1
  kind                    == Image
  metadata.name           == parent folder name
  spec.upstream.ref       non-empty string
  spec.upstream.tag       non-empty string (quote bare versions like "1.25.3"
                          or YAML coerces them to floats)
  spec.upstream.digest    matches ^sha256:[a-f0-9]{64}$
  spec.destination.package == ghcr.io/bocklabs/<parent folder name>, unique
  spec.patchPolicy        in {enabled, disabled}
  spec.validationProfile  in {process, http, oneshot}
  spec.version            == 1 (integer)

Usage: validate_inventory.py [ROOT]   (ROOT defaults to ./inventory)

PyYAML 6.0.3 is the one deliberate dependency; everything else is stdlib.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml  # PyYAML 6.0.3 — the single deliberate dependency

API_VERSION = "trusted-images.bocklabs.dev/v1"
KIND = "Image"
REGISTRY_PREFIX = "ghcr.io/bocklabs/"
SCHEMA_VERSION = 1
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PATCH_POLICIES = ("enabled", "disabled")
VALIDATION_PROFILES = ("process", "http", "oneshot")

REQUIRED_FIELDS = (
    "apiVersion",
    "kind",
    "metadata.name",
    "spec.upstream.ref",
    "spec.upstream.tag",
    "spec.upstream.digest",
    "spec.destination.package",
    "spec.patchPolicy",
    "spec.validationProfile",
    "spec.version",
)


def dig(data: dict, dotted: str) -> tuple[bool, object]:
    """Traverse a dotted field path; return (present, value)."""
    node: object = data
    for key in dotted.split("."):
        if not isinstance(node, dict) or key not in node:
            return False, None
        node = node[key]
    return True, node


def entry_failures(path: Path, data: object) -> list[str]:
    """All schema-v1 violations in one entry, each naming file + rule."""
    name = path.parent.name
    issues: list[str] = []

    def fail(rule: str) -> None:
        issues.append(f"{path}: {rule}")

    if not isinstance(data, dict):
        fail(f"entry is not a YAML mapping (got {type(data).__name__})")
        return issues

    values: dict[str, object] = {}
    for field in REQUIRED_FIELDS:
        present, value = dig(data, field)
        if not present:
            fail(f"missing required field {field}")
        else:
            values[field] = value

    if "apiVersion" in values and values["apiVersion"] != API_VERSION:
        fail(f"apiVersion must be '{API_VERSION}' (got {values['apiVersion']!r})")
    if "kind" in values and values["kind"] != KIND:
        fail(f"kind must be '{KIND}' (got {values['kind']!r})")
    if "metadata.name" in values and values["metadata.name"] != name:
        fail(
            f"metadata.name must equal folder name '{name}' "
            f"(got {values['metadata.name']!r})"
        )

    for field in ("spec.upstream.ref", "spec.upstream.tag"):
        value = values.get(field)
        if field in values and (not isinstance(value, str) or not value.strip()):
            fail(f"{field} must be a non-empty string (got {value!r})")

    if "spec.upstream.digest" in values:
        digest = values["spec.upstream.digest"]
        if not isinstance(digest, str) or not DIGEST_RE.match(digest):
            fail(f"spec.upstream.digest {digest!r} is not a valid sha256:64-hex digest")

    if "spec.destination.package" in values:
        package = values["spec.destination.package"]
        expected = f"{REGISTRY_PREFIX}{name}"
        if package != expected:
            fail(f"spec.destination.package must be '{expected}' (got {package!r})")

    if "spec.patchPolicy" in values and values["spec.patchPolicy"] not in PATCH_POLICIES:
        fail(
            f"spec.patchPolicy {values['spec.patchPolicy']!r} "
            f"not in {list(PATCH_POLICIES)}"
        )

    if (
        "spec.validationProfile" in values
        and values["spec.validationProfile"] not in VALIDATION_PROFILES
    ):
        fail(
            f"spec.validationProfile {values['spec.validationProfile']!r} "
            f"not in {list(VALIDATION_PROFILES)}"
        )

    if "spec.version" in values:
        version = values["spec.version"]
        if isinstance(version, bool) or not isinstance(version, int) or version != SCHEMA_VERSION:
            fail(f"spec.version must be the integer {SCHEMA_VERSION} (got {version!r})")

    return issues


def validate(root: Path) -> list[str]:
    """Validate every inventory/<app>/image.yaml under root; return violations."""
    if not root.is_dir():
        return [f"inventory root not found: {root}"]

    entries = sorted(root.glob("*/image.yaml"))
    if not entries:
        return [f"no inventory entries found under {root}"]

    failures: list[str] = []
    packages: dict[str, Path] = {}
    for entry in entries:
        try:
            data = yaml.safe_load(entry.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            failures.append(f"{entry}: invalid YAML ({exc})")
            continue
        failures.extend(entry_failures(entry, data))

        _, package = dig(data if isinstance(data, dict) else {}, "spec.destination.package")
        if isinstance(package, str) and package:
            if package in packages:
                failures.append(
                    f"{entry}: duplicate spec.destination.package '{package}' "
                    f"(already used by {packages[package]})"
                )
            else:
                packages[package] = entry
    return failures


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("inventory")
    failures = validate(root)
    if failures:
        for line in failures:
            print(f"[validate] {line}")
        return 1
    print("OK: inventory valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
