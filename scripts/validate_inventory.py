#!/usr/bin/env python3
"""Validate the trusted-images inventory against schema v2.

Every inventory/<app>/image.yaml is untrusted input (public-repo pull-request
surface): parse with yaml.safe_load only, never yaml.load. Any rule violation
fails the run — one line per violation, each naming the offending file and the
violated rule. Exit 0 prints "OK: inventory valid"; exit 1 means invalid.

Schema v2 rules (field names are locked — the Renovate custom manager and CI
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
  spec.validation         mapping whose "type" is required and must be in
                          {process, http, oneshot}; per-type params below;
                          ANY unknown key inside the mapping is rejected
                          (fail-closed against typos like "ports:")
  spec.version            == 2 (integer)

Per-type validation params (required first, then optional):
  http     port (int 1-65535); path; expectStatus, durationSeconds
           (positive int); command (list of str)
  process  durationSeconds (positive int); command (list of str)
  oneshot  expectedExit (int); timeoutSeconds (positive int);
           command (list of str)
  shared   expectedPlatforms (list of os/arch[/variant] strings); env
           (str->str mapping)

The v1 flat profile shape (a bare profile string where spec.validation now
lives) is accepted nowhere: an entry still carrying it fails validation
(missing spec.validation.type).

Usage: validate_inventory.py [ROOT]   (ROOT defaults to ./inventory)

PyYAML 6.0.3 is the one deliberate dependency; everything else is stdlib.
"""


import re
import sys
from pathlib import Path

import yaml

API_VERSION = "trusted-images.bocklabs.dev/v1"
KIND = "Image"
REGISTRY_PREFIX = "ghcr.io/bocklabs/"
SCHEMA_VERSION = 2
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
PATCH_POLICIES = ("enabled", "disabled")
VALIDATION_PROFILES = ("process", "http", "oneshot")
PLATFORM_RE = re.compile(r"^[a-z0-9]+/[a-z0-9]+(/.+)?$")

# spec.validation.type -> (required params, optional params). Anything outside
# required + optional + SHARED_OPTIONAL + "type" is an unknown key -> rejected.
VALIDATION_PARAM_RULES = {
    "http": {
        "required": ("port",),
        "optional": ("path", "expectStatus", "durationSeconds", "command"),
    },
    "process": {
        "required": (),
        "optional": ("durationSeconds", "command"),
    },
    "oneshot": {
        "required": (),
        "optional": ("expectedExit", "timeoutSeconds", "command"),
    },
}
SHARED_OPTIONAL = ("expectedPlatforms", "env")
POSITIVE_INT_PARAMS = ("expectStatus", "durationSeconds", "timeoutSeconds")

REQUIRED_FIELDS = (
    "apiVersion",
    "kind",
    "metadata.name",
    "spec.upstream.ref",
    "spec.upstream.tag",
    "spec.upstream.digest",
    "spec.destination.package",
    "spec.patchPolicy",
    "spec.validation.type",
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


def param_failure(param: str, value: object) -> str | None:
    """Rule violation text for one spec.validation param, or None if valid."""
    if param == "port":
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= 65535
        ):
            return f"must be an integer in 1-65535 (got {value!r})"
    elif param in POSITIVE_INT_PARAMS:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return f"must be a positive integer (got {value!r})"
    elif param == "expectedExit":
        if isinstance(value, bool) or not isinstance(value, int):
            return f"must be an integer (got {value!r})"
    elif param == "command":
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            return f"must be a list of strings (got {value!r})"
    elif param == "expectedPlatforms":
        if (
            not isinstance(value, list)
            or not value
            or not all(
                isinstance(item, str) and PLATFORM_RE.match(item) for item in value
            )
        ):
            return f"must be a list of os/arch[/variant] strings (got {value!r})"
    elif param == "env":
        if not isinstance(value, dict) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value.items()
        ):
            return f"must be a str->str mapping (got {value!r})"
    return None


def entry_failures(path: Path, data: object) -> list[str]:
    """All schema-v2 violations in one entry, each naming file + rule."""
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

    if "spec.validation.type" in values:
        vtype = values["spec.validation.type"]
        validation = dig(data, "spec.validation")[1]
        if not isinstance(vtype, str) or vtype not in VALIDATION_PROFILES:
            fail(f"spec.validation.type {vtype!r} not in {list(VALIDATION_PROFILES)}")
        elif not isinstance(validation, dict):
            fail(f"spec.validation must be a mapping (got {type(validation).__name__})")
        else:
            rules = VALIDATION_PARAM_RULES[vtype]
            allowed = (
                set(rules["required"]) | set(rules["optional"]) | set(SHARED_OPTIONAL)
            )
            for key in sorted(set(validation) - allowed - {"type"}):
                fail(
                    f"spec.validation.{key} is not a known param for type '{vtype}' "
                    f"(allowed: {sorted(allowed | {'type'})})"
                )
            for param in rules["required"]:
                if param not in validation:
                    fail(f"spec.validation.{param} is required for type '{vtype}'")
            for param, value in sorted(validation.items()):
                if param == "type":
                    continue
                violation = param_failure(param, value)
                if violation:
                    fail(f"spec.validation.{param} {violation}")

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
