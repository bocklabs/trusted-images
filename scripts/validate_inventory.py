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
  spec.patchDisabledReason required only when patchPolicy is disabled;
                          exact mapping with class=unsupported|no-fix and
                          non-empty detail; forbidden when patching is enabled
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
UPSTREAM_REF_RE = re.compile(r"^[a-z0-9][a-z0-9._/-]*(?::\d+/[a-z0-9._/-]+)?$")
UPSTREAM_TAG_RE = re.compile(r"^\w[\w.-]{0,127}$")
PATCH_POLICIES = ("enabled", "disabled")
PATCH_DISABLED_REASON_FIELDS = {"class", "detail"}
PATCH_DISABLED_REASON_CLASSES = ("unsupported", "no-fix")
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

API_VERSION_FIELD = "apiVersion"
KIND_FIELD = "kind"
NAME_FIELD = "metadata.name"
UPSTREAM_REF_FIELD = "spec.upstream.ref"
UPSTREAM_TAG_FIELD = "spec.upstream.tag"
UPSTREAM_DIGEST_FIELD = "spec.upstream.digest"
PACKAGE_FIELD = "spec.destination.package"
PATCH_POLICY_FIELD = "spec.patchPolicy"
VALIDATION_TYPE_FIELD = "spec.validation.type"
VERSION_FIELD = "spec.version"
PATCH_REASON_FIELD = "spec.patchDisabledReason"
VALIDATION_FIELD = "spec.validation"
UPSTREAM_FIELDS = (UPSTREAM_REF_FIELD, UPSTREAM_TAG_FIELD)
REQUIRED_FIELDS = (
    API_VERSION_FIELD,
    KIND_FIELD,
    NAME_FIELD,
    UPSTREAM_REF_FIELD,
    UPSTREAM_TAG_FIELD,
    UPSTREAM_DIGEST_FIELD,
    PACKAGE_FIELD,
    PATCH_POLICY_FIELD,
    VALIDATION_TYPE_FIELD,
    VERSION_FIELD,
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
        return port_failure(value)
    elif param in POSITIVE_INT_PARAMS:
        return positive_int_failure(value)
    elif param == "expectedExit":
        return integer_failure(value)
    elif param == "command":
        return command_failure(value)
    elif param == "expectedPlatforms":
        return platform_failure(value)
    elif param == "env":
        return env_failure(value)
    return None


def port_failure(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        return f"must be an integer in 1-65535 (got {value!r})"
    return None


def positive_int_failure(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return f"must be a positive integer (got {value!r})"
    return None


def integer_failure(value: object) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return f"must be an integer (got {value!r})"
    return None


def command_failure(value: object) -> str | None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return f"must be a list of strings (got {value!r})"
    return None


def platform_failure(value: object) -> str | None:
    message = f"must be a list of os/arch[/variant] strings (got {value!r})"
    if not isinstance(value, list) or not value:
        return message
    if any(not isinstance(item, str) or not PLATFORM_RE.match(item) for item in value):
        return message
    return None


def env_failure(value: object) -> str | None:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in value.items()
    ):
        return f"must be a str->str mapping (got {value!r})"
    return None


def required_field_failures(
    path: Path, data: dict
) -> tuple[dict[str, object], list[str]]:
    values: dict[str, object] = {}
    issues = []
    for field in REQUIRED_FIELDS:
        present, value = dig(data, field)
        if not present:
            issues.append(f"{path}: missing required field {field}")
        else:
            values[field] = value
    return values, issues


def identity_failures(path: Path, name: str, values: dict[str, object]) -> list[str]:
    issues = []
    if API_VERSION_FIELD in values and values[API_VERSION_FIELD] != API_VERSION:
        issues.append(
            f"apiVersion must be '{API_VERSION}' (got {values[API_VERSION_FIELD]!r})"
        )
    if KIND_FIELD in values and values[KIND_FIELD] != KIND:
        issues.append(f"kind must be '{KIND}' (got {values[KIND_FIELD]!r})")
    if NAME_FIELD in values and values[NAME_FIELD] != name:
        issues.append(
            f"metadata.name must equal folder name '{name}' (got {values[NAME_FIELD]!r})"
        )
    return [f"{path}: {issue}" for issue in issues]


def upstream_failures(path: Path, values: dict[str, object]) -> list[str]:
    issues = []
    for field in UPSTREAM_FIELDS:
        value = values.get(field)
        if field in values and (not isinstance(value, str) or not value.strip()):
            issues.append(f"{field} must be a non-empty string (got {value!r})")
    for field, pattern in (
        (UPSTREAM_REF_FIELD, UPSTREAM_REF_RE),
        (UPSTREAM_TAG_FIELD, UPSTREAM_TAG_RE),
    ):
        value = values.get(field)
        if isinstance(value, str) and not pattern.fullmatch(value):
            issues.append(f"{field} must be a shell-safe container reference component")
    digest = values.get(UPSTREAM_DIGEST_FIELD)
    if UPSTREAM_DIGEST_FIELD in values and (
        not isinstance(digest, str) or not DIGEST_RE.match(digest)
    ):
        issues.append(
            f"spec.upstream.digest {digest!r} is not a valid sha256:64-hex digest"
        )
    return [f"{path}: {issue}" for issue in issues]


def destination_failure(path: Path, name: str, values: dict[str, object]) -> list[str]:
    package = values.get(PACKAGE_FIELD)
    expected = f"{REGISTRY_PREFIX}{name}"
    if PACKAGE_FIELD in values and package != expected:
        return [
            f"{path}: spec.destination.package must be '{expected}' (got {package!r})"
        ]
    return []


def patch_policy_failures(
    path: Path, data: dict, values: dict[str, object]
) -> list[str]:
    issues = []
    patch_policy = values.get(PATCH_POLICY_FIELD)
    if PATCH_POLICY_FIELD in values and patch_policy not in PATCH_POLICIES:
        issues.append(
            f"spec.patchPolicy {values[PATCH_POLICY_FIELD]!r} not in {list(PATCH_POLICIES)}"
        )
    reason_present, reason = dig(data, PATCH_REASON_FIELD)
    if patch_policy == "disabled" and not reason_present:
        issues.append(
            f"{PATCH_REASON_FIELD} is required when spec.patchPolicy is disabled"
        )
    if patch_policy == "enabled" and reason_present:
        issues.append(
            f"{PATCH_REASON_FIELD} is only valid when spec.patchPolicy is disabled"
        )
    return [f"{path}: {issue}" for issue in issues] + patch_disabled_reason_failures(
        path, reason_present, reason
    )


def patch_disabled_reason_failures(
    path: Path, reason_present: bool, reason: object
) -> list[str]:
    if not reason_present:
        return []
    if not isinstance(reason, dict):
        return [
            f"{path}: {PATCH_REASON_FIELD} must be a mapping (got {type(reason).__name__})"
        ]
    issues = []
    for field in sorted(PATCH_DISABLED_REASON_FIELDS - set(reason)):
        issues.append(f"missing required field {PATCH_REASON_FIELD}.{field}")
    unknown = sorted(set(reason) - PATCH_DISABLED_REASON_FIELDS)
    if unknown:
        issues.append(
            f"{PATCH_REASON_FIELD} has unknown keys {unknown} "
            f"(allowed: {sorted(PATCH_DISABLED_REASON_FIELDS)})"
        )
    if "class" in reason and reason["class"] not in PATCH_DISABLED_REASON_CLASSES:
        issues.append(
            f"{PATCH_REASON_FIELD}.class {reason['class']!r} "
            f"not in {list(PATCH_DISABLED_REASON_CLASSES)}"
        )
    detail = reason.get("detail")
    if "detail" in reason and (not isinstance(detail, str) or not detail.strip()):
        issues.append(
            f"{PATCH_REASON_FIELD}.detail must be a non-empty string (got {detail!r})"
        )
    return [f"{path}: {issue}" for issue in issues]


def validation_failures(path: Path, data: dict, values: dict[str, object]) -> list[str]:
    if VALIDATION_TYPE_FIELD not in values:
        return []
    vtype = values[VALIDATION_TYPE_FIELD]
    validation = dig(data, VALIDATION_FIELD)[1]
    if not isinstance(vtype, str) or vtype not in VALIDATION_PROFILES:
        return [
            f"{path}: {VALIDATION_TYPE_FIELD} {vtype!r} not in {list(VALIDATION_PROFILES)}"
        ]
    if not isinstance(validation, dict):
        return [
            f"{path}: {VALIDATION_FIELD} must be a mapping (got {type(validation).__name__})"
        ]
    return validation_param_failures(path, validation, vtype)


def validation_param_failures(path: Path, validation: dict, vtype: str) -> list[str]:
    rules = VALIDATION_PARAM_RULES[vtype]
    allowed = set(rules["required"]) | set(rules["optional"]) | set(SHARED_OPTIONAL)
    issues = []
    for key in sorted(set(validation) - allowed - {"type"}):
        issues.append(
            f"{VALIDATION_FIELD}.{key} is not a known param for type '{vtype}' "
            f"(allowed: {sorted(allowed | {'type'})})"
        )
    for param in rules["required"]:
        if param not in validation:
            issues.append(f"{VALIDATION_FIELD}.{param} is required for type '{vtype}'")
    for param, value in sorted(validation.items()):
        if param == "type":
            continue
        violation = param_failure(param, value)
        if violation:
            issues.append(f"{VALIDATION_FIELD}.{param} {violation}")
    return [f"{path}: {issue}" for issue in issues]


def version_failure(path: Path, values: dict[str, object]) -> list[str]:
    if VERSION_FIELD not in values:
        return []
    version = values[VERSION_FIELD]
    invalid = (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version != SCHEMA_VERSION
    )
    if invalid:
        return [
            f"{path}: spec.version must be the integer {SCHEMA_VERSION} (got {version!r})"
        ]
    return []


def entry_failures(path: Path, data: object) -> list[str]:
    """All schema-v2 violations in one entry, each naming file + rule."""
    name = path.parent.name
    if not isinstance(data, dict):
        return [f"{path}: entry is not a YAML mapping (got {type(data).__name__})"]
    values, issues = required_field_failures(path, data)
    return [
        *issues,
        *identity_failures(path, name, values),
        *upstream_failures(path, values),
        *destination_failure(path, name, values),
        *patch_policy_failures(path, data, values),
        *validation_failures(path, data, values),
        *version_failure(path, values),
    ]


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

        _, package = dig(
            data if isinstance(data, dict) else {}, "spec.destination.package"
        )
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
