"""Canonical immutable image and finding identities."""

import hashlib
import json
import re

REF = re.compile(r"ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*:\w[\w.-]{0,127}@sha256:[a-f0-9]{64}", re.ASCII)
FINDING_FIELDS = {"id", "package", "installed", "class", "type", "target"}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def findings_hash(findings):
    require(isinstance(findings, list) and 0 < len(findings) <= 1000, "invalid finding set")
    for item in findings:
        require(isinstance(item, dict) and set(item) == FINDING_FIELDS, "invalid finding identity")
        require(all(isinstance(v, str) and 0 < len(v) <= 512 and not any(ord(c) < 32 for c in v)
                    for v in item.values()), "invalid finding identity value")
    ordered = sorted(findings, key=canonical)
    require(findings == ordered and len({canonical(v) for v in findings}) == len(findings),
            "findings must be sorted and unique")
    return hashlib.sha256(canonical(findings).encode()).hexdigest()
