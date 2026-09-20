"""Verify that patched labels remain add-only."""

import json
import sys
before = json.load(open(sys.argv[1])) or {}
after = json.load(open(sys.argv[2])) or {}
allowed = {
    "org.opencontainers.image.base.digest",
    "org.opencontainers.image.base.name",
    "org.opencontainers.image.source",
    "org.opencontainers.image.version",
}
if set(after) - set(before) - allowed or any(after[k] != v for k, v in before.items()):
    raise SystemExit("FATAL: patched labels violate the add-only provenance contract")
