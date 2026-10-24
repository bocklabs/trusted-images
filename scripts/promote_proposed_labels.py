"""Emit add-only OCI provenance labels."""

import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    before = json.load(stream) or {}
labels = {
    "org.opencontainers.image.base.digest": os.environ["SELECTED_DIGEST"],
    "org.opencontainers.image.base.name": os.environ["UPSTREAM_REF"]
    + ":"
    + os.environ["UPSTREAM_TAG"],
    "org.opencontainers.image.source": "https://github.com/bocklabs/trusted-images",
    "org.opencontainers.image.version": os.environ["INTERNAL_TAG"],
}
print(
    json.dumps(
        [
            f"LABEL {key}={json.dumps(value)}"
            for key, value in labels.items()
            if key not in before
        ]
    )
)
