"""Verify that a reused candidate preserves provenance bytes."""

import hashlib
import sys
from pathlib import Path

expected, root = sys.argv[1], Path(sys.argv[2])
manifest = root / "candidate-manifest.json"
actual = "sha256:" + hashlib.sha256(manifest.read_bytes()).hexdigest()
blob = root / "candidate-oci" / "blobs" / "sha256" / expected.split(":", 1)[1]
if (
    actual != expected
    or not blob.is_file()
    or blob.read_bytes() != manifest.read_bytes()
):
    raise SystemExit("FATAL: reused candidate bytes do not match its provenance")
