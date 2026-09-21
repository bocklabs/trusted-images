"""Verify and materialize an exact recovery candidate."""

import hashlib
import json
import sys
from pathlib import Path

provenance, root = Path(sys.argv[1]), Path(sys.argv[2])
record = json.loads(provenance.read_text(encoding="utf-8"))
manifest = hashlib.sha256((root / "candidate-manifest.json").read_bytes()).hexdigest()
expected = {
    "index": record["upstream"]["index_digest"],
    "child": record["upstream"]["selected_child_digest"],
    "candidate": record["internal"]["digest"],
}
actual = {
    "index": "sha256:"
    + hashlib.sha256((root / "upstream-index.json").read_bytes()).hexdigest(),
    "child": "sha256:"
    + hashlib.sha256((root / "child-manifest.json").read_bytes()).hexdigest(),
    "candidate": "sha256:" + manifest,
}
if actual != expected:
    raise SystemExit("FATAL: recovery candidate bytes do not match provenance")
blob = (
    root / "candidate-oci" / "blobs" / "sha256" / expected["candidate"].split(":", 1)[1]
)
if (
    not blob.is_file()
    or blob.read_bytes() != (root / "candidate-manifest.json").read_bytes()
):
    raise SystemExit("FATAL: recovery OCI layout does not preserve candidate bytes")
listed = {
    line.split("  ", 1)[1].removeprefix("candidate-artifact/")
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    if "  " in line
}
actual_files = set()
for path in root.rglob("*"):
    relative = path.relative_to(root).as_posix()
    if path.is_symlink() or ".." in path.parts:
        raise SystemExit(
            f"FATAL: recovery candidate path traversal or symlink: {relative}"
        )
    if path.is_file() and path.name != "SHA256SUMS":
        actual_files.add(relative)
if listed != actual_files:
    raise SystemExit("FATAL: recovery candidate checksum manifest is ambiguous")
for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    name = name.removeprefix("candidate-artifact/")
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
        raise SystemExit(f"FATAL: recovery candidate checksum failed: {name}")
Path("original-candidate-decision.json").write_bytes(
    (root / "candidate-decision.json").read_bytes()
)
