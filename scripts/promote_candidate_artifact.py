"""Validate the fresh candidate artifact and checksum manifest."""

import hashlib
from pathlib import Path

ARTIFACT_PREFIX = "candidate-artifact/"
root = Path("candidate-artifact")
mandatory = {
    "candidate-decision.json",
    "candidate-manifest.json",
    "child-config.json",
    "child-manifest.json",
    "inventory-image.yaml",
    "secobserve-upload.json",
    "source.sha",
    "tag-decision.json",
    "trivy-before-full.json",
    "trivy-copa.json",
    "trivy-full.cdx.json",
    "trivy-full.json",
    "upstream-index.json",
    "validation-evidence.json",
    "kev.json",
    "kev-fetched-at.txt",
    "trivy-db-meta-1.txt",
    "trivy-db-meta-2.txt",
    "SHA256SUMS",
}
optional = {
    "trivy-after-full.json",
    "scan-receipt.json",
    "trivy-db-meta-after.txt",
    "copa-diagnostics.txt",
    "copa-candidate-image-id.txt",
    "before-labels.json",
    "after-labels.json",
    "acceptance.json",
    "github-evidence.json",
    "original-candidate-decision.json",
    "resume-run.json",
    "resume-branch.json",
    "resume-artifacts.jsonl",
    "resume-artifact-id.txt",
    "resume-candidate-image-id.txt",
}
actual = []
for path in root.rglob("*"):
    relative = path.relative_to(root).as_posix()
    if path.is_symlink() or path.is_absolute() or ".." in path.parts:
        raise SystemExit(
            f"FATAL: candidate artifact path traversal or symlink: {relative}"
        )
    if path.is_file():
        actual.append(relative)
allowed = (
    mandatory
    | optional
    | {
        name
        for name in actual
        if name.startswith(("candidate-oci/", "validation-logs/"))
    }
)
undeclared = set(actual) - allowed
if undeclared or not mandatory <= set(actual):
    raise SystemExit("FATAL: fresh candidate artifact has undeclared or missing files")
listed = [
    line.split("  ", 1)[1] for line in (root / "SHA256SUMS").read_text().splitlines()
]
listed = [
    (name[len(ARTIFACT_PREFIX) :] if name.startswith(ARTIFACT_PREFIX) else name)
    for name in listed
]
if len(listed) != len(set(listed)) or set(listed) != {
    name for name in actual if name != "SHA256SUMS"
}:
    raise SystemExit("FATAL: fresh candidate checksum manifest is ambiguous")

for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    expected_digest, name = line.split("  ", 1)
    name = name.removeprefix(ARTIFACT_PREFIX)
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected_digest:
        raise SystemExit(f"FATAL: fresh candidate checksum failed: {name}")
