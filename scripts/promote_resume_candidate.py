"""Restore and verify the exact accepted candidate."""

import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path, PurePosixPath

import yaml

run_id, artifact_id = sys.argv[1], int(sys.argv[2])
root = Path("resume-download")
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
    "upstream-index.json",
    "trivy-full.cdx.json",
    "trivy-full.json",
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
}
allowed_prefixes = ("candidate-oci/", "validation-logs/")
files = [path for path in root.rglob("*") if path.is_file() or path.is_symlink()]
relatives = []
for path in files:
    relative = path.relative_to(root).as_posix()
    if path.is_symlink() or path.is_absolute() or ".." in path.parts:
        raise SystemExit(
            f"FATAL: candidate artifact path traversal or symlink: {relative}"
        )
    relatives.append(relative)
checksum_lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
listed = []
for line in checksum_lines:
    digest, name = line.split("  ", 1)
    relative_path = PurePosixPath(name)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise SystemExit(f"FATAL: candidate checksum manifest path traversal: {name}")
    path = root / name
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise SystemExit(f"FATAL: candidate checksum/digest mismatch: {name}")
    listed.append(name)
actual = [name for name in relatives if name != "SHA256SUMS"]
if len(listed) != len(set(listed)) or set(listed) != set(actual):
    raise SystemExit(
        "FATAL: candidate checksum manifest is incomplete or names undeclared files"
    )
allowed = (
    mandatory
    | optional
    | {name for name in actual if name.startswith(allowed_prefixes)}
)
undeclared = set(actual) - allowed
if undeclared:
    raise SystemExit(
        "FATAL: candidate artifact has undeclared files: "
        + ", ".join(sorted(undeclared))
    )
missing = mandatory - (set(actual) | {"SHA256SUMS"})
if missing:
    raise SystemExit(
        "FATAL: candidate artifact is missing required files: "
        + ", ".join(sorted(missing))
    )

spec = yaml.safe_load((root / "inventory-image.yaml").read_text(encoding="utf-8"))[
    "spec"
]
expected_package = f"ghcr.io/bocklabs/{os.environ['APP']}"
if spec["destination"]["package"] != expected_package:
    raise SystemExit("FATAL: candidate inventory app/package mismatch")
current = Path("inventory") / os.environ["APP"] / "image.yaml"
if current.read_bytes() != (root / "inventory-image.yaml").read_bytes():
    raise SystemExit("FATAL: candidate inventory bytes differ from current main")

decision_path = root / "candidate-decision.json"
decision = json.loads(decision_path.read_text(encoding="utf-8"))
module_spec = importlib.util.spec_from_file_location(
    "evaluate_promotion", "scripts/evaluate_promotion.py"
)
module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(module)
module.validate_decision(decision)
run = json.loads(Path("resume-run.json").read_text(encoding="utf-8"))
expected = {
    "app": os.environ["APP"],
    "run_id": run_id,
    "source_sha": run["head_sha"],
    "upstream_index_digest": spec["upstream"]["digest"],
}
mismatches = [key for key, value in expected.items() if decision.get(key) != value]
if (
    decision.get("run_attempt") != run["run_attempt"]
    or (root / "source.sha").read_text().strip() != run["head_sha"]
):
    mismatches.append("run_attempt/source.sha")
if decision.get("resume") is not None:
    mismatches.append("resume")
if (
    decision.get("eligible") is not False
    or decision.get("reason") != "missing_kev_acceptance"
):
    mismatches.append("blocker")
if decision.get("validation", {}).get("result") != "pass":
    mismatches.append("validation")
if mismatches:
    raise SystemExit(
        "FATAL: candidate decision binding failed (wrong run, app, source, inventory, or blocker): "
        + ", ".join(mismatches)
    )

selected = decision["selected_child_digest"]
candidate = decision["candidate"]["digest"]
for name, digest in (
    ("child-manifest.json", selected),
    ("candidate-manifest.json", candidate),
):
    actual_digest = "sha256:" + hashlib.sha256((root / name).read_bytes()).hexdigest()
    if actual_digest != digest:
        raise SystemExit(f"FATAL: candidate {name} digest mismatch")
if module.sha256_file(root / "upstream-index.json") != spec["upstream"]["digest"]:
    raise SystemExit("FATAL: candidate upstream index digest mismatch")
if (
    module.select_child(
        json.loads((root / "upstream-index.json").read_text()),
        root / "child-manifest.json",
        root / "child-config.json",
    )
    != selected
):
    raise SystemExit("FATAL: candidate child identity mismatch")
blob = root / "candidate-oci" / "blobs" / "sha256" / candidate.split(":", 1)[1]
if (
    not blob.is_file()
    or blob.read_bytes() != (root / "candidate-manifest.json").read_bytes()
):
    raise SystemExit("FATAL: candidate OCI layout does not preserve exact bytes")
tag = json.loads((root / "tag-decision.json").read_text(encoding="utf-8"))
if tag != {"internal_tag": decision["proposed_tag"], "skip_copy": False}:
    raise SystemExit("FATAL: candidate proposed tag mismatch")
if (
    json.loads((root / "validation-evidence.json").read_text())
    .get("validation", {})
    .get("result")
    != "pass"
):
    raise SystemExit("FATAL: original candidate validation did not pass")

for name in mandatory | optional:
    source = root / name
    if source.is_file():
        shutil.copyfile(source, name)
shutil.copytree(root / "candidate-oci", "candidate-oci", dirs_exist_ok=True)
shutil.copyfile(root / "candidate-decision.json", "original-candidate-decision.json")
with Path(os.environ.get("GITHUB_OUTPUT", "/dev/null")).open(
    "a", encoding="utf-8"
) as output:
    output.write(f"candidate_digest={candidate}\n")
    output.write(f"selected_child_digest={selected}\n")
    output.write(f"internal_tag={decision['proposed_tag']}\n")
    output.write("skip_copy=false\n")
    output.write(f"patched={str(decision['copa']['original_child_input']).lower()}\n")
    output.write(f"artifact_id={artifact_id}\n")
    output.write(f"original_run_id={run_id}\n")
    output.write(f"original_run_attempt={run['run_attempt']}\n")
    output.write(f"original_source_sha={run['head_sha']}\n")
