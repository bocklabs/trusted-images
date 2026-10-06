"""Bind native Chisel package scans to real OCI bytes and signed Ubuntu metadata."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.request import urlopen

import native_chisel_inventory as native


def image_inputs(oci, reference, report, cache, trivy):
    blob = oci / "blobs" / "sha256"
    manifest = blob / reference.rsplit("@sha256:", 1)[1]
    descriptor = native.read_json(manifest)
    return {"reference": reference, "artifact_name": native.read_json(report)["ArtifactName"],
            "manifest": str(manifest), "config": str(blob / descriptor["config"]["digest"].split(":")[1]),
            "layers": [str(blob / row["digest"].split(":")[1]) for row in descriptor["layers"]],
            "raw_report": str(report), "db": str(cache / "db" / "trivy.db"), "trivy": trivy, "archives": []}


def fetch_archive(root, stamp, codename, architecture):
    native.require(re.fullmatch(r"[a-z0-9]+", codename) and architecture == "amd64", "unsupported native archive")
    directory = root / "archives" / stamp
    directory.mkdir(parents=True, exist_ok=True)
    for suite in (codename, codename + "-updates", codename + "-security"):
        paths = {suite + "-InRelease": "InRelease"}
        paths.update({f"{suite}-{part}-Packages.xz": f"{part}/binary-{architecture}/Packages.xz"
                      for part in ("main", "universe")})
        for filename, relative in paths.items():
            url = f"https://snapshot.ubuntu.com/ubuntu/{stamp}/dists/{suite}/{relative}"
            with urlopen(url, timeout=60) as response, (directory / filename).open("wb") as output:
                shutil.copyfileobj(response, output)
    return str(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "oci", "evidence", "cache"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--fixable", type=Path)
    parser.add_argument("--previous", type=Path)
    args = parser.parse_args()
    raw = native.read_json(args.report)
    rows = [row for row in raw.get("Results", []) if row.get("Class") == "os-pkgs"]
    os_metadata = raw.get("Metadata", {}).get("OS") or {}
    if os_metadata.get("Family") != "ubuntu" or (rows and rows[0].get("Packages")):
        return
    trivy = shutil.which("trivy")
    native.require(trivy is not None, "missing Trivy binary")
    inputs = image_inputs(args.oci, args.reference, args.report, args.cache, trivy)
    info = native.probe(inputs)
    native.require(info["native"], "Ubuntu image has no supported package inventory or native Chisel manifest")
    if args.fixable:
        native.require(args.fixable.is_file(), "missing mandatory fixable scan report; rebuild candidate")
    if args.previous:
        native.require((args.previous / "archives").is_dir(), "missing native before archive evidence; rebuild candidate")
    root = args.evidence.resolve()
    native.require(root.name in ("native-before", "native-after", "native-published"), "invalid native evidence directory")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    shutil.copytree(args.oci, root / "oci")
    shutil.copyfile(args.report, root / "raw-image.json")
    shutil.copytree(args.cache / "db", root / "cache" / "db")
    shutil.copyfile(trivy, root / "trivy")
    (root / "trivy").chmod(0o755)
    inputs = image_inputs(root / "oci", args.reference, root / "raw-image.json", root / "cache", str(root / "trivy"))
    if args.previous:
        shutil.copytree(args.previous / "archives", root / "archives")
        inputs["archives"] = [str(path) for path in sorted((root / "archives").iterdir())]
    created = datetime.fromisoformat(info["created"].replace("Z", "+00:00"))
    native.require(created.tzinfo is not None, "native image creation timestamp has no timezone")
    date = datetime.now(timezone.utc) if args.previous else created
    stamp = date.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    inputs["archives"].append(fetch_archive(root, stamp, info["codename"], info["architecture"]))
    (root / "inputs.json").write_text(json.dumps(native.portable_inputs(inputs, root), indent=2) + "\n")
    helper = str(Path(__file__).with_name("native_chisel_inventory.py"))
    subprocess.run([sys.executable, helper, "prepare", "--inputs", str(root / "inputs.json"),
                    "--output", str(root / "sbom.json")], check=True)
    subprocess.run([str(root / "trivy"), "sbom", "--offline-scan", "--skip-db-update", "--cache-dir", str(root / "cache"),
                    "--format", "json", "--list-all-pkgs", "--output", "scan.json", "sbom.json"], cwd=root, check=True)
    subprocess.run([sys.executable, helper, "enrich", "--inputs", str(root / "inputs.json"), "--sbom", str(root / "sbom.json"),
                    "--scan", str(root / "scan.json"), "--output", str(root / "report.json"), "--capsule", str(root / "capsule.json")], check=True)
    if args.fixable:
        fixed = native.read_json(args.fixable)
        native.require(fixed["Metadata"] == raw["Metadata"] and fixed["ArtifactName"] == raw["ArtifactName"], "fixable scan image mismatch")
        shutil.copyfile(args.fixable, root / "raw-fixable.json")
        result = next((row for row in native.read_json(root / "report.json")["Results"] if row.get("Class") == "os-pkgs"), None)
        target = next((row for row in fixed.get("Results", []) if row.get("Class") == "os-pkgs"), None)
        native.require(result is not None and target is not None, "fixable scan has no Ubuntu OS result")
        target["Packages"] = result["Packages"]
        target["Vulnerabilities"] = [item for item in result["Vulnerabilities"] if item.get("FixedVersion")]
        args.fixable.write_text(json.dumps(fixed, indent=2) + "\n")
    shutil.copyfile(root / "report.json", args.report)


if __name__ == "__main__":
    main()
