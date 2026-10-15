"""Remove newly introduced Copa Chisel labels before binding final OCI bytes."""

import hashlib
import json
import re
import sys
from pathlib import Path

MANIFEST_TYPE = "application/vnd.oci.image.manifest.v1+json"
CONFIG_TYPE = "application/vnd.oci.image.config.v1+json"


def read_blob(oci: Path, descriptor: dict, media_type: str) -> dict:
    digest = descriptor.get("digest", "")
    if (descriptor.get("mediaType") != media_type or not isinstance(digest, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            or type(descriptor.get("size")) is not int):
        raise ValueError("invalid OCI descriptor")
    raw = (oci / "blobs/sha256" / digest[7:]).read_bytes()
    if len(raw) != descriptor["size"] or hashlib.sha256(raw).hexdigest() != digest[7:]:
        raise ValueError("OCI descriptor digest or size mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError("OCI blob must be an object")
    return value


def write_blob(oci: Path, descriptor: dict, value: dict) -> None:
    raw = json.dumps(value, separators=(",", ":")).encode()
    digest = hashlib.sha256(raw).hexdigest()
    (oci / "blobs/sha256" / digest).write_bytes(raw)
    descriptor.update(digest="sha256:" + digest, size=len(raw))


def finalize(oci: Path, original_config: Path) -> None:
    index = json.loads((oci / "index.json").read_bytes())
    if index.get("schemaVersion") != 2 or len(index.get("manifests", [])) != 1:
        raise ValueError("final candidate OCI must contain one image manifest")
    descriptor = index["manifests"][0]
    manifest = read_blob(oci, descriptor, MANIFEST_TYPE)
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") != MANIFEST_TYPE:
        raise ValueError("invalid OCI image manifest")
    config = read_blob(oci, manifest["config"], CONFIG_TYPE)
    original = json.loads(original_config.read_bytes())["config"].get("Labels") or {}
    labels = config["config"].get("Labels") or {}
    if not isinstance(original, dict) or not isinstance(labels, dict):
        raise TypeError("OCI config Labels must be objects")
    removed = {key for key in ("sh.copa.chisel.release", "sh.copa.chisel.version")
               if key in labels and key not in original}
    if not removed:
        return
    for key in removed:
        del labels[key]
    write_blob(oci, manifest["config"], config)
    write_blob(oci, descriptor, manifest)
    (oci / "index.json").write_text(json.dumps(index, separators=(",", ":")))


if __name__ == "__main__":
    finalize(Path(sys.argv[1]), Path(sys.argv[2]))
