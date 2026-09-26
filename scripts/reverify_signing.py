"""Recheck public signed provenance with the checked-out Cosign pin."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from promote_signing_gate import IMAGE_RE, PREDICATE_TYPE, field, load_identity, statement_from_verified

ROOT = Path(__file__).resolve().parent.parent
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"v?\d+\.\d+\.\d+\Z")


def old_signed_paths(base):
    paths = subprocess.check_output(
        ["git", "ls-tree", "-r", "--name-only", base, "--", "provenance"], cwd=ROOT, text=True
    ).splitlines()
    return {
        path for path in paths if path.endswith(".json") and
        json.loads(subprocess.check_output(["git", "show", f"{base}:{path}"], cwd=ROOT))
        .get("signing", {}).get("result") == "pass"
    }


def signed_record(record, path, identity):
    signing = record["signing"]
    app = record.get("app")
    internal = record.get("internal", {})
    signature = signing.get("image_signature", {})
    sbom = signing.get("sbom_attestation", {})
    tools = signing.get("tools", {})
    rekor = signing.get("rekor", {})
    image = f"{internal.get('package')}@{internal.get('digest')}"
    if (record.get("schema") != "trusted-images.bocklabs.dev/provenance-v1"
            or not isinstance(app, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", app)
            or image != f"ghcr.io/bocklabs/{app}@{internal.get('digest')}"
            or not IMAGE_RE.fullmatch(image)
            or signing.get("result") != "pass" or record.get("policy", {}).get("eligible") is not True
            or signature.get("certificate_identity") != identity["certificate_identity"]
            or signature.get("certificate_oidc_issuer") != identity["certificate_oidc_issuer"]
            or sbom.get("predicate_type") != PREDICATE_TYPE
            or any(not SHA256.fullmatch(str(section.get(key, ""))) for section, keys in (
                (signature, ("bundle_sha256", "attachment_sha256")),
                (sbom, ("bundle_sha256", "attachment_sha256", "predicate_sha256")),
            ) for key in keys)
            or any(not VERSION.fullmatch(str(tools.get(key, ""))) for key in ("cosign", "trivy"))
            or not isinstance(rekor, dict)
            or any(not isinstance(rekor.get(key), dict) or
                   not isinstance(rekor[key].get("log_index"), int) or
                   not rekor[key].get("log_id") or
                   not (rekor[key].get("signed_entry_timestamp") or rekor[key].get("inclusion_root_hash"))
                   for key in ("signature", "sbom_attestation"))):
        raise ValueError(f"invalid signed record: {path}")
    return image, signature["attachment_sha256"], sbom["attachment_sha256"]


def check_signed_history(previous):
    for name in previous:
        if not (ROOT / name).is_file():
            raise ValueError(f"missing signed record: {name}")
        if json.loads((ROOT / name).read_text()).get("signing", {}).get("result") != "pass":
            raise ValueError(f"successful signed record lost its evidence: {name}")


def signed_records(base, identity):
    previous = old_signed_paths(base)
    check_signed_history(previous)
    records = sorted((ROOT / "provenance").glob("*/*.json"))
    signed = []
    for path in records:
        record = json.loads(path.read_text())
        if "signing" not in record:
            continue
        signing = record["signing"]
        if not isinstance(signing, dict):
            raise ValueError(f"invalid signing block: {path}")
        if signing.get("result") == "fail":
            if record.get("policy", {}).get("eligible") is not False or not signing.get("failure"):
                raise ValueError(f"invalid quarantine record: {path}")
            continue
        signed.append(signed_record(record, path, identity))
    if not signed:
        if previous:
            raise ValueError("reverify: signed records missing")
        print("reverify: no signed records yet")
    return signed


def cosign(*args):
    result = subprocess.run(["cosign", *args], capture_output=True, check=True)
    if not result.stdout.strip():
        raise ValueError(f"cosign {args[0]} returned empty output")
    return result.stdout


def verify(image, signature_hash, attestation_hash, identity):
    digest = image.split("@", 1)[1]
    package = image.split("@", 1)[0]
    flags = ["--certificate-identity", identity["certificate_identity"],
             "--certificate-oidc-issuer", identity["certificate_oidc_issuer"]]
    signature = json.loads(cosign("verify", *flags, image))
    if not isinstance(signature, list) or not any(
        field(row, "critical", "image", "docker-manifest-digest") == digest for row in signature
    ):
        raise ValueError(f"signature digest mismatch: {image}")
    statement = statement_from_verified(cosign("verify-attestation", "--type", "cyclonedx", *flags, image))
    if (statement.get("predicateType") != PREDICATE_TYPE
            or field(statement, "predicate", "bomFormat") != "CycloneDX"
            or not any(field(row, "name") == package and field(row, "digest", "sha256") == digest[7:]
                       for row in statement.get("subject", []))):
        raise ValueError(f"attestation digest or type mismatch: {image}")
    for args, expected in ((["download", "signature", image], signature_hash),
                           (["download", "attestation", "--predicate-type", PREDICATE_TYPE, image], attestation_hash)):
        if hashlib.sha256(cosign(*args)).hexdigest() != expected:
            raise ValueError(f"public {args[1]} attachment mismatch: {image}")
    print(f"reverify: pass {image}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    try:
        identity = load_identity(ROOT / "config/signing-identity.json")
        records = signed_records(args.base, identity)
        for record in records:
            verify(*record, identity)
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            reason = f"cosign {error.cmd[1]} failed"
        elif isinstance(error, ValueError):
            reason = str(error)
        else:
            reason = type(error).__name__
        print(f"FATAL: reverify failed ({reason})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
