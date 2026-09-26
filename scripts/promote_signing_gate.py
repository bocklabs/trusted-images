"""Verify and record Cosign evidence for one published image digest."""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

IMAGE_RE = re.compile(r"^ghcr\.io/bocklabs/[a-z0-9][a-z0-9._-]*@(sha256:[a-f0-9]{64})$")
PREDICATE_TYPE = "https://cyclonedx.org/bom"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def field(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def load_identity(path):
    value = json.loads(path.read_text())
    if not isinstance(value, dict) or set(value) != {"certificate_identity", "certificate_oidc_issuer"}:
        raise ValueError("identity config must contain only identity and issuer")
    if not all(isinstance(item, str) and item for item in value.values()):
        raise ValueError("identity config values are missing")
    return value


def run_cosign(*args, output=None):
    result = subprocess.run(["cosign", *args], capture_output=True, check=True)
    if not result.stdout.strip():
        raise ValueError(f"cosign {args[0]} returned empty output")
    if output:
        Path(output).write_bytes(result.stdout)
    return result.stdout


def read_bundle(path, content_key):
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or not value.get(content_key):
        raise ValueError(f"{path.name} lacks {content_key}")
    material = value.get("verificationMaterial", {})
    if not isinstance(material, dict):
        raise ValueError(f"{path.name} has malformed verification material")
    if not material.get("certificate") and not material.get("x509CertificateChain"):
        raise ValueError(f"{path.name} lacks certificate")
    entries = material.get("tlogEntries") or []
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        raise ValueError(f"{path.name} lacks Rekor entry")
    entry = entries[0]
    if not all(isinstance(entry.get(key, {}), dict) for key in ("logId", "inclusionPromise", "inclusionProof")):
        raise ValueError(f"{path.name} has malformed Rekor entry")
    log_id = entry.get("logId", {}).get("keyId")
    timestamp = entry.get("inclusionPromise", {}).get("signedEntryTimestamp")
    proof = entry.get("inclusionProof", {})
    if not str(entry.get("logIndex", "")).isdigit() or not log_id or not (timestamp or proof.get("rootHash")):
        raise ValueError(f"{path.name} lacks Rekor log index, ID, or inclusion material")
    return value, {
        "log_index": int(entry["logIndex"]), "log_id": log_id,
        "signed_entry_timestamp": timestamp,
        "inclusion_root_hash": proof.get("rootHash"),
    }, digest(raw)


def statement_from_verified(data):
    rows = json.loads(data)
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise ValueError("verified attestation is empty")
    payload = rows[0].get("payload")
    if not isinstance(payload, str) or not payload:
        raise ValueError("verified attestation has no payload")
    statement = json.loads(base64.b64decode(payload, validate=True))
    if not isinstance(statement, dict):
        raise ValueError("verified attestation payload is not a statement")
    return statement


def downloaded_rows(data):
    rows = [json.loads(line) for line in data.splitlines() if line.strip()]
    if not rows or not all(isinstance(row, dict) for row in rows):
        raise ValueError("downloaded attachment is not JSON evidence")
    return rows


def build_evidence(args):
    match = IMAGE_RE.fullmatch(args.image)
    if not match:
        raise ValueError("image must be an exact lowercase GHCR digest reference")
    image_digest = match.group(1)
    identity = load_identity(args.identity_config)
    sign, sign_rekor, sign_hash = read_bundle(args.sign_bundle, "messageSignature")
    sbom, sbom_rekor, sbom_hash = read_bundle(args.sbom_bundle, "dsseEnvelope")
    predicate = json.loads(args.predicate.read_bytes())
    if not isinstance(predicate, dict) or predicate.get("bomFormat") != "CycloneDX":
        raise ValueError("predicate is not a CycloneDX BOM")
    flags = ["--certificate-identity", identity["certificate_identity"],
             "--certificate-oidc-issuer", identity["certificate_oidc_issuer"]]
    verified_signature = run_cosign("verify", *flags, args.image, output="verify-signature.json")
    rows = json.loads(verified_signature)
    if not isinstance(rows, list) or not rows or not any(
        field(row, "critical", "image", "docker-manifest-digest") == image_digest for row in rows
    ):
        raise ValueError("verified signature subject digest differs")
    verified_attestation = run_cosign("verify-attestation", "--type", "cyclonedx", *flags,
                                      args.image, output="verify-attestation.json")
    statement = statement_from_verified(verified_attestation)
    subjects = statement.get("subject") or []
    if statement.get("predicateType") != PREDICATE_TYPE or statement.get("predicate") != predicate:
        raise ValueError("verified CycloneDX predicate differs")
    if not isinstance(subjects, list) or not any(field(subject, "name") == args.image.split("@")[0] and
               field(subject, "digest", "sha256") == image_digest[7:] for subject in subjects):
        raise ValueError("verified attestation subject digest differs")
    local_statement = json.loads(base64.b64decode(sbom["dsseEnvelope"]["payload"], validate=True))
    if local_statement != statement:
        raise ValueError("local attestation bundle differs from verified attachment")
    signature_attachment = run_cosign("download", "signature", args.image,
                                      output="signature-attachment.json")
    attestation_attachment = run_cosign("download", "attestation", "--predicate-type", PREDICATE_TYPE,
                                        args.image, output="sbom-attestation-attachment.json")
    local_signature = base64.b64decode(sign["messageSignature"]["signature"], validate=True)
    matched_signature = False
    for row in downloaded_rows(signature_attachment):
        signature = row.get("Base64Signature")
        payload = row.get("Payload")
        if not isinstance(signature, str) or not signature or not isinstance(payload, str) or not payload:
            raise ValueError("downloaded signature lacks signature or payload")
        signed_payload = json.loads(base64.b64decode(payload, validate=True))
        if not isinstance(signed_payload, dict) or not isinstance(signed_payload.get("Critical"), dict) or not isinstance(signed_payload["Critical"].get("Image"), dict):
            raise ValueError("downloaded signature payload is malformed")
        if signed_payload["Critical"]["Image"].get("Docker-manifest-digest") != image_digest:
            raise ValueError("downloaded signature subject digest differs")
        matched_signature |= base64.b64decode(signature, validate=True) == local_signature
    if not local_signature or not matched_signature:
        raise ValueError("downloaded signature differs from local bundle")
    matched_attestation = False
    for row in downloaded_rows(attestation_attachment):
        if not isinstance(row.get("payloadType"), str) or not isinstance(row.get("payload"), str) or not row.get("signatures"):
            raise ValueError("downloaded attestation is not a DSSE envelope")
        matched_attestation |= row == sbom["dsseEnvelope"]
    if not matched_attestation:
        raise ValueError("downloaded attestation differs from local bundle")
    version = re.search(r"(?m)^GitVersion:\s*(v\d+\.\d+\.\d+)\s*$", run_cosign("version").decode())
    if not version:
        raise ValueError("Cosign version is not a release semver")
    return {
        "result": "pass", "image": args.image, "digest": image_digest,
        **identity, "cosign_version": version.group(1),
        "signature": {"bundle_sha256": sign_hash, "attachment_sha256": digest(signature_attachment),
                      "rekor": sign_rekor},
        "sbom_attestation": {"predicate_type": PREDICATE_TYPE,
                             "predicate_sha256": digest(args.predicate.read_bytes()),
                             "bundle_sha256": sbom_hash,
                             "attachment_sha256": digest(attestation_attachment),
                             "rekor": sbom_rekor},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--identity-config", type=Path, required=True)
    parser.add_argument("--sign-bundle", type=Path, required=True)
    parser.add_argument("--sbom-bundle", type=Path, required=True)
    parser.add_argument("--predicate", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        evidence = build_evidence(args)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        reason = (error.cmd[1] if isinstance(error, subprocess.CalledProcessError)
                  else str(error) if isinstance(error, ValueError) else type(error).__name__)
        args.out.write_text(json.dumps({"result": "fail", "reason": reason}) + "\n")
        print(f"FATAL: signing gate failed ({reason})", file=sys.stderr)
        return 1
    args.out.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
