"""Recheck public signed provenance with the checked-out Cosign pin."""

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from promote_signing_gate import IMAGE_RE, PREDICATE_TYPE, SIGNATURE_TYPE, downloaded_rows, field, load_identity, statement_from_verified

ROOT = Path(__file__).resolve().parent.parent
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
VERSION = re.compile(r"v?\d+\.\d+\.\d+\Z")
SCHEMA = "trusted-images.bocklabs.dev/provenance-v1"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def merged_commit(reference="origin/main"):
    commit = git("rev-parse", "--verify", reference + "^{commit}").decode().strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("provenance lookup needs an immutable merged commit")
    git("merge-base", "--is-ancestor", commit, "origin/main")
    return commit


def record_time(record):
    value = datetime.fromisoformat(record["promoted_at"].replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise ValueError("publication timestamp requires timezone")
    return value


def record_identity(record, app):
    if not isinstance(record, dict):
        raise ValueError("provenance record must be an object")
    for field_name in ("internal", "upstream", "policy", "validation"):
        if field_name in record and not isinstance(record[field_name], dict):
            raise ValueError(f"provenance {field_name} must be an object")
    internal = record.get("internal", {})
    upstream = record.get("upstream", {})
    if (record.get("schema") != SCHEMA or record.get("app") != app
            or not isinstance(app, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", app)
            or internal.get("package") != f"ghcr.io/bocklabs/{app}"
            or not isinstance(upstream.get("tag"), str)
            or not re.fullmatch(re.escape(upstream["tag"]) + r"-bocklabs\.[1-9][0-9]*", str(internal.get("tag", "")))
            or not IMAGE_RE.fullmatch(f"{internal.get('package')}@{internal.get('digest')}")
            or not isinstance(internal.get("platforms"), list) or not internal["platforms"]
            or any(not isinstance(p, str) or not re.fullmatch(r"[a-z0-9_-]+/[a-z0-9_-]+", p) for p in internal["platforms"])
            or record.get("policy", {}).get("eligible") is not None and not isinstance(record["policy"]["eligible"], bool)):
        raise ValueError(f"invalid provenance identity: {app}")
    record_time(record)
    return internal["tag"], internal["digest"]


def verified_record(record, app, identity):
    record_identity(record, app)
    signing = record.get("signing")
    if signing is None:
        return False
    if not isinstance(signing, dict):
        raise ValueError("invalid signing block")
    if signing.get("result") == "fail":
        if record.get("policy", {}).get("eligible") is not False or not signing.get("failure"):
            raise ValueError("invalid quarantine record")
        return False
    signed_record(record, Path("provenance") / app / "current.json", identity)
    return True


def replacement(previous, candidate, app, identity):
    if not verified_record(candidate, app, identity):
        raise ValueError("current replacement must be signed and eligible")
    if previous is None:
        return True
    old_tag, old_digest = record_identity(previous, app)
    verified_record(previous, app, identity)
    tag, digest = record_identity(candidate, app)
    if tag == old_tag:
        if digest != old_digest:
            raise ValueError("same-tag provenance digest disagreement")
        return False
    if (record_time(candidate) <= record_time(previous)
            or (candidate["upstream"]["tag"] == previous["upstream"]["tag"]
                and int(tag.rsplit(".", 1)[1]) < int(old_tag.rsplit(".", 1)[1]))):
        raise ValueError("stale current provenance replacement")
    return True


def selected_snapshot(rows, app, identity):
    eligible = [row for row in rows if verified_record(json.loads(row), app, identity)]
    choices = eligible or rows
    latest = max(record_time(json.loads(row)) for row in choices)
    selected = [row for row in choices if record_time(json.loads(row)) == latest]
    identities = {record_identity(json.loads(row), app) for row in selected}
    if len(identities) != 1 or len(set(selected)) != 1:
        raise ValueError("conflicting latest provenance snapshots")
    return selected[0]


def git_record(commit, path):
    present = git("ls-tree", "--name-only", commit, "--", path).decode().splitlines()
    return git("show", f"{commit}:{path}") if path in present else None


def historical_rows(commit, path, app, tag):
    commits = git("log", "--format=%H", commit, "--", path).decode().splitlines()
    found = []
    for revision in dict.fromkeys([commit, *commits]):
        data = git_record(revision, path)
        if data is not None:
            actual_tag = record_identity(json.loads(data), app)[0]
            if actual_tag != tag and not path.endswith("/current.json"):
                raise ValueError("historical tag/path disagreement")
            if actual_tag == tag:
                found.append(data)
    return found


def resolve_record(app, tag, commit=None):
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", app) or not re.fullmatch(r"[^/]+-bocklabs\.[1-9][0-9]*", tag):
        raise ValueError("invalid exact provenance lookup")
    commit = merged_commit(commit or "origin/main")
    paths = (f"provenance/{app}/current.json", f"provenance/{app}/{tag}.json")
    current = git_record(commit, paths[0])
    if current is not None and record_identity(json.loads(current), app)[0] == tag:
        return current
    found = historical_rows(commit, paths[1], app, tag) or historical_rows(commit, paths[0], app, tag)
    if not found:
        return None
    if len({record_identity(json.loads(data), app) for data in found}) != 1:
        raise ValueError("conflicting historical provenance identity")
    return found[0]


def load_current(app, commit=None):
    data = git_record(commit, f"provenance/{app}/current.json") if commit else None
    if commit is None:
        path = ROOT / "provenance" / app / "current.json"
        if path.is_symlink() or path.parent.is_symlink():
            raise ValueError("unsafe current provenance file")
        data = path.read_bytes() if path.is_file() else None
    if data is None:
        return None
    record = json.loads(data)
    record_identity(record, app)
    return record


def write_current(path, record, identity):
    if path.name != "current.json" or path.parent.parent.name != "provenance" or path.is_symlink():
        raise ValueError("current provenance must use provenance/<app>/current.json")
    app = path.parent.name
    previous = json.loads(path.read_bytes()) if path.is_file() else None
    if record.get("recovery"):
        raise ValueError("historical recovery provenance belongs in run artifacts")
    if not replacement(previous, record, app, identity):
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2) + "\n")
    return True


def migrate_current(identity):
    grouped: dict[str, list[bytes]] = {}
    paths = sorted((ROOT / "provenance").glob("*/*.json"))
    for path in paths:
        if path.is_symlink() or path.name == "current.json":
            raise ValueError("migration requires unchanged regular versioned inputs")
        if path.stem != record_identity(json.loads(path.read_bytes()), path.parent.name)[0]:
            raise ValueError("migration tag/path disagreement")
        grouped.setdefault(path.parent.name, []).append(path.read_bytes())
    selected = {app: selected_snapshot(rows, app, identity) for app, rows in grouped.items()}
    for app, data in selected.items():
        (ROOT / "provenance" / app / "current.json").write_bytes(data)
    for path in paths:
        path.unlink()
    return selected


def validate_current_tree(previous_apps, identity):
    provenance = ROOT / "provenance"
    if provenance.is_symlink() or (provenance.exists() and any(p.is_symlink() for p in provenance.iterdir())):
        raise ValueError("unsafe provenance directory")
    current_paths = sorted((ROOT / "provenance").rglob("*.json"))
    for path in current_paths:
        if path.name != "current.json" or path.is_symlink() or len(path.relative_to(ROOT).parts) != 3:
            raise ValueError("live provenance must contain only one regular current.json per app")
        record_identity(json.loads(path.read_bytes()), path.parent.name)
        if path.parent.name not in previous_apps and not verified_record(json.loads(path.read_bytes()), path.parent.name, identity):
            raise ValueError("new current record must be signed and eligible")


def validate_previous_current(app, rows, was_current, identity):
    path = ROOT / "provenance" / app / "current.json"
    if not path.is_file():
        raise ValueError("current provenance missing")
    original = selected_snapshot(rows, app, identity)
    old = json.loads(original)
    current = json.loads(path.read_bytes())
    if not was_current and path.read_bytes() != original:
        raise ValueError("migration differs from selected merged snapshot")
    if was_current and path.read_bytes() != original and not replacement(old, current, app, identity):
        raise ValueError("same identity must preserve original current bytes")
    if verified_record(old, app, identity):
        if not verified_record(current, app, identity):
            raise ValueError("signed current provenance lost")
        return str(path.relative_to(ROOT))
    return None


def check_history(base):
    paths = git("ls-tree", "-r", "--name-only", base, "--", "provenance").decode().splitlines()
    identity = load_identity(ROOT / "config/signing-identity.json")
    previous_apps: dict[str, list[bytes]] = {}
    for name in paths:
        if name.endswith(".json"):
            path = Path(name)
            if len(path.parts) != 3:
                raise ValueError("invalid baseline provenance path")
            previous_apps.setdefault(path.parent.name, []).append(git("show", f"{base}:{name}"))
    validate_current_tree(previous_apps, identity)
    return {name for app, rows in previous_apps.items()
            if (name := validate_previous_current(app, rows, f"provenance/{app}/current.json" in paths, identity))}


def signed_record(record, path, identity) -> tuple[str, str, str]:
    if not isinstance(record, dict):
        raise ValueError("signed provenance record must be an object")
    record_identity(record, record.get("app"))
    signing = record.get("signing")
    if not isinstance(signing, dict):
        raise ValueError("provenance signing must be an object")
    for field_name in ("image_signature", "sbom_attestation", "tools", "rekor"):
        if field_name in signing and not isinstance(signing[field_name], dict):
            raise ValueError(f"provenance signing.{field_name} must be an object")
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
            or record.get("validation", {}).get("result") != "pass" or internal.get("platforms") != ["linux/amd64"]
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


def signed_records(base, identity) -> list[tuple[str, str, str]]:
    previous = check_history(base)
    records = sorted((ROOT / "provenance").glob("*/current.json"))
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
    verified_attestation = cosign("verify-attestation", "--type", "cyclonedx", *flags, image)
    attachments = {}
    for predicate_type, expected in ((SIGNATURE_TYPE, signature_hash), (PREDICATE_TYPE, attestation_hash)):
        data = cosign("download", "attestation", "--predicate-type", predicate_type, image)
        selected = next((row for row, raw in downloaded_rows(data)
                         if hashlib.sha256(raw).hexdigest() == expected), None)
        if selected is None:
            raise ValueError(f"public attestation attachment mismatch: {image}")
        attachments[predicate_type] = selected
    expected_statement = json.loads(base64.b64decode(
        attachments[PREDICATE_TYPE]["dsseEnvelope"]["payload"], validate=True
    ))
    statement = statement_from_verified(verified_attestation, expected_statement)
    if (statement.get("predicateType") != PREDICATE_TYPE
            or field(statement, "predicate", "bomFormat") != "CycloneDX"
            or not any(field(row, "name") == package and field(row, "digest", "sha256") == digest[7:]
                       for row in statement.get("subject", []))):
        raise ValueError(f"attestation digest or type mismatch: {image}")
    print(f"reverify: pass {image}")


def reverify(args):
    if args.resolve:
        data = resolve_record(args.resolve, args.tag, merged_commit(args.commit))
        if data is None:
            sys.stdout.write("null\n")
        else:
            sys.stdout.buffer.write(data)
        return
    if args.migrate:
        migrate_current(load_identity(ROOT / "config/signing-identity.json"))
        return
    if args.compare:
        identity = load_identity(ROOT / "config/signing-identity.json")
        candidate = json.loads(args.compare.read_bytes())
        previous = json.loads(args.previous.read_bytes()) if args.previous and args.previous.is_file() else None
        print("update" if replacement(previous, candidate, candidate["app"], identity) else "unchanged")
        return
    if args.history_only:
        check_history(args.history_only)
        return
    identity = load_identity(ROOT / "config/signing-identity.json")
    if args.record:
        record = json.loads(args.record.read_text())
        records = [signed_record(record, args.record, identity)]
    else:
        records = signed_records(args.base, identity)
    for entry in records:
        verify(*entry, identity)
    if args.out:
        args.out.write_text(json.dumps({
            "result": "pass", "reused_provenance": str(args.record),
            "original_run_url": record["pipeline"]["run_url"],
            "image": records[0][0], **identity,
        }) + "\n")


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--base")
    mode.add_argument("--record", type=Path)
    mode.add_argument("--history-only")
    mode.add_argument("--resolve")
    mode.add_argument("--migrate", action="store_true")
    mode.add_argument("--compare", type=Path)
    parser.add_argument("--previous", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--commit", default="origin/main")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    if args.out and not args.record:
        parser.error("--out requires --record")
    if args.resolve and not args.tag:
        parser.error("--resolve requires --tag")
    try:
        reverify(args)
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as error:
        if isinstance(error, subprocess.CalledProcessError):
            reason = f"{error.cmd[0]} {error.cmd[1]} failed"
        elif isinstance(error, ValueError):
            reason = str(error)
        else:
            reason = type(error).__name__
        if args.out:
            args.out.write_text(json.dumps({"result": "fail", "reason": reason}) + "\n")
        print(f"FATAL: reverify failed ({reason})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
