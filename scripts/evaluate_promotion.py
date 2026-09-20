#!/usr/bin/env python3
"""Emit one strict candidate-decision document for a linux/amd64 candidate."""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from univers.versions import AlpineLinuxVersion, DebianVersion, RpmVersion

SCHEMA = "trusted-images.bocklabs.dev/candidate-decision-v1"
ACCEPTANCE_SCHEMA = "trusted-images.bocklabs.dev/risk-acceptance-v1"
PLATFORM = "linux/amd64"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
TRIVY_VERSION = "0.74.0"
TRIVY_ACTION_SHA = "ed142fd0673e97e23eac54620cfb913e5ce36c25"
COPA_CLASSIFICATIONS = ("not-required", "pending", "succeeded", "unsupported", "no-fix", "eol", "gpg", "unknown")
PATCH_DISABLED_CLASSES = ("unsupported", "no-fix")
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
SHA40_RE = re.compile(r"^[a-f0-9]{40}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
LEVELS = ("LOW", "MEDIUM", "HIGH")
POLICY_NOW = "policy now"
KEV_CATALOG = "KEV catalog"
IMAGE_MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
CONFIG_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
VERSION_CLASSES = {
    "alpine": AlpineLinuxVersion,
    "debian": DebianVersion,
    "ubuntu": DebianVersion,
    "redhat": RpmVersion,
    "centos": RpmVersion,
    "rocky": RpmVersion,
    "alma": RpmVersion,
    "almalinux": RpmVersion,
    "amazon": RpmVersion,
    "oracle": RpmVersion,
}


def parse_args():
    resolve_only = "--resolve-only" in sys.argv
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=not resolve_only)
    parser.add_argument("--source-sha", required=not resolve_only)
    parser.add_argument("--run-id", required=not resolve_only)
    parser.add_argument("--run-attempt", required=not resolve_only, type=int)
    parser.add_argument("--proposed-tag", required=not resolve_only)
    parser.add_argument("--index", required=not resolve_only)
    parser.add_argument("--upstream-index-digest", required=not resolve_only)
    parser.add_argument("--child-manifest", required=not resolve_only)
    parser.add_argument("--child-config", required=not resolve_only)
    parser.add_argument("--full-report", required=not resolve_only)
    parser.add_argument("--fixable-report", required=not resolve_only)
    parser.add_argument("--after-full-report")
    parser.add_argument("--scan-receipt")
    parser.add_argument("--kev", required=not resolve_only)
    parser.add_argument("--kev-fetched-at", required=not resolve_only)
    parser.add_argument("--now", required=not resolve_only)
    parser.add_argument("--acceptance")
    parser.add_argument("--github-evidence")
    parser.add_argument("--github-repository")
    parser.add_argument("--validation-result", required=not resolve_only, choices=("pass", "fail"))
    parser.add_argument("--patch-policy", choices=("enabled", "disabled"), default="enabled")
    parser.add_argument("--patch-disabled-class")
    parser.add_argument("--patch-disabled-detail")
    parser.add_argument("--copa-classification", choices=COPA_CLASSIFICATIONS)
    parser.add_argument("--candidate-digest")
    parser.add_argument("--resume-original-run-id")
    parser.add_argument("--resume-original-run-attempt", type=int)
    parser.add_argument("--resume-original-source-sha")
    parser.add_argument("--resume-artifact-id", type=int)
    parser.add_argument("--resolve-only", action="store_true")
    parser.add_argument("--selected-digest-out")
    parser.add_argument("--out", required=not resolve_only)
    return parser.parse_args()


def load_json(path: Path, label: str):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is unreadable or invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


FRACTION_RE = re.compile(r"^(?P<head>.*\.)(?P<frac>\d+)(?P<tail>Z|[+-]\d{2}:?\d{2})$")
GO_TIME_RE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<clock>\d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: (?P<off>[+-]\d{4}))? UTC$")


def parse_time(value: str, label: str) -> datetime:
    try:
        normalized = value
        go = GO_TIME_RE.match(value)
        if go:
            offset = (go.group("off") or "+0000")
            normalized = f"{go.group('date')}T{go.group('clock')}{offset[:3]}:{offset[3:]}"
        match = FRACTION_RE.match(value)
        if match:
            tail = match.group("tail")
            tail = "+00:00" if tail == "Z" else tail
            normalized = f"{match.group('head')}{match.group('frac')[:6].ljust(6, '0')}{tail}"
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO-8601 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{label} must be a UTC timestamp")
    return parsed.astimezone(timezone.utc)


def descriptor(value, label: str):
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    digest = value.get("digest")
    media_type = value.get("mediaType")
    size = value.get("size")
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise ValueError(f"{label}.digest must be a sha256 digest")
    if not isinstance(media_type, str) or not media_type:
        raise ValueError(f"{label}.mediaType must be a non-empty string")
    if isinstance(size, bool) or not isinstance(size, int) or size <= 0:
        raise ValueError(f"{label}.size must be a positive integer")
    return value


def select_amd64_child(index: dict) -> dict:
    if index.get("mediaType") not in INDEX_TYPES:
        raise ValueError("upstream index mediaType is not an OCI/Docker index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ValueError("upstream index carries no manifests")
    amd64 = []
    for number, item in enumerate(manifests):
        descriptor(item, f"index.manifests[{number}]")
        platform = item.get("platform")
        if isinstance(platform, dict) and platform.get("os") == "linux" and platform.get("architecture") == "amd64":
            amd64.append(item)
    if len(amd64) != 1:
        raise ValueError(f"upstream index must contain exactly one linux/amd64 child (found {len(amd64)})")
    selected = amd64[0]
    if selected["platform"].get("variant") not in (None, ""):
        raise ValueError("selected linux/amd64 child carries an unsupported variant")
    descriptor(selected, "selected child")
    return selected


def validate_child_manifest(selected: dict, manifest_path: Path, config_path: Path):
    manifest = load_json(manifest_path, "child manifest")
    if manifest.get("mediaType") not in IMAGE_MANIFEST_TYPES:
        raise ValueError("selected child is not an image manifest")
    if "manifests" in manifest:
        raise ValueError("candidate manifests may not be an index")
    if sha256_file(manifest_path) != selected["digest"]:
        raise ValueError("child manifest digest does not match the index descriptor")
    if manifest_path.stat().st_size != selected["size"]:
        raise ValueError("child manifest size does not match the index descriptor")
    config_descriptor = descriptor(manifest.get("config"), "child config descriptor")
    if config_descriptor["mediaType"] not in CONFIG_TYPES:
        raise ValueError("child config mediaType is invalid")
    config = load_json(config_path, "child config")
    if sha256_file(config_path) != config_descriptor["digest"]:
        raise ValueError("child config digest does not match the manifest descriptor")
    if config_path.stat().st_size != config_descriptor["size"]:
        raise ValueError("child config size does not match the manifest descriptor")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError("child config platform disagrees with linux/amd64")


def select_child(index: dict, manifest_path: Path, config_path: Path):
    selected = select_amd64_child(index)
    validate_child_manifest(selected, manifest_path, config_path)
    return selected["digest"]


def validate_report_results(report: dict, label: str, os_only: bool) -> list:
    if report.get("SchemaVersion") != 2:
        raise ValueError(f"{label}.SchemaVersion must be 2")
    results = report.get("Results")
    if not isinstance(results, list):
        raise ValueError(f"{label}.Results must be an array")
    for number, result in enumerate(results):
        if not isinstance(result, dict):
            raise ValueError(f"{label}.Results[{number}] is not an object")
        if os_only and result.get("Class") != "os-pkgs":
            raise ValueError(f"{label}.Results[{number}] is not an os-pkgs result")
    return results


def finding_identity(finding: dict, label: str) -> tuple[str, str, str, str]:
    cve = finding.get("VulnerabilityID")
    package = finding.get("PkgName")
    severity = finding.get("Severity")
    source = finding.get("SeveritySource", "")
    if not all(isinstance(value, str) and value for value in (cve, package, severity)):
        raise ValueError(f"{label} finding lacks VulnerabilityID, PkgName, or Severity")
    if not isinstance(source, str):
        raise ValueError(f"{label}.SeveritySource must be a string")
    if "|" in package:
        raise ValueError(f"{label} package identity contains the reserved delimiter |")
    return cve, package, severity, source


def finding_metadata(result: dict, finding: dict, severity: str, source: str, label: str) -> dict:
    metadata = {
        "class": result.get("Class", ""),
        "type": result.get("Type", ""),
        "target": result.get("Target", ""),
        "installed_version": finding.get("InstalledVersion", ""),
        "fixed_version": finding.get("FixedVersion", ""),
        "severity": severity,
        "severity_source": source,
    }
    if not all(isinstance(value, str) for value in metadata.values()):
        raise ValueError(f"{label} finding carries malformed ecosystem or target metadata")
    if not all(metadata[key] for key in ("class", "type", "target")):
        raise ValueError(f"{label} finding lacks ecosystem or target metadata")
    return metadata


def findings(report: dict, label: str, os_only=False):
    results = validate_report_results(report, label, os_only)
    normalized = {}
    for result_number, result in enumerate(results):
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"{label}.Results[{result_number}].Vulnerabilities must be an array")
        for finding in vulnerabilities:
            if not isinstance(finding, dict):
                raise ValueError(f"{label} contains a non-object finding")
            cve, package, severity, source = finding_identity(finding, label)
            metadata = finding_metadata(result, finding, severity, source, label)
            key = f"{PLATFORM}|{package}|{cve}"
            if key in normalized and normalized[key] != metadata:
                raise ValueError(f"{label} has conflicting duplicate finding: {key}")
            normalized[key] = metadata
    return normalized


def package_version(package: dict) -> str:
    version = package.get("Version")
    if not isinstance(version, str) or not version:
        raise ValueError("package Version must be a non-empty string")
    epoch = package.get("Epoch", 0)
    release = package.get("Release", "")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0 or not isinstance(release, str):
        raise ValueError("package Epoch or Release is invalid")
    value = f"{epoch}:{version}" if epoch else version
    return f"{value}-{release}" if release else value


def report_os_family(report: dict, label: str) -> str:
    metadata = report.get("Metadata", {})
    if not isinstance(metadata, dict):
        raise ValueError(f"{label} Metadata must be an object")
    os_metadata = metadata.get("OS", {})
    if not isinstance(os_metadata, dict):
        raise ValueError(f"{label} Metadata.OS must be an object")
    os_family = os_metadata.get("Family", "")
    if not isinstance(os_family, str):
        raise ValueError(f"{label} Metadata.OS.Family must be a string")
    return os_family


def package_ecosystem(result: dict, os_family: str, label: str) -> str:
    ecosystem = result.get("Type")
    if not isinstance(ecosystem, str) or ecosystem not in VERSION_CLASSES:
        raise ValueError(f"unsupported ecosystem: {ecosystem!r}")
    if os_family not in VERSION_CLASSES or VERSION_CLASSES[ecosystem] is not VERSION_CLASSES[os_family]:
        raise ValueError(f"report distro metadata disagrees with package ecosystem: {os_family!r}")
    if "Packages" not in result:
        raise ValueError(f"{label} has a missing package inventory")
    packages = result["Packages"]
    if not isinstance(packages, list):
        raise ValueError(f"{label}.Packages must be an array")
    return ecosystem


def add_packages(inventory: dict, packages: list, ecosystem: str, label: str) -> None:
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError(f"{label}.Packages contains a non-object package")
        name = package.get("Name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{label}.Packages contains a package without Name")
        key = (ecosystem, name)
        if key in inventory:
            raise ValueError(f"{label} has conflicting duplicate package identity (ambiguous package identity): {ecosystem}/{name}")
        version = package_version(package)
        try:
            VERSION_CLASSES[ecosystem](version)
        except ValueError as exc:
            raise ValueError(f"malformed version for {ecosystem}/{name}: {version}") from exc
        inventory[key] = {"ecosystem": ecosystem, "name": name, "version": version}


def package_inventory(report: dict, label: str):
    inventory = {}
    os_family = report_os_family(report, label)
    for result in report.get("Results", []):
        if result.get("Class") != "os-pkgs":
            continue
        ecosystem = package_ecosystem(result, os_family, label)
        add_packages(inventory, result["Packages"], ecosystem, label)
    return inventory


def package_changes(before: dict, after: dict):
    changes = []
    downgrades = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old and not new:
            change = {"ecosystem": old["ecosystem"], "name": old["name"], "change": "removed", "before": old["version"], "after": None}
            changes.append(change)
        elif new and not old:
            change = {"ecosystem": new["ecosystem"], "name": new["name"], "change": "added", "before": None, "after": new["version"]}
            changes.append(change)
        elif old and new:
            comparator = VERSION_CLASSES[old["ecosystem"]]
            if comparator(new["version"]) < comparator(old["version"]):
                change = {"ecosystem": old["ecosystem"], "name": old["name"], "change": "downgraded", "before": old["version"], "after": new["version"]}
                downgrades.append(change)
            elif comparator(new["version"]) > comparator(old["version"]):
                change = {"ecosystem": old["ecosystem"], "name": old["name"], "change": "upgraded", "before": old["version"], "after": new["version"]}
                changes.append(change)
    return sorted(changes, key=lambda item: (item["ecosystem"], item["name"])), sorted(downgrades, key=lambda item: (item["ecosystem"], item["name"]))


def cve_groups(groups: dict) -> dict:
    return {
        name: sorted({identity.split("|", 2)[2] for identity in values})
        for name, values in groups.items()
    }


def validate_scan_report(report: dict, path: Path, label: str, side: dict):
    trivy = report.get("Trivy", {})
    if not isinstance(trivy, dict) or trivy.get("Version") != TRIVY_VERSION:
        raise ValueError(f"{label} Trivy version receipt does not match {TRIVY_VERSION}")
    if report.get("ArtifactType") != "container_image":
        raise ValueError(f"{label} is not a container_image report")
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError(f"{label} Metadata must be an object")
    config = metadata.get("ImageConfig")
    if not isinstance(config, dict) or config.get("os") != "linux" or config.get("architecture") != "amd64":
        raise ValueError(f"{label} report platform is not linux/amd64")
    os_metadata = metadata.get("OS")
    if not isinstance(os_metadata, dict) or not isinstance(os_metadata.get("Family"), str) or not os_metadata["Family"] or not isinstance(os_metadata.get("Name"), str):
        raise ValueError(f"{label} report OS metadata is invalid")
    if os_metadata.get("EOSL") not in (True, False, None):
        raise ValueError(f"{label} report OS EOSL is invalid")
    if os_metadata.get("EOSL") is True:
        raise ValueError(f"{label} report OS EOSL is true")
    if report.get("ArtifactName") != side.get("artifact_name") or metadata.get("ImageID") != side.get("image_id"):
        raise ValueError(f"{label} image identity/report receipt does not match its scan receipt")
    if sha256_file(path).split(":", 1)[1] != side.get("report_sha256"):
        raise ValueError(f"{label} image identity/report receipt does not match its scan receipt")


def validate_receipt_side(side: object, name: str, expected_digest: str) -> dict:
    side_fields = {"artifact_name", "image_id", "manifest_digest", "report_sha256"}
    if not isinstance(side, dict) or set(side) != side_fields:
        raise ValueError(f"scan receipt {name} has unknown or missing fields")
    if not isinstance(side["artifact_name"], str) or not side["artifact_name"]:
        raise ValueError(f"scan receipt {name} artifact_name is invalid")
    if not isinstance(side["image_id"], str) or not DIGEST_RE.fullmatch(side["image_id"]):
        raise ValueError(f"scan receipt {name} image_id is invalid")
    if side["manifest_digest"] != expected_digest:
        raise ValueError(f"scan receipt {name} manifest receipt does not match the candidate identity")
    if not isinstance(side["report_sha256"], str) or not SHA256_RE.fullmatch(side["report_sha256"]):
        raise ValueError(f"scan receipt {name} report_sha256 is invalid")
    return side


def validate_scan_receipt(receipt: dict, before_path: Path, after_path: Path, before: dict, after: dict, now: str, child_digest: str, candidate_digest: str):
    required = {"trivy_action_sha", "trivy_db_digest", "trivy_db_updated_at", "before", "after"}
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise ValueError("scan receipt has unknown or missing fields")
    if receipt["trivy_action_sha"] != TRIVY_ACTION_SHA:
        raise ValueError("scan receipt action receipt does not match the pinned Trivy action SHA")
    if not isinstance(receipt["trivy_db_digest"], str) or not DIGEST_RE.fullmatch(receipt["trivy_db_digest"]):
        raise ValueError("scan receipt Trivy DB digest is invalid")
    if not isinstance(receipt["trivy_db_updated_at"], str):
        raise ValueError("scan receipt Trivy DB updated_at must be a string")
    db_updated = parse_time(receipt["trivy_db_updated_at"], "scan receipt Trivy DB updated_at")
    if db_updated > parse_time(now, POLICY_NOW):
        raise ValueError("scan receipt Trivy DB is future-dated")
    sides = {}
    expected_digests = {"before": child_digest, "after": candidate_digest}
    for name in ("before", "after"):
        sides[name] = validate_receipt_side(receipt[name], name, expected_digests[name])
    validate_scan_report(before, before_path, "before report", sides["before"])
    validate_scan_report(after, after_path, "after report", sides["after"])


def kev_evidence(path: Path, fetched_at: str, now: str):
    feed = load_json(path, KEV_CATALOG)
    required = ("title", "catalogVersion", "dateReleased", "count", "vulnerabilities")
    if any(not isinstance(feed.get(key), str) or not feed[key] for key in required[:3]):
        raise ValueError("KEV catalog lacks title, catalogVersion, or dateReleased")
    if feed["title"] != "CISA Catalog of Known Exploited Vulnerabilities":
        raise ValueError("KEV catalog title is not the canonical CISA feed")
    parse_time(feed["dateReleased"], "KEV dateReleased")
    count = feed.get("count")
    vulnerabilities = feed.get("vulnerabilities")
    if isinstance(count, bool) or not isinstance(count, int) or not isinstance(vulnerabilities, list):
        raise ValueError("KEV count or vulnerabilities has the wrong type")
    cves = []
    for item in vulnerabilities:
        if not isinstance(item, dict) or not isinstance(item.get("cveID"), str):
            raise ValueError("KEV vulnerability lacks cveID")
        cve = item["cveID"]
        if not CVE_RE.fullmatch(cve):
            raise ValueError(f"KEV cveID is malformed: {cve}")
        cves.append(cve)
    if count != len(cves) or len(cves) != len(set(cves)):
        raise ValueError("KEV count does not equal its unique CVE count")
    fetched = parse_time(fetched_at, "KEV fetched_at")
    current = parse_time(now, POLICY_NOW)
    if fetched > current or (current - fetched).total_seconds() > 24 * 3600:
        raise ValueError("KEV receipt is future-dated or older than 24 hours")
    return {
        "matched": [],
        "catalog": {
            "url": KEV_URL,
            "sha256": sha256_file(path).split(":", 1)[1],
            "fetched_at": fetched.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "count": count,
            "unique_cves": len(set(cves)),
            "catalog_version": feed["catalogVersion"],
            "date_released": feed["dateReleased"],
        },
    }


def exact_fields(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(f"{label} has unknown or missing fields")


def nonempty_string(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")


def acceptance_path(app: str, candidate_digest: str, kevs: list[str]) -> str:
    candidate_hash = hashlib.sha256(candidate_digest.encode()).hexdigest()
    kev_hash = hashlib.sha256("\n".join(kevs).encode()).hexdigest()
    return f"risk-acceptances/{app}/{candidate_hash}-{kev_hash}.json"


def validate_risk_assessment(value: dict):
    fields = {
        "schema", "candidateDigest", "kevs", "reason", "expiresAt", "likelihood",
        "impact", "owner", "reviewNotes", "trackingIssue",
    }
    exact_fields(value, fields, "risk acceptance")
    if value["schema"] != ACCEPTANCE_SCHEMA:
        raise ValueError("risk acceptance schema is invalid")
    if not isinstance(value["candidateDigest"], str) or not DIGEST_RE.fullmatch(value["candidateDigest"]):
        raise ValueError("risk acceptance candidateDigest is invalid")
    kevs = value["kevs"]
    if not isinstance(kevs, list) or not kevs or not all(isinstance(item, str) and CVE_RE.fullmatch(item) for item in kevs):
        raise ValueError("risk acceptance kevs must be a nonempty sorted unique CVE array")
    if kevs != sorted(set(kevs)):
        raise ValueError("risk acceptance kevs must be a nonempty sorted unique CVE array")
    nonempty_string(value["reason"], "risk acceptance reason")
    parse_time(value["expiresAt"], "risk acceptance expiresAt")
    for key in ("likelihood", "impact"):
        assessment = value[key]
        exact_fields(assessment, {"level", "rationale"}, f"risk acceptance {key}")
        if assessment["level"] not in LEVELS:
            raise ValueError(f"risk acceptance {key}.level is invalid")
        nonempty_string(assessment["rationale"], f"risk acceptance {key}.rationale")
    nonempty_string(value["owner"], "risk acceptance owner")
    notes = value["reviewNotes"]
    if not isinstance(notes, list) or not notes or not all(isinstance(note, str) and note.strip() for note in notes):
        raise ValueError("risk acceptance reviewNotes must be a nonempty string array")
    issue = value["trackingIssue"]
    if isinstance(issue, bool) or not isinstance(issue, int) or issue <= 0:
        raise ValueError("risk acceptance trackingIssue is invalid")


def validate_github_commit(value: dict, path: str) -> None:
    commit = value["commit"]
    exact_fields(commit, {"sha", "path", "blob_sha"}, "GitHub acceptance commit")
    if not isinstance(commit["sha"], str) or not SHA40_RE.fullmatch(commit["sha"]):
        raise ValueError("GitHub acceptance commit SHA is invalid")
    if commit["path"] != path or commit["blob_sha"] != value["content_blob_sha"]:
        raise ValueError("GitHub acceptance commit file mismatch")


def validate_github_pull(value: dict, repository: str) -> tuple[dict, datetime]:
    associated = value["associated_pull_requests"]
    if not isinstance(associated, list) or len(associated) != 1 or associated[0] != value["pull_request"]:
        raise ValueError("GitHub acceptance PR association is ambiguous")
    pull_request = value["pull_request"]
    pull_fields = {
        "number", "html_url", "state", "merged", "merged_at", "merged_by",
        "base_repository", "base_ref",
    }
    exact_fields(pull_request, pull_fields, "GitHub acceptance pull request")
    if isinstance(pull_request["number"], bool) or not isinstance(pull_request["number"], int) or pull_request["number"] <= 0:
        raise ValueError("GitHub acceptance PR number is invalid")
    expected_url = f"https://github.com/{repository}/pull/{pull_request['number']}"
    if pull_request["html_url"] != expected_url or pull_request["state"] != "closed" or pull_request["merged"] is not True:
        raise ValueError("GitHub acceptance PR is not merged")
    merged_at = parse_time(pull_request["merged_at"], "GitHub acceptance merged_at")
    merged_by = pull_request["merged_by"]
    exact_fields(merged_by, {"login"}, "GitHub acceptance merged_by")
    nonempty_string(merged_by["login"], "GitHub acceptance merged_by login")
    if pull_request["base_repository"] != repository or pull_request["base_ref"] != "main":
        raise ValueError("GitHub acceptance PR does not target repository main")
    return pull_request, merged_at


def validate_github_issue(value: dict) -> None:
    issue = value["issue"]
    exact_fields(issue, {"number", "html_url", "state", "is_pull_request"}, "GitHub acceptance issue")
    issue_url = f"https://github.com/{value['repository']}/issues/{issue['number']}"
    if issue["html_url"] != issue_url or issue["state"] != "open" or issue["is_pull_request"] is not False:
        raise ValueError("GitHub acceptance tracking issue is not open")


def validate_github_evidence(value: dict, repository: str, path: str, record_sha256: str):
    fields = {
        "repository", "path", "record_sha256", "content_blob_sha", "commit",
        "associated_pull_requests", "pull_request", "issue",
    }
    exact_fields(value, fields, "GitHub acceptance evidence")
    if value["repository"] != repository:
        raise ValueError("GitHub acceptance evidence wrong repository")
    if value["path"] != path:
        raise ValueError("GitHub acceptance evidence wrong path")
    if not isinstance(value["record_sha256"], str) or value["record_sha256"] != record_sha256:
        raise ValueError("GitHub acceptance record bytes changed")
    if not isinstance(value["content_blob_sha"], str) or not re.fullmatch(r"[a-f0-9]{40}", value["content_blob_sha"]):
        raise ValueError("GitHub acceptance content blob SHA is invalid")
    validate_github_commit(value, path)
    pull_request, merged_at = validate_github_pull(value, repository)
    validate_github_issue(value)
    return pull_request, merged_at


def acceptance_evidence(args, candidate_digest: str, matched: list[str], now: str):
    record_path = Path(args.acceptance) if args.acceptance else None
    evidence_path = Path(args.github_evidence) if args.github_evidence else None
    if record_path is None and evidence_path is None:
        return None
    if record_path is None or evidence_path is None:
        raise ValueError("risk acceptance and GitHub evidence must be supplied together")
    if not args.github_repository:
        raise ValueError("--github-repository is required with risk acceptance")
    record = load_json(record_path, "risk acceptance")
    validate_risk_assessment(record)
    expected_path = acceptance_path(args.app, candidate_digest, matched)
    record_sha256 = hashlib.sha256(record_path.read_bytes()).hexdigest()
    evidence = load_json(evidence_path, "GitHub acceptance evidence")
    pull_request, merged_at = validate_github_evidence(evidence, args.github_repository, expected_path, record_sha256)
    if evidence["issue"]["number"] != record["trackingIssue"]:
        raise ValueError("GitHub acceptance issue does not match the risk record")
    if record["candidateDigest"] != candidate_digest:
        raise ValueError("risk acceptance candidate digest does not match this candidate")
    if record["kevs"] != matched:
        raise ValueError("risk acceptance KEV set does not match this candidate")
    current = parse_time(now, POLICY_NOW)
    expiry = parse_time(record["expiresAt"], "risk acceptance expiresAt")
    if merged_at > current:
        raise ValueError("GitHub acceptance merge is future-dated")
    if current >= expiry:
        raise ValueError("risk acceptance expired")
    if expiry < merged_at or (expiry - merged_at).total_seconds() > 7 * 24 * 3600:
        raise ValueError("risk acceptance acceptance too old or predates merge")
    return {
        "path": expected_path,
        "sha256": record_sha256,
        "candidate_digest": record["candidateDigest"],
        "kevs": record["kevs"],
        "expires_at": record["expiresAt"],
        "commit_sha": evidence["commit"]["sha"],
        "pull_request": pull_request["number"],
        "merged_at": pull_request["merged_at"],
        "merged_by": pull_request["merged_by"]["login"],
        "issue": record["trackingIssue"],
    }


def resume_evidence(args):
    values = (
        args.resume_original_run_id, args.resume_original_run_attempt,
        args.resume_original_source_sha, args.resume_artifact_id,
    )
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError("resume inputs must be supplied together")
    if not args.resume_original_run_id.isdigit() or args.resume_original_run_attempt <= 0:
        raise ValueError("resume original run identity is invalid")
    if not SHA40_RE.fullmatch(args.resume_original_source_sha) or args.resume_artifact_id <= 0:
        raise ValueError("resume original source SHA or artifact ID is invalid")
    return {
        "original_run_id": args.resume_original_run_id,
        "original_run_attempt": args.resume_original_run_attempt,
        "original_source_sha": args.resume_original_source_sha,
        "artifact_id": args.resume_artifact_id,
    }


def patch_reason(args):
    if args.patch_policy != "disabled":
        if args.patch_disabled_class is not None or args.patch_disabled_detail is not None:
            raise ValueError("patch-disabled inputs require --patch-policy disabled")
        return None
    reason_class = args.patch_disabled_class
    detail = args.patch_disabled_detail
    if reason_class not in PATCH_DISABLED_CLASSES or not isinstance(detail, str) or not detail.strip():
        raise ValueError("disabled patching requires a valid class and non-empty detail")
    return {"class": reason_class, "detail": detail}


def finding_delta(full_ids: set, final_ids: set, fixable_identities: set) -> dict:
    delta = {
        "resolved": sorted(full_ids - final_ids),
        "remaining": sorted(full_ids & final_ids),
        "introduced": sorted(final_ids - full_ids),
        "unresolved_fixable": sorted(
            key for key in final_ids if key.rsplit("|", 1)[1] in {
                identity.rsplit("|", 1)[1] for identity in fixable_identities
            }
        ),
    }
    delta["cves"] = cve_groups(delta)
    return delta


def validate_candidate_digest(args, child_digest: str, fixable_ids: list[str], after) -> str:
    candidate_digest = args.candidate_digest or child_digest
    if not DIGEST_RE.fullmatch(candidate_digest):
        raise ValueError("--candidate-digest must be a sha256 digest")
    if candidate_digest != child_digest and not fixable_ids:
        raise ValueError("a distinct candidate requires a patch result")
    if after is None and candidate_digest != child_digest:
        raise ValueError("a distinct candidate requires an after full report")
    return candidate_digest


def resolve_copa_classification(args, patched: bool, fixable_ids: list[str]) -> str:
    if patched:
        default = "succeeded"
    elif not fixable_ids or args.patch_policy == "disabled":
        default = "not-required"
    else:
        default = "pending"
    classification = args.copa_classification or default
    if classification == "not-required" and fixable_ids and args.patch_policy != "disabled":
        raise ValueError("fixable OS findings require Copa classification")
    if classification == "pending" and patched:
        raise ValueError("a patched result requires Copa classification succeeded")
    if classification == "succeeded" and not patched:
        raise ValueError("Copa classification succeeded requires an after full report")
    return classification


def finding_details(keys, final: dict) -> str:
    return ",".join(
        f"{key.split('|', 2)[2]}:{final[key]['severity']}:{final[key]['severity_source']}"
        for key in keys
    )


def patched_integrity_reason(delta: dict, downgrades: list) -> str | None:
    blockers = []
    if delta["introduced"]:
        blockers.append(f"introduced CVEs ({','.join(delta['cves']['introduced'])})")
    if delta["unresolved_fixable"]:
        blockers.append(f"unresolved supplied CVEs ({','.join(delta['cves']['unresolved_fixable'])})")
    if downgrades:
        blockers.append("package downgrades (" + ",".join(f"{item['ecosystem']}/{item['name']}" for item in downgrades) + ")")
    return "blocked: patched-image integrity failure: " + "; ".join(blockers) if blockers else None


def decision_reason(args, delta: dict, downgrades: list, fixable_ids: list[str], patched: bool,
                    classification: str, failed_classification: bool, matched: list[str],
                    acceptance, disabled_reason, no_fix: list[str], final: dict) -> str:
    if args.validation_result != "pass":
        return f"blocked: validation result is {args.validation_result}"
    if failed_classification:
        return f"blocked: Copa classification is {classification}"
    if patched and (delta["introduced"] or delta["unresolved_fixable"] or downgrades):
        return patched_integrity_reason(delta, downgrades)
    if fixable_ids and not patched and args.patch_policy != "disabled":
        return "blocked: fixable OS findings require the Copa patch path"
    if matched and acceptance is None:
        return "missing_kev_acceptance"
    if disabled_reason:
        details = finding_details(sorted(final), final)
        return f"eligible with patching disabled ({disabled_reason['class']}): {disabled_reason['detail']}; findings: {details}"
    if no_fix:
        return f"eligible with no-fix warnings: {finding_details(no_fix, final)}"
    if patched:
        return "patched"
    return "clean"


def build_decision(args, child_digest: str, full, fixable, after, before_packages, after_packages, kev, acceptance, resume):
    full_ids = set(full)
    fixable_ids = sorted(set(fixable))
    if not set(fixable_ids) <= full_ids:
        raise ValueError("fixable report contains a finding absent from the full report")
    fixable_identities = set(fixable_ids)
    final = after if after is not None else full
    final_ids = set(final)
    delta = finding_delta(full_ids, final_ids, fixable_identities)
    changes, downgrades = package_changes(before_packages, after_packages)
    no_fix = sorted(key for key in final_ids if key not in fixable_identities)
    kev_cves = {vuln["cveID"] for vuln in load_json(Path(args.kev), KEV_CATALOG)["vulnerabilities"]}
    matched = sorted({key.split("|", 2)[2] for key in final_ids} & kev_cves)
    kev["matched"] = matched

    candidate_digest = validate_candidate_digest(args, child_digest, fixable_ids, after)
    patched = after is not None
    classification = resolve_copa_classification(args, patched, fixable_ids)
    failed_classification = classification in ("unsupported", "no-fix", "eol", "gpg", "unknown")
    disabled_reason = patch_reason(args)
    copa_ran = patched or (bool(fixable_ids) and args.patch_policy == "enabled" and failed_classification)
    eligible = (
        args.validation_result == "pass"
        and not failed_classification
        and (args.patch_policy == "disabled" or not fixable_ids or patched)
        and not delta["introduced"]
        and (not patched or not delta["unresolved_fixable"])
        and not downgrades
        and (not matched or acceptance is not None)
    )
    reason = decision_reason(
        args, delta, downgrades, fixable_ids, patched, classification, failed_classification,
        matched, acceptance, disabled_reason, no_fix, final,
    )
    return {
        "schema": SCHEMA,
        "eligible": eligible,
        "reason": reason,
        "platform": PLATFORM,
        "app": args.app,
        "source_sha": args.source_sha,
        "run_id": args.run_id,
        "run_attempt": args.run_attempt,
        "proposed_tag": args.proposed_tag,
        "upstream_index_digest": args.upstream_index_digest,
        "selected_child_digest": child_digest,
        "candidate": {"digest": candidate_digest},
        "before": {"fixable_os": fixable_ids},
        "copa": {
            "classification": classification,
            "original_child_input": copa_ran,
        },
        "delta": delta,
        "packages": {"changes": changes, "downgrades": downgrades},
        "patching": {"disabled": args.patch_policy == "disabled"} | ({"disabled_reason": disabled_reason} if disabled_reason else {}),
        "policy": {"kev": kev, "acceptance": acceptance},
        "validation": {"result": args.validation_result},
        "resume": resume,
        "published": {"digest": None},
        "provenance": {"merged": False},
        "supersedes": {"higher_upstream": False, "original_child_selected": False},
    }


def validate_string_list(value, field):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be an array of strings")


DECISION_FIELDS = {
    "schema", "eligible", "reason", "platform", "app", "source_sha", "run_id", "run_attempt",
    "proposed_tag", "upstream_index_digest", "selected_child_digest", "candidate", "before",
    "copa", "delta", "packages", "patching", "policy", "validation", "published", "provenance",
    "supersedes", "resume",
}


def validate_decision_identity(decision):
    simple = {
        "schema": str, "eligible": bool, "reason": str, "platform": str, "app": str,
        "source_sha": str, "run_id": str, "run_attempt": int, "proposed_tag": str,
        "upstream_index_digest": str, "selected_child_digest": str,
    }
    for key, kind in simple.items():
        if not isinstance(decision[key], kind) or (kind is str and not decision[key]):
            raise ValueError(f"decision.{key} has the wrong type or is empty")
    if decision["schema"] != SCHEMA or decision["platform"] != PLATFORM:
        raise ValueError("decision schema or platform is invalid")
    if not SHA40_RE.fullmatch(decision["source_sha"]) or not decision["run_id"].isdigit():
        raise ValueError("decision source SHA or run ID is invalid")
    if not DIGEST_RE.fullmatch(decision["upstream_index_digest"]) or not DIGEST_RE.fullmatch(decision["selected_child_digest"]):
        raise ValueError("decision upstream or child digest is invalid")


def validate_decision_candidate(decision):
    if set(decision["candidate"]) != {"digest"} or not DIGEST_RE.fullmatch(decision["candidate"]["digest"]):
        raise ValueError("decision.candidate is invalid")
    if set(decision["before"]) != {"fixable_os"}:
        raise ValueError("decision.before is invalid")
    validate_string_list(decision["before"]["fixable_os"], "before.fixable_os")
    if set(decision["copa"]) != {"classification", "original_child_input"} or decision["copa"]["classification"] not in COPA_CLASSIFICATIONS or not isinstance(decision["copa"]["original_child_input"], bool):
        raise ValueError(f"decision.copa is invalid {decision['copa']!r}")


def validate_decision_delta(decision):
    delta_groups = {"resolved", "remaining", "introduced", "unresolved_fixable"}
    if set(decision["delta"]) != delta_groups | {"cves"}:
        raise ValueError("decision.delta is invalid")
    for key in delta_groups:
        validate_string_list(decision["delta"][key], f"delta.{key}")
    if not isinstance(decision["delta"]["cves"], dict) or set(decision["delta"]["cves"]) != delta_groups:
        raise ValueError("decision.delta.cves is invalid")
    for key, value in decision["delta"]["cves"].items():
        validate_string_list(value, f"delta.cves.{key}")


def expected_package_change(group: str, item: dict) -> str:
    if group == "downgrades":
        return "downgraded"
    if item["before"] and not item["after"]:
        return "removed"
    if item["after"] and not item["before"]:
        return "added"
    return "upgraded"


def validate_decision_package(group: str, item):
    package_fields = {"ecosystem", "name", "change", "before", "after"}
    if not isinstance(item, dict) or set(item) != package_fields:
        raise ValueError(f"decision.packages.{group} item is invalid")
    if not isinstance(item["ecosystem"], str) or item["ecosystem"] not in VERSION_CLASSES:
        raise ValueError(f"decision.packages.{group} ecosystem is invalid")
    if not isinstance(item["name"], str) or not item["name"]:
        raise ValueError(f"decision.packages.{group} name is invalid")
    if item["change"] != expected_package_change(group, item):
        raise ValueError(f"decision.packages.{group} change is invalid")
    if not all(value is None or isinstance(value, str) for value in (item["before"], item["after"])):
        raise ValueError(f"decision.packages.{group} versions are invalid")


def validate_decision_packages(decision):
    if set(decision["packages"]) != {"changes", "downgrades"}:
        raise ValueError("decision.packages is invalid")
    for group in decision["packages"]:
        for item in decision["packages"][group]:
            validate_decision_package(group, item)


def validate_decision_patching(decision):
    patching = decision["patching"]
    if set(patching) not in ({"disabled"}, {"disabled", "disabled_reason"}) or not isinstance(patching["disabled"], bool):
        raise ValueError("decision.patching is invalid")
    if patching["disabled"] and set(patching) != {"disabled", "disabled_reason"}:
        raise ValueError("disabled patching requires disabled_reason")
    if not patching["disabled"] and "disabled_reason" in patching:
        raise ValueError("enabled patching cannot carry disabled_reason")
    if patching["disabled"]:
        reason = patching["disabled_reason"]
        if (not isinstance(reason, dict) or set(reason) != {"class", "detail"} or reason.get("class") not in ("unsupported", "no-fix") or not isinstance(reason.get("detail"), str) or not reason["detail"]):
            raise ValueError("decision.patching.disabled_reason is invalid")


def validate_decision_catalog(catalog):
    catalog_fields = {
        "url": str, "sha256": str, "fetched_at": str, "count": int,
        "unique_cves": int, "catalog_version": str, "date_released": str,
    }
    if not isinstance(catalog, dict) or set(catalog) != set(catalog_fields):
        raise ValueError("decision.policy.kev.catalog is invalid")
    for key, kind in catalog_fields.items():
        value = catalog[key]
        if not isinstance(value, kind) or (kind is str and not value) or (kind is int and isinstance(value, bool)):
            raise ValueError(f"decision.policy.kev.catalog.{key} is invalid")
    if catalog["url"] != KEV_URL or not re.fullmatch(r"[a-f0-9]{64}", catalog["sha256"]):
        raise ValueError("decision.policy.kev.catalog identity is invalid")


def validate_decision_acceptance(acceptance):
    acceptance_fields = {
        "path", "sha256", "candidate_digest", "kevs", "expires_at", "commit_sha",
        "pull_request", "merged_at", "merged_by", "issue",
    }
    if not isinstance(acceptance, dict) or set(acceptance) != acceptance_fields:
        raise ValueError("decision.policy.acceptance is invalid")
    for key in ("path", "sha256", "candidate_digest", "expires_at", "commit_sha", "merged_at", "merged_by"):
        if not isinstance(acceptance[key], str) or not acceptance[key]:
            raise ValueError(f"decision.policy.acceptance.{key} is invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", acceptance["sha256"]):
        raise ValueError("decision.policy.acceptance.sha256 is invalid")
    if not DIGEST_RE.fullmatch(acceptance["candidate_digest"]) or not SHA40_RE.fullmatch(acceptance["commit_sha"]):
        raise ValueError("decision.policy.acceptance identity is invalid")
    validate_string_list(acceptance["kevs"], "decision.policy.acceptance.kevs")
    for key in ("pull_request", "issue"):
        value = acceptance[key]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"decision.policy.acceptance.{key} is invalid")


def validate_decision_policy(decision):
    if set(decision["policy"]) != {"kev", "acceptance"} or set(decision["policy"]["kev"]) != {"matched", "catalog"}:
        raise ValueError("decision.policy is invalid")
    validate_string_list(decision["policy"]["kev"]["matched"], "policy.kev.matched")
    validate_decision_catalog(decision["policy"]["kev"]["catalog"])
    acceptance = decision["policy"]["acceptance"]
    if acceptance is not None:
        validate_decision_acceptance(acceptance)


def validate_resume_record(resume):
    resume_fields = {"original_run_id", "original_run_attempt", "original_source_sha", "artifact_id"}
    if not isinstance(resume, dict) or set(resume) != resume_fields:
        raise ValueError("decision.resume is invalid")
    if not isinstance(resume["original_run_id"], str) or not resume["original_run_id"].isdigit():
        raise ValueError("decision.resume.original_run_id is invalid")
    if isinstance(resume["original_run_attempt"], bool) or not isinstance(resume["original_run_attempt"], int) or resume["original_run_attempt"] <= 0:
        raise ValueError("decision.resume.original_run_attempt is invalid")
    if not isinstance(resume["original_source_sha"], str) or not SHA40_RE.fullmatch(resume["original_source_sha"]):
        raise ValueError("decision.resume.original_source_sha is invalid")
    if isinstance(resume["artifact_id"], bool) or not isinstance(resume["artifact_id"], int) or resume["artifact_id"] <= 0:
        raise ValueError("decision.resume.artifact_id is invalid")


def validate_decision_resume(decision):
    resume = decision["resume"]
    if resume is not None:
        validate_resume_record(resume)


def validate_decision_publication(decision):
    if set(decision["validation"]) != {"result"} or decision["validation"]["result"] not in ("pass", "fail"):
        raise ValueError("decision.validation is invalid")
    validate_decision_resume(decision)
    if set(decision["published"]) != {"digest"} or not (decision["published"]["digest"] is None or DIGEST_RE.fullmatch(decision["published"]["digest"])):
        raise ValueError("decision.published.digest is invalid")
    if set(decision["provenance"]) != {"merged"} or not isinstance(decision["provenance"]["merged"], bool):
        raise ValueError("decision.provenance is invalid")
    if set(decision["supersedes"]) != {"higher_upstream", "original_child_selected"} or not all(isinstance(value, bool) for value in decision["supersedes"].values()):
        raise ValueError("decision.supersedes is invalid")


def validate_decision(decision):
    if not isinstance(decision, dict):
        raise ValueError("decision must be an object")
    if set(decision) != DECISION_FIELDS:
        raise ValueError("decision has unknown or missing top-level fields")
    validate_decision_identity(decision)
    validate_decision_candidate(decision)
    validate_decision_delta(decision)
    validate_decision_packages(decision)
    validate_decision_patching(decision)
    validate_decision_policy(decision)
    validate_decision_publication(decision)


def run_resolve_only(args) -> int:
    if not args.selected_digest_out:
        raise ValueError("--resolve-only requires --selected-digest-out")
    index = load_json(Path(args.index), "upstream index")
    if sha256_file(Path(args.index)) != args.upstream_index_digest:
        raise ValueError("upstream index bytes do not match the inventory digest")
    child_digest = select_child(index, Path(args.child_manifest), Path(args.child_config))
    out = Path(args.selected_digest_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(child_digest + "\n", encoding="utf-8")
    print(child_digest)
    return 0


def validate_candidate_inputs(args):
    if not SHA40_RE.fullmatch(args.source_sha):
        raise ValueError("--source-sha must be 40 lowercase hex digits")
    if not args.run_id.isdigit() or args.run_attempt <= 0 or not args.proposed_tag.strip():
        raise ValueError("--run-id, --run-attempt, or --proposed-tag is invalid")
    index = load_json(Path(args.index), "upstream index")
    index_digest = sha256_file(Path(args.index))
    if index_digest != args.upstream_index_digest:
        raise ValueError("upstream index bytes do not match the inventory digest")
    child_digest = select_child(index, Path(args.child_manifest), Path(args.child_config))
    return index, child_digest, index_digest


def evaluate_candidate(args):
    _, child_digest, index_digest = validate_candidate_inputs(args)
    full_path = Path(args.full_report)
    after_path = Path(args.after_full_report) if args.after_full_report else None
    receipt_path = Path(args.scan_receipt) if args.scan_receipt else None
    if bool(after_path) != bool(receipt_path):
        raise ValueError("--after-full-report and --scan-receipt must be supplied together")
    candidate_digest = args.candidate_digest or child_digest
    if not DIGEST_RE.fullmatch(candidate_digest):
        raise ValueError("--candidate-digest must be a sha256 digest")
    patch_reason(args)
    full_report = load_json(full_path, "full Trivy report")
    os_metadata = full_report.get("Metadata", {}).get("OS")
    if os_metadata is not None and (not isinstance(os_metadata, dict) or os_metadata.get("EOSL") is True):
        raise ValueError("full report OS EOSL is true")
    after_report = load_json(after_path, "after full Trivy report") if after_path else None
    if after_report is not None:
        validate_scan_receipt(
            load_json(receipt_path, "scan receipt"), full_path, after_path, full_report, after_report,
            args.now, child_digest, candidate_digest,
        )
    full = findings(full_report, "full report")
    fixable = findings(load_json(Path(args.fixable_report), "fixable Trivy report"), "fixable report", True)
    after = findings(after_report, "after full report") if after_report is not None else None
    before_packages = package_inventory(full_report, "full report")
    after_packages = package_inventory(after_report, "after full report") if after_report is not None else before_packages
    kev = kev_evidence(Path(args.kev), args.kev_fetched_at, args.now)
    candidate_digest = args.candidate_digest or child_digest
    final_ids = set(after if after is not None else full)
    kev_cves = {item["cveID"] for item in load_json(Path(args.kev), KEV_CATALOG)["vulnerabilities"]}
    matched = sorted({key.split("|", 2)[2] for key in final_ids} & kev_cves)
    resume = resume_evidence(args)
    acceptance = acceptance_evidence(args, candidate_digest, matched, args.now)
    decision = build_decision(args, child_digest, full, fixable, after, before_packages, after_packages, kev, acceptance, resume)
    decision["upstream_index_digest"] = index_digest
    validate_decision(decision)
    return decision


def write_decision(decision, args) -> int:
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(decision, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 1 if not decision["eligible"] else 0


def main():
    args = parse_args()
    try:
        if args.resolve_only:
            return run_resolve_only(args)
        decision = evaluate_candidate(args)
    except ValueError as exc:
        print(f"[policy] {exc}", file=sys.stderr)
        return 2
    return write_decision(decision, args)


if __name__ == "__main__":
    sys.exit(main())
