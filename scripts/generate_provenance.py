#!/usr/bin/env python3
"""Generate the provenance record for one promoted internal image.

One promotion run renders its full evidence set into a single provenance-v1
JSON file (one file per internal tag under provenance/<app>/).

Fail-closed: every input is validated BEFORE anything is written. All
violations are collected and printed — one line per violation, each prefixed
[provenance] and naming the offending field — and the run exits 1 without
creating or modifying the output file. No value is ever invented: every
field in the record comes from a flag captured during the run that produced
the image.

stdlib only.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import evaluate_promotion as promotion

SCHEMA = "trusted-images.bocklabs.dev/provenance-v1"
PACKAGE_PREFIX = "ghcr.io/bocklabs/"
DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
BARE_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SOURCE_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
BEFORE_REPORT = "before report"
FINAL_REPORT = "final report"
FIXABLE_REPORT = "fixable report"

# flag -> (kind, required); kind: text | digest (sha256:<64hex>) | sha256
# (bare 64-hex) | json (object or array — per-flag shape in *_JSON_FLAGS)
FLAGS: dict[str, tuple[str, bool]] = {
    "--app": ("text", True),
    "--upstream-ref": ("text", True),
    "--upstream-tag": ("text", True),
    "--upstream-digest": ("digest", True),
    "--upstream-child-digest": ("digest", True),
    "--media-type": ("text", True),
    "--internal-package": ("text", True),
    "--internal-tag": ("text", True),
    "--internal-digest": ("digest", True),
    "--platforms": ("text", True),
    "--run-url": ("text", True),
    "--workflow": ("text", True),
    "--dispatched-by": ("text", True),
    "--trivy-version": ("text", True),
    "--trivy-action-sha": ("text", True),
    "--skopeo-version": ("text", True),
    "--skopeo-image-digest": ("digest", True),
    "--trivy-db-check-bundle-digest": ("digest", True),
    "--trivy-db-updated-at": ("text", True),
    "--full-report-sha256": ("sha256", True),
    "--copa-report-sha256": ("sha256", True),
    "--decision-sha256": ("sha256", True),
    "--decision": ("path", True),
    "--before-report": ("path", True),
    "--final-report": ("path", True),
    "--fixable-report": ("path", True),
    "--kev-report": ("path", True),
    "--now": ("text", True),
    "--github-evidence": ("path", False),
    "--github-repository": ("text", False),
    "--copa-version": ("text", False),
    "--secobserve-product": ("text", True),
    "--secobserve-origin": ("text", True),
    "--validation-type": ("text", True),
    "--validation-result": ("text", True),
    "--validation-params": ("json", True),
    "--validation-timings": ("json", True),
    "--validation-health": ("json", True),
    "--validation-runner": ("text", True),
    "--validation-entrypoint": ("json", True),
    "--validation-cmd": ("json", True),
    "--validation-env": ("json", True),
    "--signing-evidence": ("path", True),
    "--signing-result": ("text", True),
    "--signing-failure": ("text", False),
    "--notes": ("text", False),
    "--original-run-url": ("text", False),
    "--original-source-sha": ("text", False),
    "--recovered-tag": ("text", False),
    "--recovered-digest": ("digest", False),
    "--out": ("text", True),
}

RECOVERY_FLAGS = (
    "--original-run-url",
    "--original-source-sha",
    "--recovered-tag",
    "--recovered-digest",
)

JSON_OBJECT_FLAGS = (
    "--validation-params",
    "--validation-timings",
    "--validation-health",
)
JSON_ARRAY_FLAGS = ("--validation-entrypoint", "--validation-cmd", "--validation-env")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write one provenance-v1 record for a promoted internal image.",
    )
    for flag in FLAGS:
        parser.add_argument(flag, default="")
    return parser.parse_args()


def value_of(args: argparse.Namespace, flag: str) -> str:
    return getattr(args, flag.lstrip("-").replace("-", "_"))


def load_json(path: str, label: str) -> dict:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_utc(value: str, label: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError(f"{label} must use strict UTC YYYY-MM-DDTHH:MM:SSZ")
    return datetime.strptime(value, UTC_FORMAT).replace(tzinfo=timezone.utc)


def finding_rows(findings: dict) -> list[dict]:
    rows = []
    for identity, metadata in findings.items():
        platform, package, cve = identity.split("|", 2)
        rows.append(
            {
                "identity": identity,
                "platform": platform,
                "package": package,
                "cve": cve,
                **metadata,
            }
        )
    return sorted(rows, key=lambda row: row["identity"])


def warning_rows(final: dict, fixable: dict, decision: dict) -> list[dict]:
    warnings = [
        {"kind": "no-fix", **row}
        for row in finding_rows(
            {key: value for key, value in final.items() if key not in fixable}
        )
    ]
    if decision["patching"].get("disabled_reason"):
        warnings.append(
            {"kind": "patching-disabled", **decision["patching"]["disabled_reason"]}
        )
    return warnings


def policy_evidence(
    args: argparse.Namespace, decision: dict
) -> tuple[dict, list[dict], dict]:
    before = promotion.findings(
        load_json(value_of(args, "--before-report"), BEFORE_REPORT), BEFORE_REPORT
    )
    final = promotion.findings(
        load_json(value_of(args, "--final-report"), FINAL_REPORT), FINAL_REPORT
    )
    fixable = promotion.findings(
        load_json(value_of(args, "--fixable-report"), FIXABLE_REPORT),
        FIXABLE_REPORT,
        True,
    )
    if not set(fixable) <= set(before):
        raise ValueError(
            f"{FIXABLE_REPORT} contains a finding absent from the {BEFORE_REPORT}"
        )
    if decision["before"]["fixable_os"] != sorted(fixable):
        raise ValueError("decision fixable findings do not match the fixable report")

    before_ids, final_ids = set(before), set(final)
    expected_delta = {
        "resolved": sorted(before_ids - final_ids),
        "remaining": sorted(before_ids & final_ids),
        "introduced": sorted(final_ids - before_ids),
        "unresolved_fixable": sorted(
            key
            for key in final_ids
            if key.rsplit("|", 1)[1]
            in {identity.rsplit("|", 1)[1] for identity in fixable}
        ),
    }
    expected_delta["cves"] = promotion.cve_groups(expected_delta)
    if decision["delta"] != expected_delta:
        raise ValueError(
            f"decision delta does not match the {BEFORE_REPORT} and {FINAL_REPORT}"
        )

    before_packages = promotion.package_inventory(
        load_json(value_of(args, "--before-report"), BEFORE_REPORT), BEFORE_REPORT
    )
    final_packages = promotion.package_inventory(
        load_json(value_of(args, "--final-report"), FINAL_REPORT), FINAL_REPORT
    )
    changes, downgrades = promotion.package_changes(before_packages, final_packages)
    if decision["packages"] != {"changes": changes, "downgrades": downgrades}:
        raise ValueError(
            f"decision package changes do not match the {BEFORE_REPORT} and {FINAL_REPORT}"
        )

    receipt = promotion.kev_evidence(
        Path(value_of(args, "--kev-report")),
        decision["policy"]["kev"]["catalog"]["fetched_at"],
        value_of(args, "--now"),
    )
    if decision["policy"]["kev"]["catalog"] != receipt["catalog"]:
        raise ValueError(
            "decision KEV catalog receipt does not match the catalog bytes"
        )
    matched = sorted(
        {key.split("|", 2)[2] for key in final_ids}
        & {
            row["cveID"]
            for row in load_json(value_of(args, "--kev-report"), "KEV catalog")[
                "vulnerabilities"
            ]
        }
    )
    if decision["policy"]["kev"]["matched"] != matched:
        raise ValueError(
            "decision KEV matches do not match the final report and catalog"
        )

    acceptance = decision["policy"]["acceptance"]
    if not matched:
        if acceptance is not None:
            raise ValueError("policy acceptance cannot exist without a KEV match")
    elif acceptance is None:
        raise ValueError("nonempty KEV matches require exact acceptance evidence")
    else:
        validate_acceptance(args, decision, acceptance, matched)

    catalog = {
        "url": receipt["catalog"]["url"],
        "sha256": receipt["catalog"]["sha256"],
        "fetched_at": receipt["catalog"]["fetched_at"],
        "catalogVersion": receipt["catalog"]["catalog_version"],
        "dateReleased": receipt["catalog"]["date_released"],
    }
    return (
        {
            "kev": {"matches": matched, "catalog": catalog},
            "acceptance": provenance_acceptance(args, acceptance),
            "patching": decision["patching"],
            "copa": decision["copa"],
            "supersedes": decision["supersedes"],
        },
        warning_rows(final, fixable, decision),
        {
            "before": finding_rows(before),
            "final": finding_rows(final),
            "summary": decision["delta"]["cves"],
        },
    )


def validate_acceptance(
    args: argparse.Namespace, decision: dict, acceptance: dict, matched: list[str]
) -> None:
    if (
        acceptance["kevs"] != matched
        or acceptance["candidate_digest"] != decision["candidate"]["digest"]
    ):
        raise ValueError(
            "acceptance candidate digest or KEV set does not match this candidate"
        )
    now = parse_utc(value_of(args, "--now"), "--now")
    merged = parse_utc(acceptance["merged_at"], "acceptance merged_at")
    expiry = parse_utc(acceptance["expires_at"], "acceptance expires_at")
    if merged > now or now >= expiry:
        raise ValueError("acceptance is future-dated or expired")
    if not value_of(args, "--github-evidence") or not value_of(
        args, "--github-repository"
    ):
        raise ValueError(
            "--github-evidence and --github-repository are required with acceptance"
        )
    evidence = load_json(
        value_of(args, "--github-evidence"), "GitHub acceptance evidence"
    )
    pull_request, evidence_merged = promotion.validate_github_evidence(
        evidence,
        value_of(args, "--github-repository"),
        acceptance["path"],
        acceptance["sha256"],
    )
    if (
        pull_request["number"] != acceptance["pull_request"]
        or evidence_merged.strftime(UTC_FORMAT) != acceptance["merged_at"]
        or evidence["issue"]["number"] != acceptance["issue"]
    ):
        raise ValueError("acceptance GitHub identity does not match the decision")


def provenance_acceptance(
    args: argparse.Namespace, acceptance: dict | None
) -> dict | None:
    if acceptance is None:
        return None
    evidence = load_json(
        value_of(args, "--github-evidence"), "GitHub acceptance evidence"
    )
    return {
        "candidate_digest": acceptance["candidate_digest"],
        "kevs": acceptance["kevs"],
        "record_path": acceptance["path"],
        "record_commit": acceptance["commit_sha"],
        "pr_url": evidence["pull_request"]["html_url"],
        "merged_by": acceptance["merged_by"],
        "merged_at": acceptance["merged_at"],
        "issue_url": evidence["issue"]["html_url"],
        "issue_state": evidence["issue"]["state"],
        "expires_at": acceptance["expires_at"],
    }


def scalar_flag_violation(flag: str, kind: str, value: str) -> str | None:
    if kind == "digest" and value.strip() and not DIGEST_RE.fullmatch(value):
        return f"{flag} must be sha256: followed by 64 lowercase hex digits (got {value!r})"
    if kind == "sha256" and value.strip() and not BARE_SHA256_RE.fullmatch(value):
        return f"{flag} must be bare 64-hex sha256sum output, no sha256: prefix (got {value!r})"
    if kind == "path" and value.strip() and not Path(value).is_file():
        return f"{flag} must be an existing JSON file (got {value!r})"
    return None


def json_flag_violation(flag: str, value: str) -> str | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return f"{flag} must be valid JSON (got {value!r})"
    if flag in JSON_OBJECT_FLAGS and not isinstance(parsed, dict):
        return f"{flag} must be a JSON object (got {type(parsed).__name__})"
    if flag in JSON_ARRAY_FLAGS and not isinstance(parsed, list):
        return f"{flag} must be a JSON array (got {type(parsed).__name__})"
    return None


def flag_violations(args: argparse.Namespace) -> list[str]:
    violations = []
    for flag, (kind, required) in FLAGS.items():
        value = value_of(args, flag)
        if required and not value.strip():
            violations.append(f"missing required value for {flag} ({flag.lstrip('-')})")
            continue
        violation = scalar_flag_violation(flag, kind, value)
        if violation:
            violations.append(violation)
        if kind == "json" and value.strip():
            violation = json_flag_violation(flag, value)
            if violation:
                violations.append(violation)
    return violations


def identity_violations(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    violations = []
    app = value_of(args, "--app")
    package = value_of(args, "--internal-package")
    if app.strip() and package.strip() and package != f"{PACKAGE_PREFIX}{app}":
        violations.append(
            f"--internal-package must be '{PACKAGE_PREFIX}{app}' (got {package!r})"
        )

    upstream_tag = value_of(args, "--upstream-tag")
    internal_tag = value_of(args, "--internal-tag")
    if upstream_tag.strip() and internal_tag.strip():
        tag_re = re.compile(re.escape(upstream_tag) + r"-bocklabs\.\d+")
        if not tag_re.fullmatch(internal_tag):
            violations.append(
                f"--internal-tag must be '{upstream_tag}-bocklabs.N' "
                f"with N a positive integer (got {internal_tag!r})"
            )

    platforms_raw = value_of(args, "--platforms")
    platforms: list[str] = []
    if platforms_raw.strip():
        platforms = [part.strip() for part in platforms_raw.split(",")]
        if not all(platforms):
            violations.append(
                f"--platforms must be a comma-separated list of non-empty platforms "
                f"(got {platforms_raw!r})"
            )
    return violations, platforms


def decision_identity_violations(decision: dict, expected: dict[str, str]) -> list[str]:
    mismatches = {
        "app": decision["app"] != expected["app"],
        "upstream_index_digest": decision["upstream_index_digest"]
        != expected["upstream_index_digest"],
        "selected_child_digest": decision["selected_child_digest"]
        != expected["selected_child_digest"],
        "candidate_digest": decision["candidate"]["digest"]
        != expected["candidate_digest"],
        "proposed_tag": decision["proposed_tag"] != expected["proposed_tag"],
    }
    return [
        f"decision {key} does not match provenance identity"
        for key, failed in mismatches.items()
        if failed
    ]


def decision_violations(
    args: argparse.Namespace, app: str, internal_tag: str, platforms: list[str]
) -> tuple[list[str], dict | None]:
    violations = []
    provided_child = value_of(args, "--upstream-child-digest").strip()
    decision_sha = value_of(args, "--decision-sha256").strip()
    try:
        decision = load_json(value_of(args, "--decision"), "--decision")
        promotion.validate_decision(decision)
    except (OSError, ValueError) as exc:
        violations.append(f"decision validation failed: {exc}")
        decision = None
    if decision is not None:
        expected = {
            "app": app,
            "upstream_index_digest": value_of(args, "--upstream-digest"),
            "selected_child_digest": provided_child,
            "candidate_digest": value_of(args, "--internal-digest"),
            "proposed_tag": internal_tag,
        }
        violations.extend(
            decision_match_violations(args, decision, expected, decision_sha)
        )
    if provided_child:
        if platforms != ["linux/amd64"]:
            violations.append("--platforms must be exactly linux/amd64 for new records")
        if provided_child == value_of(args, "--upstream-digest"):
            violations.append(
                "--upstream-child-digest must differ from the index digest"
            )
    return violations, decision


def decision_match_violations(
    args: argparse.Namespace, decision: dict, expected: dict, decision_sha: str
) -> list[str]:
    violations = []
    if decision is not None:
        try:
            parse_utc(value_of(args, "--now"), "--now")
        except ValueError as exc:
            violations.append(str(exc))
        violations.extend(decision_identity_violations(decision, expected))
        quarantine = value_of(args, "--signing-result") == "fail"
        if decision["validation"]["result"] != "pass" or (decision["eligible"] == quarantine):
            violations.append("decision eligible state must match signing result with passing validation")
        if quarantine and decision["reason"] != "signing verification failed":
            violations.append("quarantine decision reason must be signing verification failed")
        if decision["published"]["digest"] != value_of(args, "--internal-digest"):
            violations.append(
                "decision published digest must match the provenance candidate"
            )
        if decision["provenance"]["merged"]:
            violations.append(
                "decision provenance merged must be false before this run writes provenance"
            )
        if decision_sha != file_sha256(Path(value_of(args, "--decision"))):
            violations.append("--decision-sha256 does not match --decision bytes")
    return violations


def recovery_violations(
    args: argparse.Namespace, decision: dict | None, internal_tag: str
) -> list[str]:
    violations = []
    recovery_values = [value_of(args, flag).strip() for flag in RECOVERY_FLAGS]
    original_values, recovered_values = recovery_values[:2], recovery_values[2:]
    if any(original_values) and not all(original_values):
        violations.append("original run metadata must provide URL and source SHA")
    if any(recovered_values) and not all(recovered_values):
        violations.append("recovery metadata must provide tag and digest")
    if any(original_values):
        violations.extend(
            original_run_violations(args, decision, original_values, recovered_values)
        )
    if any(recovered_values):
        if not all(original_values):
            violations.append("recovery metadata requires original run metadata")
        violations.extend(recovered_tag_violations(args, internal_tag))
    return violations


def original_run_violations(
    args: argparse.Namespace,
    decision: dict | None,
    original_values: list[str],
    recovered_values: list[str],
) -> list[str]:
    violations = []
    if not SOURCE_SHA_RE.fullmatch(value_of(args, "--original-source-sha")):
        violations.append("--original-source-sha must be 40 lowercase hex digits")
    if (
        decision is not None
        and decision["resume"] is None
        and not all(recovered_values)
    ):
        violations.append(
            "original run metadata requires decision resume or recovery evidence"
        )
    if (
        decision is not None
        and decision["resume"] is not None
        and not all(original_values)
    ):
        violations.append("decision resume requires original run metadata")
    if value_of(args, "--original-run-url") == value_of(args, "--run-url"):
        violations.append("--run-url must identify a new recovery run")
    return violations


def recovered_tag_violations(args: argparse.Namespace, internal_tag: str) -> list[str]:
    violations = []
    if value_of(args, "--recovered-tag") != internal_tag:
        violations.append("--recovered-tag must equal --internal-tag")
    if value_of(args, "--recovered-digest") != value_of(args, "--internal-digest"):
        violations.append("--recovered-digest must equal --internal-digest")
    return violations


def report_hash_violations(args: argparse.Namespace) -> list[str]:
    violations = []
    if value_of(args, "--full-report-sha256").strip():
        try:
            if value_of(args, "--full-report-sha256") != file_sha256(
                Path(value_of(args, "--final-report"))
            ):
                violations.append(
                    "--full-report-sha256 must match --final-report bytes"
                )
        except OSError:
            pass
    if value_of(args, "--copa-report-sha256").strip():
        try:
            if value_of(args, "--copa-report-sha256") != file_sha256(
                Path(value_of(args, "--fixable-report"))
            ):
                violations.append(
                    "--copa-report-sha256 must match --fixable-report bytes"
                )
        except OSError:
            pass

    return violations


def signing_hash_violations(path, group, item) -> list[str]:
    errors = []
    sources = {
        "signature": {"bundle_sha256": "sign-bundle.json", "attachment_sha256": "signature-attachment.json"},
        "sbom_attestation": {"bundle_sha256": "sbom-bundle.json", "attachment_sha256": "sbom-attestation-attachment.json", "predicate_sha256": "trivy-full.cdx.json"},
    }
    for key, filename in sources[group].items():
        if not BARE_SHA256_RE.fullmatch(str(item.get(key, ""))):
            errors.append(f"signing-evidence {group}.{key} is invalid")
            continue
        try:
            if item[key] != file_sha256(Path(path).parent / filename):
                errors.append(f"signing-evidence {group}.{key} differs from local bytes")
        except OSError:
            errors.append(f"signing-evidence {group}.{key} source file is missing")
    return errors


def signing_attachment_violations(path, group, item) -> list[str]:
    errors = []
    if not isinstance(item, dict):
        return [f"signing-evidence {group} is missing"]
    errors.extend(signing_hash_violations(path, group, item))
    if group == "sbom_attestation" and item.get("predicate_type") != "https://cyclonedx.org/bom":
        errors.append("signing-evidence sbom_attestation.predicate_type is invalid")
    rekor = item.get("rekor")
    if not isinstance(rekor, dict) or not (
        isinstance(rekor.get("log_index"), int) and not isinstance(rekor.get("log_index"), bool)
        and rekor["log_index"] >= 0 and isinstance(rekor.get("log_id"), str) and rekor["log_id"]
        and any(isinstance(rekor.get(key), str) and rekor[key] for key in ("signed_entry_timestamp", "inclusion_root_hash"))
    ):
        errors.append(f"signing-evidence {group}.rekor is invalid")
    return errors


def successful_signing_violations(args, path, evidence) -> list[str]:
    errors = []
    digest = value_of(args, "--internal-digest")
    package = value_of(args, "--internal-package")
    if evidence.get("digest") != digest or evidence.get("image") != f"{package}@{digest}":
        errors.append("signing-evidence digest or image differs from published candidate")
    identity = load_json(str(Path(__file__).resolve().parent.parent / "config/signing-identity.json"), "signing identity")
    for key in ("certificate_identity", "certificate_oidc_issuer"):
        if evidence.get(key) != identity[key]:
            errors.append(f"signing-evidence {key} differs from pinned identity")
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", str(evidence.get("cosign_version", ""))):
        errors.append("signing-evidence cosign_version is invalid")
    if evidence.get("trivy_version") != value_of(args, "--trivy-version"):
        errors.append("signing-evidence trivy_version differs from pinned Trivy version")
    for group in ("signature", "sbom_attestation"):
        errors.extend(signing_attachment_violations(path, group, evidence.get(group)))
    try:
        predicate = load_json(str(Path(path).parent / "trivy-full.cdx.json"), "signing predicate")
        if predicate.get("bomFormat") != "CycloneDX" or not isinstance(predicate.get("components"), list):
            errors.append("signing-evidence predicate is not a CycloneDX BOM")
    except (OSError, ValueError) as exc:
        errors.append(f"signing-evidence predicate is invalid: {exc}")
    return errors


def signing_violations(args: argparse.Namespace) -> list[str]:
    result = value_of(args, "--signing-result")
    failure = value_of(args, "--signing-failure")
    errors = []
    if result not in ("pass", "fail"):
        errors.append("--signing-result must be pass or fail")
    if result == "pass" and failure:
        errors.append("--signing-failure is only allowed for failed signing")
    if result == "fail" and not re.fullmatch(r"[A-Za-z0-9 .:_/-]{1,160}", failure):
        errors.append("--signing-failure must be a bounded single-line reason")
    path = value_of(args, "--signing-evidence")
    if not path or not Path(path).is_file():
        return errors
    try:
        evidence = load_json(path, "--signing-evidence")
    except (OSError, ValueError) as exc:
        return errors + [f"--signing-evidence is invalid: {exc}"]
    if evidence.get("result") != result:
        errors.append("signing-evidence result differs from --signing-result")
    if result == "fail":
        if evidence.get("reason") != failure:
            errors.append("signing-evidence reason differs from --signing-failure")
        return errors
    return errors + successful_signing_violations(args, path, evidence)


def collect_violations(args: argparse.Namespace) -> list[str]:
    """Every rule violation, one line each naming the offending field."""
    violations = flag_violations(args)
    identity, platforms = identity_violations(args)
    violations.extend(identity)
    app = value_of(args, "--app")
    internal_tag = value_of(args, "--internal-tag")
    decision_issues, decision = decision_violations(args, app, internal_tag, platforms)
    violations.extend(decision_issues)
    violations.extend(recovery_violations(args, decision, internal_tag))
    violations.extend(report_hash_violations(args))
    violations.extend(signing_violations(args))
    return violations


def build_record(
    args: argparse.Namespace,
    platforms: list[str],
    policy: dict,
    warnings: list[dict],
    cves: dict,
    decision: dict,
) -> dict:
    record = {
        "schema": SCHEMA,
        "app": value_of(args, "--app"),
        "upstream": {
            "ref": value_of(args, "--upstream-ref"),
            "tag": value_of(args, "--upstream-tag"),
            "digest": value_of(args, "--upstream-digest"),
            "index_digest": value_of(args, "--upstream-digest"),
            "media_type": value_of(args, "--media-type"),
            **(
                {
                    "selected_platform": "linux/amd64",
                    "selected_child_digest": value_of(args, "--upstream-child-digest"),
                }
                if value_of(args, "--upstream-child-digest")
                else {}
            ),
        },
        "internal": {
            "package": value_of(args, "--internal-package"),
            "tag": value_of(args, "--internal-tag"),
            "digest": value_of(args, "--internal-digest"),
            "platforms": platforms,
        },
        "pipeline": {
            "run_url": value_of(args, "--run-url"),
            "workflow": value_of(args, "--workflow"),
            "dispatched_by": value_of(args, "--dispatched-by"),
        },
        "tools": {
            "trivy": value_of(args, "--trivy-version"),
            "trivy_action": value_of(args, "--trivy-action-sha"),
            "copa": value_of(args, "--copa-version") or None,
            "skopeo": value_of(args, "--skopeo-version"),
            "skopeo_image_digest": value_of(args, "--skopeo-image-digest"),
        },
        "scan": {
            "trivy_db": {
                "check_bundle_digest": value_of(args, "--trivy-db-check-bundle-digest"),
                "updated_at": value_of(args, "--trivy-db-updated-at"),
            },
            "full_report_sha256": value_of(args, "--full-report-sha256"),
            "copa_report_sha256": value_of(args, "--copa-report-sha256"),
            "decision_sha256": value_of(args, "--decision-sha256"),
            "reports": {
                "before_sha256": file_sha256(Path(value_of(args, "--before-report"))),
                "final_sha256": file_sha256(Path(value_of(args, "--final-report"))),
                "fixable_sha256": file_sha256(Path(value_of(args, "--fixable-report"))),
            },
            "secobserve": {
                "product": value_of(args, "--secobserve-product"),
                "origin": value_of(args, "--secobserve-origin"),
            },
        },
        "policy": policy
        | {"outcome": decision["reason"], "eligible": decision["eligible"], "warnings": warnings},
        "cves": cves,
        "packages": decision["packages"]
        | {"downgrade_blocked": bool(decision["packages"]["downgrades"])},
        "validation": {
            "profile": value_of(args, "--validation-type"),
            "result": value_of(args, "--validation-result"),
            "params": json.loads(value_of(args, "--validation-params")),
            "timings": json.loads(value_of(args, "--validation-timings")),
            "health": json.loads(value_of(args, "--validation-health")),
            "runner": value_of(args, "--validation-runner"),
            "baseline": {
                "entrypoint": json.loads(value_of(args, "--validation-entrypoint")),
                "cmd": json.loads(value_of(args, "--validation-cmd")),
                "env": json.loads(value_of(args, "--validation-env")),
            },
        },
        "promoted_at": datetime.now(timezone.utc).strftime(UTC_FORMAT),
        "notes": args.notes,
    }
    signing = load_json(value_of(args, "--signing-evidence"), "--signing-evidence")
    if value_of(args, "--signing-result") == "fail":
        record["signing"] = {"result": "fail", "failure": value_of(args, "--signing-failure")}
    else:
        record["signing"] = {
            "result": "pass",
            "image_signature": {
                "bundle_sha256": signing["signature"]["bundle_sha256"],
                "attachment_sha256": signing["signature"]["attachment_sha256"],
                "certificate_identity": signing["certificate_identity"],
                "certificate_oidc_issuer": signing["certificate_oidc_issuer"],
            },
            "sbom_attestation": {key: signing["sbom_attestation"][key] for key in ("predicate_type", "predicate_sha256", "bundle_sha256", "attachment_sha256")},
            "rekor": {key: signing[key]["rekor"] for key in ("signature", "sbom_attestation")},
            "tools": {"cosign": signing["cosign_version"], "trivy": signing["trivy_version"]},
        }
    if value_of(args, "--original-run-url"):
        record["pipeline"]["original_run_url"] = value_of(args, "--original-run-url")
        record["pipeline"]["original_source_sha"] = value_of(
            args, "--original-source-sha"
        )
    if decision["resume"] is not None:
        record["resume"] = decision["resume"]
    if value_of(args, "--recovered-tag"):
        record["recovery"] = {
            "original_run_url": value_of(args, "--original-run-url"),
            "original_source_sha": value_of(args, "--original-source-sha"),
            "recovered_tag": value_of(args, "--recovered-tag"),
            "recovered_digest": value_of(args, "--recovered-digest"),
        }
    return record


def main() -> int:
    args = parse_args()

    violations = collect_violations(args)
    if violations:
        for line in violations:
            print(f"[provenance] {line}")
        return 1

    platforms = [part.strip() for part in value_of(args, "--platforms").split(",")]
    try:
        decision = load_json(value_of(args, "--decision"), "--decision")
        policy, warnings, cves = policy_evidence(args, decision)
    except (OSError, ValueError) as exc:
        print(f"[provenance] policy evidence validation failed: {exc}")
        return 1
    record = build_record(args, platforms, policy, warnings, cves, decision)

    out = Path(value_of(args, "--out"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
