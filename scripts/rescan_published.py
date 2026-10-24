"""Scan the latest merged published image and request producer remediation."""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import yaml
from evaluate_promotion import (
    findings,
    validate_native_inventory,
    validate_report_results,
)
from finding_identity import canonical, findings_hash, require
from promote_signing_gate import load_identity
from reverify_signing import load_current, merged_commit, record_time, verified_record
from validate_inventory import dig, entry_failures, parse_go_file_build

INVENTORY = Path(__file__).resolve().parents[1] / "inventory"
ARTIFACT = Path("published-rescan")
SELECTION_FILE = "selection.json"
INVALID_PACKAGE_INVENTORY = "invalid scanned package inventory"


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def retain(name, value):
    ARTIFACT.mkdir(exist_ok=True)
    (ARTIFACT / name).write_text(canonical(value) + "\n")
    paths = []
    for path in sorted(ARTIFACT.rglob("*")):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "unsafe rescan artifact entry")
        if path.is_file() and path != ARTIFACT / "SHA256SUMS":
            paths.append(path)
    (ARTIFACT / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(ARTIFACT).as_posix()}\n" for p in paths))


def output(values):
    print(canonical(values))
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.writelines(f"{key}={value if isinstance(value, str) else canonical(value)}\n" for key, value in values.items())
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\nPublished-image rescan: `" + canonical(values) + "`\n")


def latest_record(app):
    record = load_current(app, merged_commit())
    identity = load_identity(Path("config/signing-identity.json"))
    if record is None or not verified_record(record, app, identity):
        return None
    internal = record["internal"]
    return record_time(record), f"{internal['package']}:{internal['tag']}@{internal['digest']}", record


def select():
    require(os.getenv("GITHUB_REF") == "refs/heads/main", "automatic rescan requires main")
    require(not any(os.getenv(key, "").lower() not in ("", "false") for key in (
        "INPUT_FORCE_REPROMOTE", "INPUT_RECOVER_TAG", "INPUT_RECOVERY_RUN_ID",
        "INPUT_ACCEPTED_CANDIDATE_RUN_ID")), "automatic rescan cannot combine manual overrides")
    app = os.environ["INPUT_APP"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", app), "invalid inventory app")
    require(git("rev-parse", "HEAD") == git("rev-parse", "origin/main"),
            "queued source is stale; dispatch a fresh main rescan")
    path = Path("inventory") / app / "image.yaml"
    require(path.is_file(), "missing inventory entry")
    inventory = yaml.safe_load(path.read_text())
    require(not entry_failures(path, inventory), "invalid inventory entry")
    spec = inventory["spec"]
    latest = latest_record(app)
    if latest is None:
        value = {"app": app, "proceed": False, "reason": "no merged published image; first publication requires operator review"}
        retain(SELECTION_FILE, value)
        output(value)
        return
    _, ref, record = latest
    value = {"app": app, "ref": ref, "spec": spec, "published": record,
             "source_sha": git("rev-parse", "HEAD")}
    retain(SELECTION_FILE, value)
    output({"ref": ref, "proceed": False})


def reviewed_file_build(selection, report):
    app = selection["app"]
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", app), "invalid inventory app")
    path = INVENTORY / app / "go-file-build.json"
    if not path.exists():
        return None
    require(path.is_file() and not path.is_symlink(), "unsafe Go file-build evidence")
    raw = path.read_bytes()
    review = parse_go_file_build(raw, path)
    require(review["ref"] == selection["ref"], "Go file-build evidence is stale for the selected published image")
    metadata = report.get("Metadata", {})
    require(isinstance(metadata, dict), "Go file-build scan Metadata must be an object")
    _, labels = dig(report, "Metadata.ImageConfig.config.Labels")
    diff_ids = metadata.get("DiffIDs")
    require(isinstance(diff_ids, list), "Go file-build scan DiffIDs must be a list")
    require(isinstance(labels, dict) and review["config_digest"] == metadata.get("ImageID")
            and review["upstream_child_digest"] == dig(selection, "published.upstream.selected_child_digest")[1]
            and review["layer"]["DiffID"] in diff_ids
            and review["source"]["repository"] == labels.get("org.opencontainers.image.source")
            and review["source"]["revision"] == labels.get("org.opencontainers.image.revision"),
            "Go file-build scan evidence differs from scanned image")
    return {**review, "review_sha256": hashlib.sha256(raw).hexdigest()}


def versionless_go_replacement(result, package):
    if ("Version" in package or "Relationship" in package or result.get("Class") != "lang-pkgs"
            or result.get("Type") != "gobinary" or not isinstance(result.get("Target"), str)
            or not result["Target"] or package.get("ID") != package["Name"]
            or package.get("AnalyzedBy") != "gobinary"):
        return False
    name = package["Name"]
    identifier = package.get("Identifier")
    if not isinstance(identifier, dict) or not isinstance(identifier.get("UID"), str) or not identifier["UID"]:
        return False
    if re.fullmatch(r"\./[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", name):
        return set(identifier) == {"UID"}
    return (re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)+", name)
            and isinstance(identifier.get("PURL"), str)
            and identifier["PURL"].casefold() == ("pkg:golang/" + name).casefold())


def go_root_package(result, package, file_build):
    return (
        "Version" not in package and result.get("Class") == "lang-pkgs"
        and result.get("Type") == "gobinary" and isinstance(result.get("Target"), str)
        and bool(result["Target"]) and package.get("ID") == package["Name"]
        and re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*", package["Name"])
        and package.get("AnalyzedBy") == "gobinary"
        and (
            package.get("Relationship") == "root"
            or (
                file_build is not None
                and "Relationship" not in package
                and (result["Target"], package["Name"], package.get("Layer"))
                == (file_build["target"], file_build["module"], file_build["layer"])
            )
        )
        and isinstance(package.get("Identifier"), dict)
        and isinstance(package["Identifier"].get("PURL"), str)
        and package["Identifier"]["PURL"].casefold() == ("pkg:golang/" + package["Name"]).casefold()
    )


def go_relative_root(result, package, packages):
    return (
        "Version" not in package and result.get("Class") == "lang-pkgs"
        and result.get("Type") == "gobinary" and isinstance(result.get("Target"), str)
        and bool(result["Target"]) and package.get("ID") == package["Name"] == "../"
        and package.get("AnalyzedBy") == "gobinary" and "Relationship" not in package
        and isinstance(package.get("Identifier"), dict)
        and set(package["Identifier"]) == {"UID"}
        and isinstance(package["Identifier"]["UID"], str)
        and any(
            isinstance(root, dict) and root.get("Relationship") == "root"
            and isinstance(root.get("Version"), str) and bool(root["Version"])
            and isinstance(root.get("Identifier"), dict)
            and str(root["Identifier"].get("PURL", "")).startswith("pkg:golang/")
            and isinstance(root.get("DependsOn"), list) and "../" in root["DependsOn"]
            for root in packages
        )
    )


def package_coverage(results, file_build=None):
    covered = bool(results)
    limitations = []
    for result in results:
        packages = result.get("Packages")
        covered = covered and result.get("Class") in ("os-pkgs", "lang-pkgs") and bool(result.get("Type")) and isinstance(packages, list) and bool(packages)
        if packages is None:
            continue
        require(isinstance(packages, list), INVALID_PACKAGE_INVENTORY)
        for package in packages:
            require(isinstance(package, dict) and isinstance(package.get("Name"), str)
                    and package["Name"], INVALID_PACKAGE_INVENTORY)
            go_root = go_root_package(result, package, file_build)
            relative_root = go_relative_root(result, package, packages)
            replacement = not (go_root or relative_root) and versionless_go_replacement(result, package)
            require(go_root or relative_root or replacement
                    or (isinstance(package.get("Version"), str) and package["Version"]),
                    INVALID_PACKAGE_INVENTORY)
            if replacement:
                covered = False
                limitations.append({"target": result["Target"], "module": package["Name"],
                                     "version": "unknown", "reason": "Go local/workspace replacement has no version"})
    return bool(covered), limitations


def decide(selection, report, enabled):
    require(report.get("ArtifactName") == selection["ref"], "scan reference differs from selected published image")
    validate_native_inventory(report, ARTIFACT / "trivy-full.json")
    results = validate_report_results(report, "published full report", False)
    normalized = findings(report, "published full report")
    require(report.get("Metadata", {}).get("OS", {}).get("EOSL") is not True, "published image is end-of-life")
    file_build = reviewed_file_build(selection, report)
    covered, limitations = package_coverage(results, file_build)
    spec = selection["spec"]
    changed_upstream = spec["upstream"] != {k: selection["published"]["upstream"][k] for k in ("ref", "tag", "digest")}
    requested = []
    no_fix = unsupported = 0
    for key, item in normalized.items():
        if not item["fixed_version"]:
            no_fix += 1
            continue
        actionable = (item["class"] == "os-pkgs" and spec["patchPolicy"] == "enabled") or (item["class"] == "lang-pkgs" and changed_upstream)
        if not actionable:
            unsupported += 1
            continue
        requested.append({"id": key.rsplit("|", 1)[1], "package": item.get("package", key.split("|", 2)[1]),
                          "installed": item["installed_version"], "class": item["class"],
                          "type": item["type"], "target": item["target"]})
    requested = sorted({canonical(item): item for item in requested}.values(), key=canonical)
    value = {"app": selection["app"], "ref": selection["ref"], "proceed": False,
             "force_repromote": False, "findings": len(normalized), "no_fix": no_fix,
             "unsupported": unsupported, "actionable": len(requested), "package_coverage": bool(covered)}
    if limitations:
        value["coverage_limitations"] = limitations
    if file_build is not None:
        value.setdefault("coverage_limitations", []).extend([{"target": file_build["target"], "module": file_build["module"],
            "version": "unknown", "reason": "reviewed first-party Go file build has no module version",
            "review_sha256": file_build["review_sha256"]}])
    if not covered:
        value["reason"] = "package coverage incomplete; full report retained"
    elif not requested:
        value["reason"] = "no actionable fix; full findings retained"
    elif not enabled:
        value["reason"] = "automatic remediation disabled; full findings retained"
    else:
        value.update(proceed=True, force_repromote=True, reason="actionable producer remediation",
                     requested_remediation={"app": selection["app"], "ref": selection["ref"],
                                            "findings": requested, "need_sha256": findings_hash(requested)})
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("select", "decide"))
    args = parser.parse_args()
    if args.command == "select":
        select()
    else:
        selection = json.loads((ARTIFACT / SELECTION_FILE).read_text())
        report = json.loads((ARTIFACT / "trivy-full.json").read_text())
        package, tag = selection["ref"].split(":", 1)
        retain("secobserve-upload.json", {"app": selection["app"], "upstream_ref": package, "upstream_tag": tag})
        value = decide(selection, report, os.getenv("REMEDIATION_ENABLED", "").lower() == "true")
        retain("decision.json", value)
        output(value)


if __name__ == "__main__":
    main()
