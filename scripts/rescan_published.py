"""Scan the latest merged published image and request producer remediation."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import yaml

from evaluate_promotion import findings, validate_report_results
from finding_identity import canonical, findings_hash, REF, require
from promote_signing_gate import load_identity
from reverify_signing import signed_record
from validate_inventory import entry_failures

ARTIFACT = Path("published-rescan")
SELECTION_FILE = "selection.json"


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def retain(name, value):
    ARTIFACT.mkdir(exist_ok=True)
    (ARTIFACT / name).write_text(canonical(value) + "\n")
    paths = sorted(p for p in ARTIFACT.iterdir() if p.name != "SHA256SUMS")
    (ARTIFACT / "SHA256SUMS").write_text("".join(
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in paths))


def output(values):
    print(canonical(values))
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value if isinstance(value, str) else canonical(value)}\n")
    if os.getenv("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
            stream.write("\nPublished-image rescan: `" + canonical(values) + "`\n")


def latest_record(app):
    records = []
    paths = git("ls-tree", "-r", "--name-only", "origin/main", "--", f"provenance/{app}").splitlines()
    identity = load_identity(Path("config/signing-identity.json"))
    for name in paths:
        if not name.endswith(".json"):
            continue
        record = json.loads(git("show", f"origin/main:{name}"))
        require(record.get("schema") == "trusted-images.bocklabs.dev/provenance-v1" and
                record.get("app") == app, "invalid merged publication identity")
        if record.get("policy", {}).get("eligible") is not True:
            continue
        internal = record["internal"]
        ref = f"{internal['package']}:{internal['tag']}@{internal['digest']}"
        require(REF.fullmatch(ref) and internal["package"] == f"ghcr.io/bocklabs/{app}" and
                Path(name).stem == internal["tag"], "invalid merged publication reference")
        promoted = datetime.fromisoformat(record["promoted_at"].replace("Z", "+00:00"))
        require(promoted.tzinfo is not None, "publication time requires timezone")
        records.append((promoted, ref, record))
    if not records:
        return None
    latest = max(records, key=lambda item: item[0])
    record = latest[2]
    signed_record(record, Path(f"provenance/{app}/{record['internal']['tag']}.json"), identity)
    require(record["validation"].get("result") == "pass" and
            record["internal"]["platforms"] == ["linux/amd64"], "invalid published validation/platform")
    return latest


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


def package_coverage(results):
    covered = bool(results)
    for result in results:
        packages = result.get("Packages")
        covered = covered and result.get("Class") in ("os-pkgs", "lang-pkgs") and bool(result.get("Type")) and isinstance(packages, list) and bool(packages)
        if packages is not None:
            require(isinstance(packages, list) and all(isinstance(p, dict) and
                    isinstance(p.get("Name"), str) and p["Name"] and
                    isinstance(p.get("Version"), str) and p["Version"] for p in packages),
                    "invalid scanned package inventory")
    return bool(covered)


def decide(selection, report, enabled):
    require(report.get("ArtifactName") == selection["ref"], "scan reference differs from selected published image")
    results = validate_report_results(report, "published full report", False)
    normalized = findings(report, "published full report")
    require(report.get("Metadata", {}).get("OS", {}).get("EOSL") is not True, "published image is end-of-life")
    covered = package_coverage(results)
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
    if not covered:
        value["reason"] = "unsupported scanner/package coverage; full report retained"
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
