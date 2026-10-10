"""Supplement Trivy with independently replayable, pinned Arch scanner evidence."""

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import parse_qs, unquote, urlsplit
from urllib.request import urlopen

from univers.versions import ArchLinuxVersion
import native_chisel_inventory as native
from scan_native_chisel import image_inputs

PINS = {
    "syft": ("1.54.0", "54a87372498168b2d033e876fd41fa4e8035b872699e525a57046e1f2f09c860",
             "d46a9a61a6ae3d367f0a03748c5e9c59253e586c4388ab26ddcacebc2efa0d92"),
    "grype": ("0.120.0", "a5a1218dce63acdac152a6b3b5bb366e7267e36f4069848cf455543b3fa5700e",
              "4de6935c80c111d3d37b2b09f86d1a30b3d10a2f7146d4dbe74ed86c81f35790"),
}
SIDES = ("arch-before", "arch-after", "arch-published")
require = native.require
read_json = native.read_json


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def regular_files(root):
    require(root.is_dir() and not root.is_symlink(), "unsafe Arch capsule directory")
    files = {}
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink() and (path.is_dir() or path.is_file()), "unsafe Arch capsule file")
        if path.is_file():
            files[path.relative_to(root).as_posix()] = native.file_digest(path)
    return files


def local_path(root, value):
    require(isinstance(value, str) and value and Path(value).as_posix() == value
            and not Path(value).is_absolute() and ".." not in Path(value).parts,
            "unsafe Arch capsule path")
    path = root / value
    require(all(not parent.is_symlink() for parent in (path, *path.parents)), "unsafe Arch capsule symlink")
    require(path.is_file(), "missing Arch capsule file")
    return path


def checked_blob(oci, descriptor):
    require(isinstance(descriptor, dict) and re.fullmatch(r"sha256:[0-9a-f]{64}", descriptor.get("digest", ""))
            and type(descriptor.get("size")) is int, "invalid OCI descriptor")
    path = local_path(oci, "blobs/sha256/" + descriptor["digest"][7:])
    require(path.stat().st_size == descriptor["size"] and native.file_digest(path) == descriptor["digest"][7:],
            "OCI descriptor digest or size mismatch")
    return path


def inventory(oci, reference, raw):
    regular_files(oci)
    index = read_json(oci / "index.json")
    require(index.get("schemaVersion") == 2 and len(index.get("manifests", [])) == 1,
            "Arch OCI must contain one immutable child")
    manifest_path = checked_blob(oci, index["manifests"][0])
    require(reference.endswith("@" + index["manifests"][0]["digest"]), "OCI reference mismatch")
    manifest = read_json(manifest_path)
    require(manifest.get("schemaVersion") == 2, "invalid OCI manifest")
    config_path = checked_blob(oci, manifest["config"])
    config = read_json(config_path)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64", "unsupported Arch platform")
    for descriptor in manifest["layers"]:
        checked_blob(oci, descriptor)
    inputs = image_inputs(oci, reference, Path("unused"), Path("unused"), "unused")
    files = native.image_files(inputs, raw)
    release_path = "etc/os-release" if "etc/os-release" in files else "usr/lib/os-release"
    if release_path not in files:
        return None
    release = {}
    for line in native.read_image_file(files, release_path).decode().splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            parsed = shlex.split(value)
            require(len(parsed) == 1 and key not in release, "invalid OCI OS release")
            release[key] = parsed[0]
    if release.get("ID") != "arch":
        return None
    require(release.get("VERSION_ID"), "Arch OS version missing")
    packages = []
    for name in sorted(files):
        if re.fullmatch(r"var/lib/pacman/local/[^/]+/desc", name):
            fields = {}
            for block in native.read_image_file(files, name).decode().strip().split("\n\n"):
                lines = block.splitlines()
                require(lines and lines[0] not in fields, "duplicate pacman field")
                fields[lines[0]] = lines[1:]
            require(all(len(fields.get(key, [])) == 1 for key in ("%NAME%", "%VERSION%", "%ARCH%")),
                    "invalid pacman package")
            package = {key: fields[field][0] for key, field in
                       (("name", "%NAME%"), ("version", "%VERSION%"), ("arch", "%ARCH%"))}
            require(re.fullmatch(r"[a-zA-Z0-9@._+:-]+", package["name"])
                    and package["arch"] in ("x86_64", "any") and ArchLinuxVersion.is_valid(package["version"]),
                    "invalid native Arch tuple")
            package["path"] = "/" + name
            packages.append(package)
    require(packages and len({p["name"] for p in packages}) == len(packages), "empty or duplicate pacman inventory")
    return {"os": release, "packages": packages}


def configuration(tool, replay=False):
    if tool == "syft":
        return {"check-for-app-update": False, "scope": "squashed"}
    return {"check-for-app-update": False, "timestamp": False, "ignore": [], "exclude": [],
            "match-upstream-kernel-headers": True, "only-fixed": False, "only-notfixed": False,
            "vex-documents": [], "external-sources": {"enable": False},
            "db": {"cache-dir": "db", "auto-update": False, "validate-by-hash-on-start": True,
                   "validate-age": not replay, "max-allowed-built-age": "120h"}}


def run_tool(root, tool, arguments, replay=False):
    executable = local_path(root, "tools/" + tool)
    require(native.file_digest(executable) == PINS[tool][2], "untrusted Arch scanner executable")
    executable.chmod(0o755)
    with tempfile.TemporaryDirectory(prefix=".runtime-", dir=root) as temporary:
        runtime = Path(temporary)
        config = runtime / "config.json"
        write_json(config, configuration(tool, replay))
        env = {"PATH": "/usr/bin:/bin", "HOME": temporary, "XDG_CONFIG_HOME": temporary,
               "XDG_CACHE_HOME": temporary, "TMPDIR": temporary, "LANG": "C.UTF-8"}
        return subprocess.run([str(executable), "--config", str(config), *arguments], cwd=root,
                              env=env, capture_output=True, check=True, timeout=600).stdout


def stage_tools(root, source):
    target = root / "tools"
    target.mkdir()
    for tool, (version, archive_hash, binary_hash) in PINS.items():
        archive_name = f"{tool}_{version}_linux_amd64.tar.gz"
        checksums = f"{tool}_{version}_checksums.txt"
        for filename in (archive_name, checksums):
            destination = target / filename
            if source:
                shutil.copyfile(local_path(source, filename), destination)
            else:
                url = f"https://github.com/anchore/{tool}/releases/download/v{version}/{filename}"
                with urlopen(url, timeout=60) as stream, destination.open("wb") as output:
                    shutil.copyfileobj(stream, output)
        require(native.file_digest(target / archive_name) == archive_hash, "untrusted Arch scanner archive")
        require(f"{archive_hash}  {archive_name}" in (target / checksums).read_text().splitlines(),
                "Arch release checksum mismatch")
        with tarfile.open(target / archive_name) as archive:
            member = archive.getmember(tool)
            require(member.isfile(), "unsafe Arch executable archive member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("missing Arch executable")
            with (target / tool).open("wb") as output:
                shutil.copyfileobj(stream, output)
        require(native.file_digest(target / tool) == binary_hash, "untrusted Arch binary")
        write_json(target / f"{tool}-config.json", configuration(tool))
        version_info = json.loads(run_tool(root, tool, ["version", "-o", "json"]))
        require(version_info.get("version") == version and version_info.get("platform") == "linux/amd64",
                "Arch scanner version mismatch")
        write_json(target / f"{tool}-version.json", version_info)


def validate_tools(root):
    for tool, (version, archive_hash, binary_hash) in PINS.items():
        require(native.file_digest(local_path(root, f"tools/{tool}_{version}_linux_amd64.tar.gz")) == archive_hash
                and native.file_digest(local_path(root, "tools/" + tool)) == binary_hash,
                "untrusted Arch scanner pins")
        require(f"{archive_hash}  {tool}_{version}_linux_amd64.tar.gz" in
                local_path(root, f"tools/{tool}_{version}_checksums.txt").read_text().splitlines(),
                "Arch release checksum mismatch")
        require(read_json(root / "tools" / f"{tool}-config.json") == configuration(tool), "Arch scanner config mismatch")
        actual = json.loads(run_tool(root, tool, ["version", "-o", "json"]))
        require(actual == read_json(root / "tools" / f"{tool}-version.json") and actual["version"] == version
                and actual["platform"] == "linux/amd64", "Arch scanner version mismatch")
    require(actual.get("supportedDbSchema") == 6, "unknown Grype DB schema")
    require(read_json(root / "tools/syft-version.json").get("schemaVersion") == "16.1.11", "unknown Syft schema")


def validate_database(root, status, scanned_at):
    require(status.get("valid") is True and re.fullmatch(r"v6\.\d+\.\d+", status.get("schemaVersion", "")),
            "invalid Grype database status")
    built = datetime.fromisoformat(status["built"].replace("Z", "+00:00"))
    now = datetime.fromisoformat(scanned_at.replace("Z", "+00:00"))
    require(built.tzinfo is not None and now.tzinfo is not None and timedelta(0) <= now - built <= timedelta(hours=120),
            "Grype database stale or future dated")
    imported = read_json(root / "db/6/import.json")
    source = urlsplit(imported.get("source", ""))
    require(source.scheme == "https" and source.netloc == "grype.anchore.io"
            and source.path.startswith("/databases/v6/") and status["from"] == imported["source"]
            and re.fullmatch(r"sha256:[0-9a-f]{64}", parse_qs(source.query).get("checksum", [""])[0])
            and imported.get("client_version") == status["schemaVersion"], "invalid Grype database source")


def syft_packages(sbom, native_inventory, raw, reference):
    require(sbom.get("schema", {}).get("version") == "16.1.11" and sbom["distro"].get("id") == "arch"
            and sbom["distro"].get("versionID") == native_inventory["os"]["VERSION_ID"], "Syft OS/schema mismatch")
    source = sbom["source"]["metadata"]
    require(source["manifestDigest"] == reference.rsplit("@", 1)[1] and source["imageID"] == raw["Metadata"]["ImageID"]
            and json.loads(base64.b64decode(source["config"])) == raw["Metadata"]["ImageConfig"], "Syft OCI source mismatch")
    require(native.digest(base64.b64decode(source["manifest"])) == reference.rsplit("@sha256:", 1)[1],
            "Syft manifest mismatch")
    packages = [p for p in sbom["artifacts"] if p["type"] == "alpm"]
    expected = {(p["name"], p["version"], p["arch"], p["path"]) for p in native_inventory["packages"]}
    found = set()
    for package in packages:
        metadata = package["metadata"]
        primary = [p["path"] for p in package["locations"] if p.get("annotations", {}).get("evidence") == "primary"]
        require(package["foundBy"] == "alpm-db-cataloger" and len(primary) == 1
                and (package["name"], package["version"]) == (metadata["package"], metadata["version"]), "invalid Syft ALPM identity")
        purl = urlsplit(package["purl"])
        require(purl.scheme == "pkg" and unquote(purl.path) == f"alpm/arch/{package['name']}@{package['version']}"
                and parse_qs(purl.query).get("arch") == [metadata["architecture"]], "invalid Syft ALPM PURL")
        found.add((package["name"], package["version"], metadata["architecture"], primary[0]))
    require(len(found) == len(packages) and found == expected, "native/Syft tuple mismatch")
    return {p["id"]: p for p in packages}


def finding_rows(match, packages):
    artifact, vulnerability = match["artifact"], match["vulnerability"]
    package = packages.get(artifact["id"])
    require(package and all(artifact[k] == package[k] for k in ("name", "version", "purl", "type")),
            "Grype package mismatch")
    require(re.fullmatch(r"AVG-\d+", vulnerability.get("id", ""))
            and vulnerability.get("namespace") == "arch:distro:archlinux:rolling"
            and vulnerability.get("dataSource") == "https://security.archlinux.org/" + vulnerability["id"], "invalid Arch advisory")
    severity = vulnerability["severity"].upper()
    require(severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL", "NEGLIGIBLE"), "invalid Grype severity")
    severity = "LOW" if severity == "NEGLIGIBLE" else severity
    fix = vulnerability["fix"]
    require(fix.get("state") in ("fixed", "not-fixed", "wont-fix", "unknown")
            and isinstance(fix.get("versions"), list)
            and all(isinstance(v, str) and ArchLinuxVersion.is_valid(v) for v in fix["versions"]), "invalid Grype fix")
    upgrades = [v for v in fix["versions"] if ArchLinuxVersion(v) > ArchLinuxVersion(package["version"])]
    require(fix["state"] != "fixed" or upgrades, "fixed Arch advisory has no upgrade")
    fixed = min(upgrades, key=ArchLinuxVersion) if fix["state"] == "fixed" else ""
    aliases = {row["id"] for row in match["relatedVulnerabilities"]}
    require(all(re.fullmatch(r"CVE-\d{4}-\d{4,}", value) for value in aliases), "invalid Arch CVE aliases")
    provenance = {"name": "grype", "version": PINS["grype"][0], "primary": vulnerability["id"],
                  "aliases": sorted(aliases), "namespace": vulnerability["namespace"],
                  "dataSource": vulnerability["dataSource"], "fix": fix, "match": match}
    return [{"VulnerabilityID": identity, "PkgName": package["name"], "InstalledVersion": package["version"],
             "PkgID": package["name"] + "@" + package["version"],
             "FixedVersion": fixed, "Severity": severity, "PkgIdentifier": {"PURL": package["purl"]},
             "PrimaryURL": vulnerability["dataSource"], "DataSource": {"ID": "archlinux", "Name": "Grype / Arch Linux", "URL": vulnerability["dataSource"]},
             "Description": vulnerability.get("description", ""), "ArchProvenance": provenance}
            for identity in [vulnerability["id"], *sorted(aliases)]]


def supplement(raw, inventory_value, sbom, scan, reference, marker, fixable=False):
    packages = syft_packages(sbom, inventory_value, raw, reference)
    require(scan["descriptor"]["name"] == "grype" and scan["descriptor"]["version"] == PINS["grype"][0]
            and not scan.get("ignoredMatches"), "invalid or suppressed Grype scan")
    matches = [m for m in scan["matches"] if m["artifact"]["type"] == "alpm"]
    findings = [row for match in matches for row in finding_rows(match, packages)]
    identities: dict[tuple[str, str], dict] = {}
    for row in findings:
        key = (row["PkgIdentifier"]["PURL"], row["VulnerabilityID"])
        require(key not in identities or identities[key] == row, "conflicting Arch findings")
        identities[key] = row
    report = copy.deepcopy(raw)
    require(not any(r.get("Class") == "os-pkgs" for r in report.get("Results", [])), "Arch report already has OS inventory")
    report.setdefault("Metadata", {})["OS"] = {"Family": "archlinux", "Name": inventory_value["os"]["VERSION_ID"]}
    rows = [{"ID": p["name"] + "@" + p["version"], "Name": p["name"], "Version": p["version"],
             "Arch": p["metadata"]["architecture"], "Identifier": {"PURL": p["purl"]},
             "AnalyzedBy": "syft", "ArchScanner": {"name": "syft", "version": PINS["syft"][0]}}
            for p in sorted(packages.values(), key=lambda p: p["name"])]
    report.setdefault("Results", []).append({"Target": "Arch Linux " + inventory_value["os"]["VERSION_ID"],
        "Class": "os-pkgs", "Type": "archlinux", "Packages": rows,
        "Vulnerabilities": [r for r in identities.values() if not fixable or r["FixedVersion"]],
        "ArchScanner": {"inventory": "syft", "findings": "grype", "raw_advisories": len(matches), "policy_identities": len(identities)}})
    report["ArchScanner"] = {"schema": "arch-scanner-v1", "capsule": marker}
    return report


def semantic(value):
    result = copy.deepcopy(value)
    source = result.get("source", {})
    if "name" in source:
        source["name"] = "presentation"
    if isinstance(source.get("target"), dict) and "userInput" in source["target"]:
        source["target"]["userInput"] = "presentation"
    for key in ("userInput", "file", "path"):
        if key in source.get("metadata", {}):
            source["metadata"][key] = "presentation"
    descriptor = result.get("descriptor", {})
    descriptor.pop("timestamp", None)
    config = descriptor.get("configuration", {})
    config.pop("configPath", None)
    for family, field in (("java-archive", "maven-localrepository-dir"), ("golang", "local-mod-cache-dir")):
        if family in config.get("packages", {}):
            config["packages"][family][field] = "isolated-runtime-path"
    if "db" in config:
        config["db"]["validate-age"] = True
    status = descriptor.get("db", {}).get("status", {})
    status.pop("path", None)
    return result


def replay(root, capsule):
    validate_tools(root)
    raw = read_json(root / "raw-trivy.json")
    native_inventory = inventory(root / "oci", capsule["reference"], raw)
    require(native_inventory == read_json(root / "pacman.json"), "Arch native inventory mismatch")
    db_hash = native.file_digest(root / "db/6/vulnerability.db")
    require(db_hash == capsule["grype_db_sha256"], "Grype frozen database mismatch")
    sbom = json.loads(run_tool(root, "syft", ["scan", "oci-dir:oci", "--scope", "squashed", "-o", "syft-json"]))
    require(semantic(sbom) == semantic(read_json(root / "syft.json")), "Syft independent replay mismatch")
    with tempfile.TemporaryDirectory(prefix=".replay-", dir=root) as temporary:
        sbom_path = Path(temporary) / "syft.json"
        write_json(sbom_path, sbom)
        scan = json.loads(run_tool(root, "grype", ["sbom:" + str(sbom_path), "-o", "json"], replay=True))
    require(semantic(scan) == semantic(read_json(root / "grype.json")), "Grype independent replay mismatch")
    validate_database(root, scan["descriptor"]["db"]["status"], capsule["scanned_at"])
    recorded_status = read_json(root / "db-status.json")
    require(recorded_status == scan["descriptor"]["db"]["status"], "Grype database status mismatch")
    require(native.file_digest(root / "db/6/vulnerability.db") == db_hash, "Grype replay changed DB")
    return supplement(raw, native_inventory, sbom, read_json(root / "grype.json"), capsule["reference"],
                      root.name + "/capsule.json")


def verify_capsule(path):
    path = Path(path)
    require(path.name == "capsule.json" and path.parent.name in SIDES, "invalid Arch capsule path")
    require(all(not p.is_symlink() for p in (path, *path.parents)), "unsafe Arch capsule symlink")
    root = path.parent.resolve()
    capsule = read_json(path)
    require(set(capsule) == {"schema", "reference", "scanned_at", "grype_db_sha256", "hashes"}
            and capsule["schema"] == "arch-scanner-capsule-v1", "invalid Arch capsule schema")
    hashes = regular_files(root)
    hashes.pop("capsule.json")
    require(hashes == capsule["hashes"], "Arch capsule file set or digest mismatch")
    for name in capsule["hashes"]:
        local_path(root, name)
    expected = replay(root, capsule)
    require(expected == read_json(root / "report.json"), "Arch capsule report mismatch")
    final_hashes = regular_files(root)
    final_hashes.pop("capsule.json")
    require(final_hashes == hashes, "Arch replay changed capsule inputs")
    return expected


def scan_image(args):
    raw = read_json(args.report)
    from evaluate_promotion import VERSION_CLASSES

    metadata = raw.get("Metadata")
    require(isinstance(metadata, dict), "invalid Trivy image metadata")
    os_metadata = metadata.get("OS")
    require(os_metadata is None or isinstance(os_metadata, dict), "invalid Trivy OS metadata")
    family = os_metadata.get("Family") if os_metadata else None
    require(family is None or isinstance(family, str), "invalid Trivy OS family")
    if family in VERSION_CLASSES and family != "archlinux":
        return
    native_inventory = inventory(args.oci, args.reference, raw)
    if native_inventory is None:
        return
    root = args.evidence.resolve()
    require(root.name in SIDES and not args.evidence.is_symlink() and not root.exists(), "Arch evidence already exists or unsafe")
    root.mkdir()
    shutil.copytree(args.oci, root / "oci")
    shutil.copyfile(args.report, root / "raw-trivy.json")
    regular_files(args.cache / "db")
    shutil.copytree(args.cache / "db", root / "trivy-cache/db")
    stage_tools(root, args.tools)
    if args.previous:
        verify_capsule(args.previous / "capsule.json")
        require(args.grype_db is None, "after scan cannot replace frozen Grype DB")
        source = args.previous / "db"
    else:
        source = args.grype_db
    if source:
        regular_files(source)
        shutil.copytree(source, root / "db")
    else:
        run_tool(root, "grype", ["db", "update"])
    scanned_at = datetime.now(timezone.utc).isoformat()
    status = json.loads(run_tool(root, "grype", ["db", "status", "-o", "json"]))
    validate_database(root, status, scanned_at)
    write_json(root / "db-status.json", status)
    db_hash = native.file_digest(root / "db/6/vulnerability.db")
    write_json(root / "pacman.json", native_inventory)
    sbom_bytes = run_tool(root, "syft", ["scan", "oci-dir:oci", "--scope", "squashed", "-o", "syft-json"])
    (root / "syft.json").write_bytes(sbom_bytes)
    sbom = json.loads(sbom_bytes)
    scan_bytes = run_tool(root, "grype", ["sbom:syft.json", "-o", "json"])
    (root / "grype.json").write_bytes(scan_bytes)
    scan = json.loads(scan_bytes)
    require(native.file_digest(root / "db/6/vulnerability.db") == db_hash, "Grype scan changed DB")
    report = supplement(raw, native_inventory, sbom, scan, args.reference, root.name + "/capsule.json")
    write_json(root / "report.json", report)
    if args.fixable:
        fixed = read_json(args.fixable)
        require(fixed["Metadata"] == raw["Metadata"] and fixed["ArtifactName"] == raw["ArtifactName"], "Arch fixable identity mismatch")
        shutil.copyfile(args.fixable, root / "raw-fixable.json")
        write_json(args.fixable, supplement(fixed, native_inventory, sbom, scan, args.reference,
                                           root.name + "/capsule.json", fixable=True))
    capsule = {"schema": "arch-scanner-capsule-v1", "reference": args.reference, "scanned_at": scanned_at,
               "grype_db_sha256": db_hash, "hashes": regular_files(root)}
    write_json(root / "capsule.json", capsule)
    verify_capsule(root / "capsule.json")
    write_json(args.report, report)


def annotate_cyclonedx(report_path, cdx_path):
    report = read_json(report_path)
    if not report.get("ArchScanner"):
        return
    from evaluate_promotion import validate_native_inventory

    validate_native_inventory(report, report_path)
    cdx = read_json(cdx_path)
    require(cdx.get("bomFormat") == "CycloneDX", "invalid CycloneDX document")
    os_row = next(r for r in report["Results"] if r.get("Type") == "archlinux")
    packages = {(p["Name"], p["Version"]): p for p in os_row["Packages"]}
    refs = {}
    for component in cdx["components"]:
        package = packages.get((component["name"], component.get("version")))
        if package and component.get("purl", "").startswith("pkg:alpm/arch/"):
            component["purl"] = package["Identifier"]["PURL"]
            component.setdefault("properties", []).append({"name": "trusted-images:inventory:scanner", "value": "syft@" + PINS["syft"][0]})
            refs[component["bom-ref"]] = component["purl"]
    findings = {(f["VulnerabilityID"], f["PkgIdentifier"]["PURL"]): f for f in os_row["Vulnerabilities"]}
    for vulnerability in cdx.get("vulnerabilities", []):
        native_rows = [findings[(vulnerability["id"], refs[a["ref"]])] for a in vulnerability["affects"]
                       if a["ref"] in refs and (vulnerability["id"], refs[a["ref"]]) in findings]
        if native_rows:
            provenance = native_rows[0]["ArchProvenance"]
            vulnerability["source"] = {"name": "Grype / Arch Linux", "url": provenance["dataSource"]}
            vulnerability.setdefault("properties", []).extend([
                {"name": "trusted-images:findings:scanner", "value": "grype@" + PINS["grype"][0]},
                {"name": "trusted-images:findings:primary-advisory", "value": provenance["primary"]},
                {"name": "trusted-images:findings:namespace", "value": provenance["namespace"]}])
    tools = cdx.setdefault("metadata", {}).setdefault("tools", {}).setdefault("components", [])
    tools.extend({"type": "application", "name": name, "version": pin[0]} for name, pin in PINS.items())
    write_json(cdx_path, cdx)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("scan", "verify", "annotate"))
    for name in ("report", "oci", "evidence", "cache", "tools", "grype-db", "previous", "fixable", "capsule", "cdx"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--reference")
    args = parser.parse_args()
    required = {"verify": ("capsule",), "annotate": ("report", "cdx"),
                "scan": ("report", "oci", "reference", "evidence", "cache")}[args.operation]
    for name in required:
        if getattr(args, name) is None:
            parser.error("--" + name + " is required")
    if args.operation == "verify":
        verify_capsule(args.capsule)
    elif args.operation == "annotate":
        annotate_cyclonedx(args.report, args.cdx)
    else:
        scan_image(args)


if __name__ == "__main__":
    main()
