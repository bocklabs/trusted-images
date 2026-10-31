#!/usr/bin/env python3
"""Generate reviewed Go file-build evidence from a published-image scan."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

INVENTORY = Path(__file__).resolve().parents[1] / "inventory"
DEVEL = "(devel)"
VCS_REVISION = "vcs.revision"
GITHUB_PREFIX = "https://github.com/"


def require(value, message):
    if not value:
        raise ValueError(message)


def run(*args, cwd=None):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=120, cwd=cwd).stdout


def docker(*args):
    return run("docker", *args)


def parse_build_info(text):
    lines = text.splitlines()
    require(lines and ": go" in lines[0], "unreadable Go build info")
    info = {
        "go_version": "go" + lines[0].rsplit("go", 1)[-1],
        "program": "",
        "main_module": "",
        "module_version": "",
        "first_party_module": "",
        "deps": [],
        "build": {},
    }
    for line in lines[1:]:
        fields = line.strip().split("\t")
        if len(fields) >= 2 and fields[0] == "path":
            info["program"] = fields[1]
        elif len(fields) >= 3 and fields[0] == "mod":
            info["main_module"], info["module_version"] = fields[1], fields[2]
        elif len(fields) >= 3 and fields[0] == "dep":
            info["deps"].append(fields[1:])
        elif len(fields) >= 2 and fields[0] == "build":
            key, _, value = fields[1].partition("=")
            info["build"][key] = value
    info["first_party_module"] = info["main_module"] or next(
        (dep[0] for dep in info["deps"] if DEVEL in dep), ""
    )
    require(info["program"] and info["first_party_module"], "Go build info lacks program or first-party module")
    if not info["main_module"]:
        info["module_version"] = DEVEL
    info["go_package_count"] = len(info["deps"])
    info["versioned_go_package_count"] = sum(DEVEL not in dep for dep in info["deps"])
    return info


def versionless_targets(report):
    targets = {}
    for result in report.get("Results") or []:
        if result.get("Class") != "lang-pkgs" or result.get("Type") != "gobinary":
            continue
        packages = [p for p in result.get("Packages") or [] if not p.get("Version") and p.get("AnalyzedBy") == "gobinary"]
        if packages:
            targets[result["Target"]] = packages
    return targets


def target_layer(packages):
    layers = {json.dumps(p.get("Layer"), sort_keys=True) for p in packages}
    require(len(layers) == 1 and "null" not in layers, "versionless Go packages span multiple layers")
    return packages[0]["Layer"]


def infer_modules(packages, info):
    if info["module_version"] == DEVEL:
        return [info["first_party_module"]]
    relative = sorted({p["Name"] for p in packages if p["Name"].startswith(("./", "../"))})
    require(relative, "versioned Go binary has no reviewed relative package")
    absolute = [p["Name"] for p in packages if not p["Name"].startswith(("./", "../"))]
    require(not absolute, "versioned Go binary has an unreviewed absolute package")
    return relative


def resolve_tag(repository, *tags):
    for tag in tags:
        try:
            output = run("git", "ls-remote", "--tags", repository, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
        except subprocess.CalledProcessError:
            continue
        rows = [line.split() for line in output.splitlines() if line.split()]
        refs = {ref: sha for sha, ref in rows}
        revision = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
        if revision:
            return tag, revision
    raise ValueError(f"source tag is not resolvable for {repository}: {tags[-1]}")


def github_source(module):
    parts = module.split("/")
    if len(parts) >= 3 and parts[0] == "github.com":
        return f"{GITHUB_PREFIX}{parts[1]}/{parts[2]}"
    return ""


def same_repository(left, right):
    return left.rstrip("/").lower() == right.rstrip("/").lower()


def opaque_source(module_repo, vcs_revision, image_version, deps, fallback):
    if module_repo or not vcs_revision or not image_version:
        return fallback
    candidates = {
        repo.lower(): repo for dep in deps
        if dep[1] == image_version and (repo := github_source(dep[0]))
    }
    if not candidates:
        return fallback
    require(len(candidates) == 1, "ambiguous binary source repositories")
    repository = next(iter(candidates.values()))
    tag, revision = resolve_tag(repository, image_version)
    require(revision == vcs_revision, "source tag revision differs from binary VCS revision")
    return repository, tag, revision


def source_info(labels, info):
    label_repo = labels.get("org.opencontainers.image.source", "")
    module_repo = github_source(info["first_party_module"])
    repository = module_repo or label_repo
    if label_repo and (
        labels.get("org.opencontainers.image.revision")
        or not module_repo
        or same_repository(module_repo, label_repo)
    ):
        repository = label_repo
    require(repository, "source repository is unknown")
    revision = labels.get("org.opencontainers.image.revision", "") if repository == label_repo else ""
    vcs_revision = info["build"].get(VCS_REVISION, "")
    revision = revision or vcs_revision
    base_tag = labels.get("org.opencontainers.image.base.name", "").rsplit(":", 1)[-1]
    tag = info["module_version"] if info["module_version"] != DEVEL else base_tag
    if not revision:
        require(base_tag, "image has no source tag or revision")
        require(
            repository.startswith(GITHUB_PREFIX),
            "source tag fallback requires a GitHub repository",
        )
        tag, revision = resolve_tag(repository, f"v{base_tag}", base_tag)
    repository, tag, revision = opaque_source(
        module_repo, vcs_revision, labels.get("org.opencontainers.image.version", ""), info.get("deps", []),
        (repository, tag, revision),
    )
    files = {}
    if repository.startswith(GITHUB_PREFIX):
        raw = repository.replace(GITHUB_PREFIX, "https://raw.githubusercontent.com/")
        for name in ("Dockerfile", "go.mod"):
            url = f"{raw}/{revision}/{name}"
            try:
                with urllib.request.urlopen(url, timeout=20) as response:
                    data = response.read()
            except (urllib.error.URLError, TimeoutError):
                continue
            files[name] = {"url": url, "sha256": hashlib.sha256(data).hexdigest()}
    return {"repository": repository, "revision": revision, **({"tag": tag} if tag else {}), "files": files}


def binary_build_info(ref, target):
    with tempfile.TemporaryDirectory() as directory:
        name = Path(target).name
        container = docker("create", ref).strip()
        try:
            docker("cp", f"{container}:{target}", str(Path(directory) / name))
        finally:
            docker("rm", "-f", container)
        path = Path(directory) / name
        binary_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        text = run("go", "version", "-m", name, cwd=directory)
        info = parse_build_info(text)
        info["sha256"] = hashlib.sha256(text.encode()).hexdigest()
        return binary_sha, info


def record(selection, report, ref, target, packages, run_url):
    binary_sha, info = binary_build_info(ref, target)
    labels = report["Metadata"]["ImageConfig"]["config"]["Labels"]
    modules = infer_modules(packages, info)
    source = source_info(labels, info)
    records = []
    for module in modules:
        records.append({
            "schema": "trusted-images.bocklabs.dev/go-file-build-v1",
            "ref": ref,
            "config_digest": report["Metadata"]["ImageID"],
            "upstream_child_digest": selection["published"]["upstream"]["selected_child_digest"],
            "target": target,
            "module": module,
            "layer": target_layer(packages),
            "binary_sha256": binary_sha,
            "source": source,
            "build_info": {
                "program": info["program"],
                "main_module": info["main_module"] or None,
                "module_version": info["module_version"],
                "go_version": info["go_version"],
                "sha256": info["sha256"],
                "go_package_count": info["go_package_count"],
                "versioned_go_package_count": info["versioned_go_package_count"],
                **({"vcs_revision": info["build"][VCS_REVISION]} if info["build"].get(VCS_REVISION) else {}),
            },
            "evidence_run": run_url,
            "limitation": "The scanned package has no version. Coverage is limited to the reviewed binary; vulnerability coverage is not established for the unversioned package.",
        })
    return records


def record_key(item):
    return (
        item["target"],
        item["module"],
        item["source"]["repository"],
        item.get("build_info", {}).get("main_module", ""),
    )


def load_existing(inventory, app):
    existing = {}
    for path in sorted((inventory / app).glob("go-file-build*.json")):
        require(path.is_file() and not path.is_symlink(), f"{path}: unsafe Go file-build evidence")
        value = json.loads(path.read_text())
        require(isinstance(value, dict), f"{path}: invalid Go file-build evidence")
        existing[record_key(value)] = (path, value)
    return existing


def write_one(inventory, app, value, previous, used):
    path = previous[0] if previous else None
    if path is None:
        stem = (
            "go-file-build"
            if "go-file-build.json" not in used
            else "go-file-build-"
            + (re.sub(r"[^a-z0-9]+", "-", value["module"].rsplit("/", 1)[-1].lower()).strip("-") or "module")
        )
        suffix = 1
        name = stem
        while f"{name}.json" in used:
            suffix += 1
            name = f"{stem}-{suffix}"
        path = inventory / app / f"{name}.json"
    used.add(path.name)
    candidate = value
    if previous and "evidence_run" in value:
        candidate = {
            **value,
            "evidence_run": previous[1].get("evidence_run", value["evidence_run"]),
        }
    text = json.dumps(candidate, indent=2) + "\n"
    if path.exists() and path.read_text() == text:
        return False
    path.write_text(json.dumps(value, indent=2) + "\n")
    return True


def write_records(inventory, app, records, existing):
    generated = {record_key(item): item for item in records}
    structural = set(generated) != set(existing)
    changed = structural
    used = {path.name for path, _ in existing.values()}
    for key, value in generated.items():
        changed = write_one(inventory, app, value, existing.get(key), used) or changed
    for key, (path, _) in existing.items():
        if key not in generated:
            path.unlink()
            changed = True
    return changed, structural


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True)
    parser.add_argument("--report", default="published-rescan/trivy-full.json")
    parser.add_argument("--selection", default="published-rescan/selection.json")
    parser.add_argument("--inventory", type=Path, default=INVENTORY)
    parser.add_argument("--run-url", default=os.getenv("GITHUB_RUN_URL", ""))
    args = parser.parse_args()
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", args.app), "invalid inventory app")
    report = json.loads(Path(args.report).read_text())
    selection = json.loads(Path(args.selection).read_text())
    ref = selection["ref"]
    targets = versionless_targets(report)
    existing = load_existing(args.inventory, args.app)
    scanned_targets = {
        result.get("Target") for result in report.get("Results") or []
        if result.get("Class") == "lang-pkgs" and result.get("Type") == "gobinary" and result.get("Packages")
    }
    require({key[0] for key in existing} <= scanned_targets, "scan is missing previously reviewed Go targets")
    if not targets:
        records = []
    else:
        print(run("go", "version").strip(), file=sys.stderr)
        records = [item for target, packages in targets.items() for item in record(selection, report, ref, target, packages, args.run_url)]
    changed, structural = write_records(args.inventory, args.app, records, existing)
    value = {"app": args.app, "changed": changed, "structural_drift": structural, "records": len(records)}
    print(json.dumps(value))
    if os.getenv("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write(f"changed={str(changed).lower()}\nstructural_drift={str(structural).lower()}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
