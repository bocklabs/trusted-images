"""Bind native Chisel inventory to OCI bytes and signed Ubuntu package indexes."""

import argparse
import copy
from compression import zstd
import hashlib
import json
import lzma
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import tarfile
from urllib.parse import quote, unquote


KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
WALL = "var/lib/chisel/manifest.wall"
TRIVY_VERSION = "0.75.0"
SHA256_PREFIX = "sha256:"
UNSAFE_CAPSULE_PATH = "unsafe native capsule paths"
TRIVY_SHA256 = "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def normalized(path):
    require(isinstance(path, str) and ".." not in PurePosixPath(path).parts,
            "unsafe OCI path")
    return str(PurePosixPath(path.lstrip("/"))).rstrip("/")


def apply_whiteouts(files, members):
    for member in members:
        name = normalized(member.name)
        parent, _, base = name.rpartition("/")
        if not base.startswith(".wh."):
            continue
        target = parent if base == ".wh..wh..opq" else normalized(f"{parent}/{base[4:]}")
        for old in tuple(files):
            if not target or old.startswith(target + "/") or (old == target and base != ".wh..wh..opq"):
                del files[old]


def member_bytes(files, archive, member):
    require(member.isfile() or member.isdir() or member.issym() or member.islnk(),
            "unsupported OCI file type")
    if member.islnk():
        target = normalized(member.linkname)
        require(target in files and files[target][0].isfile(), "unresolved OCI hardlink")
        return files[target][1]
    stream = archive.extractfile(member) if member.isfile() else None
    return stream.read() if stream else b""


def overlay_layer(files, path):
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        apply_whiteouts(files, members)
        for member in members:
            name = normalized(member.name)
            if PurePosixPath(name).name.startswith(".wh."):
                continue
            if not member.isdir():
                for old in [path for path in files if path.startswith(name + "/")]:
                    del files[old]
            files[name] = (member, member_bytes(files, archive, member))


def image_files(inputs, raw):
    manifest = read_json(inputs["manifest"])
    config = read_json(inputs["config"])
    reference = inputs["reference"]
    require(re.fullmatch(r".+@sha256:[0-9a-f]{64}", reference), "native reference is not digest-bound")
    expected_manifest = reference.rsplit("@", 1)[-1]
    require(expected_manifest == SHA256_PREFIX + file_digest(inputs["manifest"]),
            "OCI manifest digest mismatch")
    require(manifest["config"]["digest"] == SHA256_PREFIX + file_digest(inputs["config"]),
            "OCI config digest mismatch")
    metadata = raw.get("Metadata", {})
    require(raw.get("ArtifactType") == "container_image"
            and isinstance(raw.get("ArtifactName"), str) and raw["ArtifactName"],
            "raw report is not a named container image")
    require(metadata.get("ImageID") == manifest["config"]["digest"]
            and metadata.get("ImageConfig") == config, "raw report config mismatch")
    require(metadata.get("DiffIDs") == config["rootfs"]["diff_ids"], "raw report layers mismatch")
    require(len(inputs["layers"]) == len(manifest["layers"]) == len(metadata["DiffIDs"]),
            "incomplete OCI layers")
    files: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
    for path, descriptor, diff_id in zip(inputs["layers"], manifest["layers"], metadata["DiffIDs"], strict=True):
        require(file_digest(path) == descriptor["digest"].removeprefix(SHA256_PREFIX)
                and Path(path).stat().st_size == descriptor["size"], "OCI layer digest mismatch")
        with tarfile.open(path, "r:*") as archive:
            archive.fileobj.seek(0)
            checksum = hashlib.sha256()
            while block := archive.fileobj.read(1024 * 1024):
                checksum.update(block)
            require(checksum.hexdigest() == diff_id.removeprefix(SHA256_PREFIX), "OCI uncompressed layer mismatch")
        overlay_layer(files, path)
    return files


def read_image_file(files, name):
    for _ in range(40):
        require(name in files, f"missing OCI path: {name}")
        member, data = files[name]
        if not member.issym():
            return data
        target = member.linkname if member.linkname.startswith("/") else str(PurePosixPath(name).parent / member.linkname)
        name = normalized(posixpath.normpath("/" + target.lstrip("/")))
    raise ValueError("OCI symlink loop")


def native_packages(files):
    rows = [json.loads(line) for line in zstd.decompress(read_image_file(files, WALL)).splitlines()]
    require(rows and rows[0].get("jsonwall") == "1.0" and rows[0].get("schema") == "1.0"
            and rows[0].get("count") == len(rows), "invalid native manifest header")
    require(all(row.get("kind") in {"content", "package", "path", "slice"} for row in rows[1:]),
            "unknown native manifest record")
    paths = [row for row in rows if row.get("kind") == "path"]
    for row in paths:
        verify_manifest_path(files, row)
    require(paths and len({row["path"] for row in paths}) == len(paths), "duplicate native paths")
    packages = [row for row in rows if row.get("kind") == "package"]
    for row in packages:
        require(all(isinstance(row.get(key), str) and row[key] for key in ("name", "version", "arch"))
                and re.fullmatch("[0-9a-f]{64}", row.get("sha256", "")), "invalid native package")
    require(packages and len({row["name"] for row in packages}) == len(packages),
            "empty or duplicate native packages")
    verify_manifest_links(rows, paths, packages)
    return packages


def verify_manifest_path(files, row):
    name = normalized(row.get("path"))
    require(isinstance(row.get("mode"), str) and re.fullmatch(r"[0-7]{3,4}", row["mode"]),
            "invalid native path mode")
    require(isinstance(row.get("slices"), list) and all(isinstance(name, str) for name in row["slices"]),
            "invalid native path slices")
    require(name in files, "missing native manifest path")
    member, data = files[name]
    require(member.mode & 0o7777 == int(row["mode"], 8), "native path mode mismatch")
    if "link" in row:
        require(member.issym() and member.linkname == row["link"], "native symlink mismatch")
    elif row["path"].endswith("/"):
        require(member.isdir(), "native directory mismatch")
    else:
        require(member.isfile() or member.islnk(), "native file type mismatch")
        expected = row.get("final_sha256", row.get("sha256"))
        require((expected and digest(data) == expected) or (name == WALL and not expected),
                "native file digest mismatch")
        require("size" not in row or len(data) == row["size"], "native file size mismatch")


def verify_manifest_links(rows, paths, packages):
    slice_rows = [row for row in rows if row.get("kind") == "slice"]
    content_rows = [row for row in rows if row.get("kind") == "content"]
    require(all(isinstance(row.get("name"), str) and row["name"] for row in slice_rows),
            "invalid native slice record")
    require(all(isinstance(row.get("path"), str) and isinstance(row.get("slice"), str) for row in content_rows),
            "invalid native content record")
    slices = [row["name"] for row in slice_rows]
    names = {row["name"] for row in packages}
    require(slices and len(slices) == len(set(slices))
            and {name.split("_", 1)[0] for name in slices} == names,
            "native package/slice inventory mismatch")
    content = {(row["path"], row["slice"]) for row in content_rows}
    edges = {(row["path"], name) for row in paths for name in row["slices"]}
    require(content == edges and all(name in slices for _, name in edges),
            "native path/slice inventory mismatch")


def deb_paragraphs(stream):
    fields: dict[str, str] = {}
    last = ""
    for line in stream:
        if not line.strip():
            if fields:
                yield fields
                fields = {}
            continue
        if line.startswith(" "):
            require(fields and last, "invalid signed Debian package continuation")
            fields[last] += "\n" + line.rstrip()
        else:
            last, separator, value = line.rstrip().partition(":")
            require(separator, "invalid signed Debian package paragraph")
            fields[last] = value.lstrip()
    if fields:
        yield fields


def signed_indexes(directory, suite, codename, architecture):
    release = Path(directory) / (suite + "-InRelease")
    try:
        subprocess.run(["gpgv", "--keyring", KEYRING, str(release)], check=True, capture_output=True)
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or b"").decode(errors="replace").strip()
        raise ValueError(f"Ubuntu signature verification failed: {detail}") from error
    text = release.read_text()
    require(f"\nCodename: {codename}\n" in text and "\nOrigin: Ubuntu\n" in text
            and f"\nSuite: {suite}\n" in text, "signed release distro mismatch")
    section = text.split("\nSHA256:\n", 1)
    require(len(section) == 2, "signed release has no SHA256 section")
    signature = section[1].split("\n-----BEGIN PGP SIGNATURE-----", 1)
    require(len(signature) == 2, "signed release has no signature section")
    hashes = signature[0]
    for component in ("main", "universe"):
        relative = f"{component}/binary-{architecture}/Packages.xz"
        rows = (line.split() for line in hashes.splitlines())
        entries = [row for row in rows if len(row) == 3 and row[2] == relative]
        require(len(entries) == 1, "missing signed index hash")
        expected, size, _ = entries[0]
        index = Path(directory) / f"{suite}-{component}-Packages.xz"
        require(file_digest(index) == expected and index.stat().st_size == int(size),
                "signed package index digest mismatch")
        yield index


def match_packages(index, wanted, matches):
    with lzma.open(index, "rt") as stream:
        for row in deb_paragraphs(stream):
            identity = tuple(row.get(key) for key in ("Package", "Version", "Architecture", "SHA256"))
            if identity not in wanted:
                continue
            require(identity not in matches or matches[identity].get("Source") == row.get("Source"),
                    "conflicting signed package source")
            matches[identity] = row


def signed_packages(inputs, packages, codename):
    wanted = {(row["name"], row["version"], row["arch"], row["sha256"]) for row in packages}
    matches: dict[tuple[str, ...], dict[str, str]] = {}
    architecture = read_json(inputs["config"])["architecture"]
    for directory in inputs["archives"]:
        for suite in (codename, codename + "-updates", codename + "-security"):
            for index in signed_indexes(directory, suite, codename, architecture):
                match_packages(index, wanted, matches)
    require(set(matches) == wanted, "incomplete exact signed package inventory")
    return matches


def package_component(package, metadata, distro):
    source = metadata.get("Source", package["name"])
    match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()]+)\))?", source)
    if match is None:
        raise ValueError("invalid signed source identity")
    source_name, source_version = match.groups()
    purl = (f"pkg:deb/ubuntu/{quote(package['name'], safe='')}@{quote(package['version'], safe='')}"
            f"?arch={quote(package['arch'], safe='')}&distro=ubuntu-{distro}")
    return {"type": "library", "name": package["name"], "version": package["version"],
            "purl": purl, "bom-ref": purl,
            "hashes": [{"alg": "SHA-256", "content": package["sha256"]}],
            "properties": [{"name": "aquasecurity:trivy:SrcName", "value": source_name},
                           {"name": "aquasecurity:trivy:SrcVersion", "value": source_version or package["version"]}]}


def os_release(files):
    release = {key: value for line in read_image_file(files, "etc/os-release").decode().splitlines()
               if "=" in line for key, value in [line.split("=", 1)]}
    release = {key: value.strip('"') for key, value in release.items()}
    require(release.get("VERSION_CODENAME") and release.get("VERSION_ID"), "native OS release is missing codename or version")
    return release


def probe(inputs):
    raw = read_json(inputs["raw_report"])
    files = image_files(inputs, raw)
    if WALL not in files:
        return {"native": False}
    native_packages(files)
    release = os_release(files)
    require(release.get("ID") == "ubuntu", "native OS is not Ubuntu")
    config = raw["Metadata"]["ImageConfig"]
    return {"native": True, "codename": release["VERSION_CODENAME"], "version": release["VERSION_ID"],
            "created": config["created"], "architecture": config["architecture"]}


def prepare(inputs):
    raw = read_json(inputs["raw_report"])
    files = image_files(inputs, raw)
    require(WALL in files, "image has no native Chisel manifest")
    packages = native_packages(files)
    release = os_release(files)
    distro = release["VERSION_ID"]
    require(release.get("ID") == "ubuntu" and raw["Metadata"].get("OS") == {"Family": "ubuntu", "Name": distro},
            "native OS identity mismatch")
    metadata = signed_packages(inputs, packages, release["VERSION_CODENAME"])
    components = [{"type": "operating-system", "name": "ubuntu", "version": distro,
                   "bom-ref": "ubuntu-" + distro}]
    for package in packages:
        identity = tuple(package[key] for key in ("name", "version", "arch", "sha256"))
        components.append(package_component(package, metadata[identity], distro))
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "container", "name": inputs["reference"].split("@", 1)[0],
                                       "version": SHA256_PREFIX + file_digest(inputs["manifest"])}},
            "components": components}


def scan_packages(sbom, scan):
    results = scan.get("Results", [])
    require(scan.get("ArtifactType") == "cyclonedx" and len(results) == 1
            and results[0].get("Class") == "os-pkgs" and results[0].get("Type") == "ubuntu",
            "invalid native SBOM scan")
    packages = results[0].get("Packages", [])
    components = [row for row in sbom["components"] if row["type"] == "library"]
    require(len(packages) == len(components), "incomplete scanned native inventory")
    by_purl = {unquote(row["Identifier"]["PURL"]): row for row in packages}
    require(len(by_purl) == len(components), "duplicate scanned package identities")
    for component in components:
        row = by_purl.get(unquote(component["purl"]), {})
        properties = {item["name"]: item["value"] for item in component["properties"]}
        require((row.get("Name"), row.get("Version"), row.get("SrcName"), row.get("SrcVersion"), row.get("Digest"))
                == (component["name"], component["version"], properties["aquasecurity:trivy:SrcName"],
                    properties["aquasecurity:trivy:SrcVersion"], SHA256_PREFIX + component["hashes"][0]["content"]),
                "scanned native source/package mismatch")
    return results[0]


def enrich(inputs, sbom, scan, sbom_path):
    require(sbom == prepare(inputs), "native SBOM differs from signed image inventory")
    raw = read_json(inputs["raw_report"])
    require(scan.get("Trivy") == raw.get("Trivy"), "native scanner version mismatch")
    require(scan.get("Metadata", {}).get("OS") == raw["Metadata"]["OS"], "native scan OS mismatch")
    supplied = scan_packages(sbom, scan)
    require(scan.get("Trivy", {}).get("Version") == TRIVY_VERSION
            and file_digest(inputs["trivy"]) == TRIVY_SHA256, "untrusted native scanner binary")
    scanner = Path(inputs["trivy"])
    scanner.chmod(scanner.stat().st_mode | 0o100)
    db_before = file_digest(inputs["db"])
    scanned = subprocess.run([inputs["trivy"], "sbom", "--offline-scan", "--skip-db-update",
                              "--cache-dir", str(Path(inputs["db"]).parent.parent), "--format", "json",
                              "--list-all-pkgs", Path(sbom_path).name],
                             cwd=Path(sbom_path).resolve().parent, capture_output=True, check=True)
    replay = json.loads(scanned.stdout)
    require(file_digest(inputs["db"]) == db_before, "native scan changed frozen DB")
    require(replay.get("Trivy") == scan.get("Trivy") and replay.get("Metadata") == scan.get("Metadata")
            and scan_packages(sbom, replay).get("Packages") == supplied.get("Packages")
            and replay["Results"][0].get("Vulnerabilities", []) == supplied.get("Vulnerabilities", []),
            "native scan does not match frozen DB replay")
    result = fill_os_result(raw, supplied)
    capsule = inputs.get("capsule")
    require(isinstance(capsule, str) and not Path(capsule).is_absolute()
            and ".." not in Path(capsule).parts, "native capsule marker is required")
    result["NativeChisel"] = {"schema": "native-chisel-v1", "capsule": capsule}
    return result


def fill_os_result(raw, supplied):
    result = copy.deepcopy(raw)
    os_rows = [row for row in result.get("Results", []) if row.get("Class") == "os-pkgs"]
    require(len(os_rows) == 1 and os_rows[0].get("Type") == "ubuntu"
            and not os_rows[0].get("Packages") and not os_rows[0].get("Vulnerabilities"),
            "native enrichment requires exactly one empty Ubuntu OS result")
    os_rows[0]["Packages"] = supplied["Packages"]
    os_rows[0]["Vulnerabilities"] = supplied.get("Vulnerabilities", [])
    return result


def input_hashes(inputs, extra):
    paths = [inputs[key] for key in ("manifest", "config", "raw_report", "db", "trivy")]
    paths.extend(inputs["layers"])
    for directory in inputs["archives"]:
        paths.extend(str(path) for path in sorted(Path(directory).glob("*-InRelease")))
        paths.extend(str(path) for path in sorted(Path(directory).glob("*-Packages.xz")))
    return {str(path): file_digest(path) for path in paths + extra}


def resolve_inputs(inputs, root):
    result = inputs.copy()
    for key in ("manifest", "config", "raw_report", "db", "trivy"):
        if key in inputs:
            result[key] = str((root / inputs[key]).resolve())
    for key in ("layers", "archives"):
        result[key] = [str((root / path).resolve()) for path in inputs.get(key, [])]
    return result


def portable_inputs(inputs, root):
    result = inputs.copy()
    for key in ("manifest", "config", "raw_report", "db", "trivy"):
        result[key] = str(Path(inputs[key]).resolve().relative_to(root))
    for key in ("layers", "archives"):
        result[key] = [str(Path(path).resolve().relative_to(root)) for path in inputs[key]]
    return result


def portable_hashes(inputs, extra, root):
    return {str(Path(path).resolve().relative_to(root)): value
            for path, value in input_hashes(inputs, extra).items()}


def safe_relative(root, value):
    require(isinstance(value, str) and value and not Path(value).is_absolute()
            and ".." not in Path(value).parts, UNSAFE_CAPSULE_PATH)
    path = (root / value).resolve()
    require(path.is_relative_to(root), UNSAFE_CAPSULE_PATH)
    return str(path)


def verify_capsule(path):
    path = Path(path).resolve()
    root = path.parent
    capsule = read_json(path)
    require(capsule.get("schema") == "native-chisel-capsule-v1", "unknown native capsule schema")
    for key in ("manifest", "config", "raw_report", "db", "trivy"):
        safe_relative(root, capsule["inputs"][key])
    for key in ("layers", "archives"):
        for value in capsule["inputs"][key]:
            safe_relative(root, value)
    inputs = resolve_inputs(capsule["inputs"], root)
    require(portable_inputs(inputs, root) == capsule["inputs"], UNSAFE_CAPSULE_PATH)
    require(inputs["capsule"] == f"{root.name}/{path.name}", "native capsule marker mismatch")
    extra = [safe_relative(root, capsule[key]) for key in ("sbom", "scan", "output")]
    require(portable_hashes(inputs, extra, root) == capsule["hashes"], "native capsule input digest mismatch")
    sbom, scan, output = extra
    expected = enrich(inputs, read_json(sbom), read_json(scan), sbom)
    require(read_json(output) == expected, "native capsule report mismatch")
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("probe", "prepare", "enrich", "verify"))
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--sbom", type=Path)
    parser.add_argument("--scan", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--capsule", type=Path)
    args = parser.parse_args()
    required = {"probe": ("inputs",), "prepare": ("inputs", "output"),
                "enrich": ("inputs", "sbom", "scan", "output", "capsule"),
                "verify": ("capsule",)}[args.operation]
    missing = [name for name in required if getattr(args, name) is None]
    if missing:
        parser.error(f"--{missing[0]} is required for {args.operation}")
    if args.operation == "verify":
        verify_capsule(args.capsule)
        return
    inputs = resolve_inputs(read_json(args.inputs), args.inputs.resolve().parent)
    if args.operation == "probe":
        print(json.dumps(probe(inputs)))
        return
    if args.operation == "prepare":
        result = prepare(inputs)
    else:
        inputs["capsule"] = f"{args.capsule.resolve().parent.name}/{args.capsule.name}"
        result = enrich(inputs, read_json(args.sbom), read_json(args.scan), args.sbom)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    if args.operation == "enrich":
        root = args.capsule.resolve().parent
        capsule = {"schema": "native-chisel-capsule-v1", "inputs": portable_inputs(inputs, root)}
        capsule.update({key: str(value.resolve().relative_to(root))
                        for key, value in (("sbom", args.sbom), ("scan", args.scan), ("output", args.output))})
        capsule["hashes"] = portable_hashes(inputs, [str(args.sbom), str(args.scan), str(args.output)], root)
        args.capsule.write_text(json.dumps(capsule, indent=2) + "\n")


if __name__ == "__main__":
    main()
