from compression import zstd
import copy
import gzip
import importlib.util
import io
import json
import lzma
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/native_chisel_inventory.py"
SPEC = importlib.util.spec_from_file_location("native_chisel_inventory", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise ImportError("Cannot load native Chisel inventory validator")
native = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(native)


def fixture(root, source="glibc (2.39-0ubuntu8)", missing=False, created="2025-05-27T12:00:00Z", package_sha="b" * 64):
    release = b'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\n'
    library = b"real fixture content"
    packages = [
        {"kind": "package", "name": "base-files", "version": "13ubuntu10.2", "arch": "amd64", "sha256": "a" * 64},
        {"kind": "package", "name": "libc6", "version": "2.39-0ubuntu8.4", "arch": "amd64", "sha256": package_sha},
    ]
    paths = [("/etc/os-release", "base-files_release", release),
             ("/usr/lib/libc.so", "libc6_libs", library), ("/" + native.WALL, "base-files_release", None)]
    rows = packages[:1] if missing else packages.copy()
    rows.extend({"kind": "slice", "name": name} for name in ("base-files_release", "libc6_libs"))
    for name, owner, content in paths:
        rows.append({"kind": "content", "path": name, "slice": owner})
        row = {"kind": "path", "path": name, "mode": "0644", "slices": [owner]}
        if content is not None:
            row.update(sha256=native.digest(content), size=len(content))
        rows.append(row)
    header = {"jsonwall": "1.0", "schema": "1.0", "count": len(rows) + 1}
    wall = zstd.compress("\n".join(json.dumps(row) for row in [header, *rows]).encode())
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as archive:
        for name, _, content in paths:
            data = wall if content is None else content
            entry = tarfile.TarInfo(name.lstrip("/"))
            entry.size = len(data)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(data))
    compressed = gzip.compress(layer.getvalue())
    diff_ids = ["sha256:" + native.digest(layer.getvalue())]
    config = {"architecture": "amd64", "created": created,
              "rootfs": {"diff_ids": diff_ids}}
    config_path = root / "config.json"
    config_path.write_text(json.dumps(config))
    config_digest = "sha256:" + native.file_digest(config_path)
    manifest = {"config": {"digest": config_digest},
                "layers": [{"digest": "sha256:" + native.digest(compressed), "size": len(compressed)}]}
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest))
    reference = "example.test/native@sha256:" + native.file_digest(manifest_path)
    raw = {"ArtifactType": "container_image", "ArtifactName": reference,
           "Trivy": {"Version": "0.75.0"},
           "Metadata": {"ImageConfig": config, "ImageID": config_digest,
                        "DiffIDs": diff_ids, "OS": {"Family": "ubuntu", "Name": "24.04"}},
           "Results": [{"Class": "os-pkgs", "Type": "ubuntu", "Target": "native (ubuntu 24.04)"},
                       {"Class": "lang-pkgs", "Type": "dotnet-core", "Packages": [{"Name": "runtime"}]}]}
    raw_path = root / "raw.json"
    raw_path.write_text(json.dumps(raw))
    layer_path = root / "layer.tar.gz"
    layer_path.write_bytes(compressed)
    index_text = (f"Package: base-files\nVersion: 13ubuntu10.2\nArchitecture: amd64\nSHA256: {'a' * 64}\n\n"
                  f"Package: libc6\nVersion: 2.39-0ubuntu8.4\nArchitecture: amd64\nSHA256: {'b' * 64}\nSource: {source}\n\n")
    index_bytes = lzma.compress(index_text.encode())
    for suite in ("noble", "noble-updates", "noble-security"):
        hashes = []
        for component in ("main", "universe"):
            (root / f"{suite}-{component}-Packages.xz").write_bytes(index_bytes)
            hashes.append(f" {native.digest(index_bytes)} {len(index_bytes)} {component}/binary-amd64/Packages.xz")
        (root / (suite + "-InRelease")).write_text(
            f"Signed fixture\nOrigin: Ubuntu\nSuite: {suite}\nCodename: noble\nSHA256:\n" + "\n".join(hashes)
            + "\n-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----\n")
    return {"reference": reference, "manifest": str(manifest_path), "config": str(config_path),
            "layers": [str(layer_path)], "raw_report": str(raw_path), "archives": [str(root)]}


def orchestrator():
    spec = importlib.util.spec_from_file_location("native_orchestrator", SCRIPT.with_name("scan_native_chisel.py"))
    if spec is None or spec.loader is None:
        raise ImportError("Cannot load native Chisel orchestrator")
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, {"native_chisel_inventory": native}):
        spec.loader.exec_module(module)
    return module


class NativeChiselInventoryTests(unittest.TestCase):
    def test_ordered_hardlink_chain_keeps_regular_bytes_and_rejects_missing_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "layer.tar"
            with tarfile.open(path, "w") as archive:
                target = tarfile.TarInfo("target")
                target.size = 4
                archive.addfile(target, io.BytesIO(b"data"))
                for name, linked in (("alias", "target"), ("second", "alias")):
                    member = tarfile.TarInfo(name)
                    member.type = tarfile.LNKTYPE
                    member.linkname = linked
                    archive.addfile(member)
            files: dict = {}
            native.overlay_layer(files, path)
            self.assertEqual([native.read_image_file(files, name) for name in ("target", "alias", "second")], [b"data"] * 3)
            member.linkname = "missing"
            with tarfile.open(path) as archive, self.assertRaisesRegex(ValueError, "unresolved OCI hardlink"):
                native.member_bytes(files, archive, member)

    def test_debian_continuations_require_an_existing_field(self):
        for text in (" continuation\n", "Package: example\n\n continuation\n"):
            paragraphs = native.deb_paragraphs(io.StringIO(text))
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "continuation"):
                list(paragraphs)
        self.assertEqual(list(native.deb_paragraphs(io.StringIO("Description: first\n second\n"))),
                         [{"Description": "first\n second"}])

    def test_signed_release_requires_hash_signature_and_exact_index_path(self):
        for old, new, message in (("SHA256:", "SHA512:", "no SHA256"),
                                  ("-----BEGIN PGP SIGNATURE-----", "missing signature", "no signature"),
                                  ("main/binary-amd64/Packages.xz", "foo-main/binary-amd64/Packages.xz", "missing signed index")):
            with tempfile.TemporaryDirectory() as directory:
                fixture(Path(directory))
                release = Path(directory) / "noble-InRelease"
                release.write_text(release.read_text().replace(old, new))
                with self.subTest(message=message), patch.object(native.subprocess, "run"), \
                        self.assertRaisesRegex(ValueError, message):
                    list(native.signed_indexes(directory, "noble", "noble", "amd64"))

    def test_cli_reports_missing_operation_arguments_before_reading_inputs(self):
        for arguments, flag in ((["probe"], "inputs"),
                                (["prepare", "--inputs", "unused"], "output"),
                                (["enrich", "--inputs", "unused", "--sbom", "unused", "--scan", "unused", "--output", "unused"], "capsule"),
                                (["verify"], "capsule")):
            with self.subTest(operation=arguments[0]):
                result = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(f"--{flag} is required", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_prepare_checks_image_inventory_and_signed_source_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = fixture(Path(directory))
            with patch.object(native.subprocess, "run") as gpgv:
                sbom = native.prepare(inputs)
            gpgv.assert_any_call(["gpgv", "--keyring", native.KEYRING,
                                 str(Path(directory) / "noble-InRelease")], check=True, capture_output=True)
            self.assertEqual(gpgv.call_count, 3)
            components = sbom["components"]
            self.assertEqual([(row["name"], row["version"]) for row in components],
                             [("ubuntu", "24.04"), ("base-files", "13ubuntu10.2"), ("libc6", "2.39-0ubuntu8.4")])
            self.assertEqual(components[2]["properties"], [
                {"name": "aquasecurity:trivy:SrcName", "value": "glibc"},
                {"name": "aquasecurity:trivy:SrcVersion", "value": "2.39-0ubuntu8"},
            ])
            self.assertEqual(components[1]["properties"][0]["value"], "base-files")
            self.assertEqual(components[2]["purl"],
                             "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=amd64&distro=ubuntu-24.04")
            self.assertEqual(native.probe(inputs)["codename"], "noble")

    def test_tampered_or_incomplete_inventory_fails_closed(self):
        cases = (("OCI", "OCI manifest digest mismatch"), ("index", "signed package index digest mismatch"),
                 ("source", "invalid signed source identity"), ("missing", "native package/slice inventory mismatch"))
        for case, reason in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = fixture(root, source="not a source" if case == "source" else "glibc", missing=case == "missing")
                if case == "OCI":
                    Path(inputs["manifest"]).write_text("{}")
                if case == "index":
                    (root / "noble-main-Packages.xz").write_bytes(b"tampered")
                with patch.object(native.subprocess, "run"), self.assertRaisesRegex(ValueError, reason):
                    native.prepare(inputs)

    def test_probe_rejects_absent_creation_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = fixture(Path(directory), created=None)
            with self.assertRaisesRegex(ValueError, "no creation timestamp"):
                native.probe(inputs)

    def test_native_package_requires_a_string_sha256(self):
        for sha256 in (None, 123):
            with self.subTest(sha256=sha256), tempfile.TemporaryDirectory() as directory:
                inputs = fixture(Path(directory), package_sha=sha256)
                with self.assertRaisesRegex(ValueError, "invalid native package"):
                    native.probe(inputs)

    def test_archive_fetch_reports_the_failed_snapshot_url(self):
        module = orchestrator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failure = URLError("unavailable")
            with patch.object(module, "urlopen", side_effect=failure), \
                    self.assertRaisesRegex(ValueError, "20250527T120000Z/dists/noble/InRelease") as raised:
                module.fetch_archive(root, "20250527T120000Z", "noble", "amd64")
            self.assertIs(raised.exception.__cause__, failure)

    def test_os_release_requires_codename_and_version(self):
        for content in (b"ID=ubuntu\nVERSION_ID=24.04\n", b"ID=ubuntu\nVERSION_CODENAME=noble\n"):
            files = {"etc/os-release": (tarfile.TarInfo("etc/os-release"), content)}
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, "missing codename or version"):
                native.os_release(files)

    def test_orchestrator_rejects_bad_reference_before_reading_blobs(self):
        module = orchestrator()
        for reference in ("example.test/image:tag", "example.test/image@sha256:../../outside"):
            with self.subTest(reference=reference), self.assertRaisesRegex(ValueError, "not digest-bound"):
                module.image_inputs(Path("missing-oci"), reference, Path("missing-report"), Path("missing-cache"), "unused")

    def test_orchestrator_skips_existing_inventory_without_staging(self):
        module = orchestrator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "raw.json"
            raw = {"Metadata": {"OS": {"Family": "ubuntu"}}, "Results": [
                {"Class": "os-pkgs", "Type": "ubuntu", "Packages": []},
                {"Class": "os-pkgs", "Type": "ubuntu", "Packages": [{"Name": "libc6"}]},
            ]}
            report.write_text(json.dumps(raw))
            evidence = root / "native-before"
            arguments = ["scan_native_chisel.py", "--report", str(report), "--oci", "missing", "--cache", "missing",
                         "--evidence", str(evidence), "--reference", "unused"]
            with patch.object(sys, "argv", arguments), patch("sys.stderr", new_callable=io.StringIO) as diagnostics:
                module.main()
            self.assertFalse(evidence.exists())
            self.assertEqual(json.loads(report.read_text()), raw)
            self.assertIn("existing OS inventory", diagnostics.getvalue())

    def test_orchestrator_missing_required_inputs_preserves_previous_evidence(self):
        module = orchestrator()
        for flag, message in (("fixable", "mandatory fixable"), ("previous", "before archive evidence")):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                inputs = fixture(root)
                evidence = root / "native-before"
                evidence.mkdir()
                saved = evidence / "saved.json"
                saved.write_text("retained evidence")
                arguments = ["scan_native_chisel.py", "--report", inputs["raw_report"], "--oci", "unused",
                             "--cache", "unused", "--evidence", str(evidence), "--reference", inputs["reference"],
                             "--" + flag, str(root / "missing")]
                with self.subTest(flag=flag), patch.object(sys, "argv", arguments), \
                        patch.object(module.shutil, "which", return_value="unused"), \
                        patch.object(module, "image_inputs", return_value=inputs), self.assertRaisesRegex(ValueError, message):
                    module.main()
                self.assertEqual(saved.read_text(), "retained evidence")

    def test_staging_preserves_existing_directories_and_symlink_targets(self):
        module = orchestrator()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = root / "native-before"
            evidence.mkdir()
            saved = evidence / "saved.json"
            saved.write_text("retained evidence")
            alias = root / "native-after"
            alias.symlink_to(evidence, target_is_directory=True)
            for path in (evidence, alias):
                args = type("Arguments", (), {"evidence": path})()
                with self.subTest(path=path), self.assertRaisesRegex(ValueError, "already exists or is a symlink"):
                    module.stage_evidence(args, {}, "unused")
                self.assertEqual(saved.read_text(), "retained evidence")

    def test_manifest_rejects_missing_or_invalid_path_fields(self):
        files = {"file": (tarfile.TarInfo("file"), b"content")}
        for field, value in (("mode", None), ("mode", "invalid"), ("slices", None), ("slices", [1])):
            row: dict[str, object] = {"path": "/file", "mode": "0644", "slices": ["base_files"]}
            if value is None:
                del row[field]
            else:
                row[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "invalid native path"):
                native.verify_manifest_path(files, row)

    def test_signature_provider_failure_propagates(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = fixture(Path(directory))
            failure = subprocess.CalledProcessError(1, ["gpgv"], stderr=b"invalid signature")
            with patch.object(native.subprocess, "run", side_effect=failure), \
                    self.assertRaisesRegex(ValueError, "Ubuntu signature verification failed: invalid signature"):
                native.prepare(inputs)

    def test_enrichment_preserves_container_metadata_and_language_results(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = fixture(Path(directory))
            raw = native.read_json(inputs["raw_report"])
            original = copy.deepcopy(raw)
            supplied = {"Packages": [{"Name": "libc6", "SrcName": "glibc"}],
                        "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-0395", "PkgName": "libc6"}]}
            result = native.fill_os_result(raw, supplied)
        self.assertEqual(raw, original)
        self.assertEqual(result["ArtifactType"], "container_image")
        self.assertEqual(result["Metadata"], original["Metadata"])
        self.assertEqual(result["Results"][1], original["Results"][1])
        self.assertEqual(result["Results"][0]["Target"], "native (ubuntu 24.04)")
        self.assertEqual(result["Results"][0]["Packages"], [{"Name": "libc6", "SrcName": "glibc"}])
        with self.assertRaisesRegex(ValueError, "empty Ubuntu"):
            native.fill_os_result(result, supplied)

    def test_scan_inventory_and_untrusted_binary_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = fixture(root)
            with patch.object(native.subprocess, "run"):
                sbom = native.prepare(inputs)
            packages = [
                {"Name": "base-files", "Version": "13ubuntu10.2", "SrcName": "base-files",
                 "SrcVersion": "13ubuntu10.2", "Digest": "sha256:" + "a" * 64,
                 "Identifier": {"PURL": "pkg:deb/ubuntu/base-files@13ubuntu10.2?arch=amd64&distro=ubuntu-24.04"}},
                {"Name": "libc6", "Version": "2.39-0ubuntu8.4", "SrcName": "glibc",
                 "SrcVersion": "2.39-0ubuntu8", "Digest": "sha256:" + "b" * 64,
                 "Identifier": {"PURL": "pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4?arch=amd64&distro=ubuntu-24.04"}},
            ]
            scan = {"ArtifactType": "cyclonedx", "Trivy": {"Version": "0.75.0"},
                    "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
                    "Results": [{"Class": "os-pkgs", "Type": "ubuntu", "Packages": packages}]}
            self.assertEqual(len(native.scan_packages(sbom, scan)["Packages"]), 2)
            for field in ("SrcName", "Digest", "missing"):
                rows = copy.deepcopy(packages)
                if field == "missing":
                    rows.pop()
                else:
                    rows[1][field] = "tampered"
                invalid = {**scan, "Results": [{"Class": "os-pkgs", "Type": "ubuntu", "Packages": rows}]}
                with self.subTest(field=field), self.assertRaises(ValueError):
                    native.scan_packages(sbom, invalid)
            scanner = root / "untrusted-trivy"
            scanner.write_bytes(b"untrusted executable")
            inputs["trivy"] = str(scanner)
            with patch.object(native.subprocess, "run") as gpgv, \
                    self.assertRaisesRegex(ValueError, "untrusted native scanner binary"):
                native.enrich(inputs, sbom, scan, root / "sbom.json")
            self.assertTrue(all(call.args[0][0] == "gpgv" for call in gpgv.call_args_list))

    def test_capsule_rejects_parent_paths_before_opening_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            capsule = Path(directory) / "capsule.json"
            capsule.write_text(json.dumps({"schema": "native-chisel-capsule-v1",
                                           "inputs": {"manifest": "../outside.json"}}))
            with self.assertRaisesRegex(ValueError, "unsafe native capsule paths"):
                native.verify_capsule(capsule)

    def test_capsule_rejects_missing_members_before_opening_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capsule = root / "capsule.json"
            inputs: dict[str, object] = {key: key + ".json" for key in ("manifest", "config", "raw_report", "db", "trivy")}
            inputs.update(layers=[], archives=[], capsule=f"{root.name}/capsule.json")
            capsule.write_text(json.dumps({"schema": "native-chisel-capsule-v1", "inputs": inputs,
                                           "scan": "scan.json", "output": "report.json"}))
            with self.assertRaisesRegex(ValueError, "unsafe native capsule paths"):
                native.verify_capsule(capsule)

    def test_opaque_upper_layer_removes_lower_files(self):
        files = {"obsolete": (tarfile.TarInfo("obsolete"), b"lower layer")}
        with tempfile.TemporaryDirectory() as directory:
            upper = Path(directory) / "upper.tar"
            with tarfile.open(upper, "w") as archive:
                archive.addfile(tarfile.TarInfo(".wh..wh..opq"), io.BytesIO())
                entry = tarfile.TarInfo("replacement")
                entry.size = 5
                archive.addfile(entry, io.BytesIO(b"upper"))
            native.overlay_layer(files, upper)
        self.assertEqual(set(files), {"replacement"})
        self.assertEqual(files["replacement"][1], b"upper")
