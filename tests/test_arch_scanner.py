"""Arch admission keeps independent scanner evidence mandatory."""

import sys
import copy
import json
import tempfile
import shlex
import subprocess
import base64
import gzip
import hashlib
import io
import tarfile
import os
from types import SimpleNamespace
from unittest.mock import patch
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import evaluate_promotion as policy
import scan_arch as arch


def arch_image_fixture(root):
    oci = root / "oci"
    blobs = oci / "blobs/sha256"
    blobs.mkdir(parents=True)
    version = "1:2.15.4-1"
    package_path = f"/var/lib/pacman/local/libxml2-{version}/desc"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for name, text in (("etc/os-release", "ID=arch\nVERSION_ID=20261009\n"),
                           (package_path[1:], f"%NAME%\nlibxml2\n\n%VERSION%\n{version}\n\n%ARCH%\nx86_64\n")):
            data = text.encode()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
    layer = gzip.compress(buffer.getvalue())
    config: dict = {"os": "linux", "architecture": "amd64", "rootfs": {"diff_ids": ["sha256:" + hashlib.sha256(buffer.getvalue()).hexdigest()]}}
    config_bytes = json.dumps(config).encode()
    config_hash = hashlib.sha256(config_bytes).hexdigest()
    layer_hash = hashlib.sha256(layer).hexdigest()
    manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"digest": "sha256:" + config_hash, "size": len(config_bytes)},
                "layers": [{"digest": "sha256:" + layer_hash, "size": len(layer)}]}
    manifest_bytes = json.dumps(manifest).encode()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    for name, data in ((config_hash, config_bytes), (layer_hash, layer), (manifest_hash, manifest_bytes)):
        (blobs / name).write_bytes(data)
    arch.write_json(oci / "index.json", {"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_hash, "size": len(manifest_bytes)}]})
    reference = "example.test/arch@sha256:" + manifest_hash
    raw = {"SchemaVersion": 2, "ArtifactType": "container_image", "ArtifactName": reference,
           "Trivy": {"Version": "0.75.0"}, "Metadata": {"ImageConfig": config, "ImageID": "sha256:" + config_hash,
           "DiffIDs": config["rootfs"]["diff_ids"]}, "Results": [{"Class": "lang-pkgs", "Type": "python-pkg", "Target": "app",
           "Packages": [{"Name": "language", "Version": "1"}], "Vulnerabilities": []}]}
    package = {"id": "xml", "name": "libxml2", "version": version, "type": "alpm", "foundBy": "alpm-db-cataloger",
               "metadata": {"package": "libxml2", "version": version, "architecture": "x86_64"},
               "locations": [{"path": package_path, "annotations": {"evidence": "primary"}}],
               "purl": "pkg:alpm/arch/libxml2@1%3A2.15.4-1?arch=x86_64"}
    sbom = {"schema": {"version": "16.1.11"}, "distro": {"id": "arch", "versionID": "20261009"},
            "source": {"metadata": {"manifestDigest": "sha256:" + manifest_hash, "imageID": "sha256:" + config_hash,
            "config": base64.b64encode(config_bytes).decode(), "manifest": base64.b64encode(manifest_bytes).decode()}},
            "artifacts": [package]}
    match = {"artifact": {key: package[key] for key in ("id", "name", "version", "purl", "type")},
             "vulnerability": {"id": "AVG-2898", "severity": "High", "namespace": "arch:distro:archlinux:rolling",
             "dataSource": "https://security.archlinux.org/AVG-2898", "fix": {"state": "not-fixed", "versions": []}},
             "relatedVulnerabilities": [{"id": "CVE-2025-49794"}]}
    scan = {"descriptor": {"name": "grype", "version": "0.120.0"}, "matches": [match]}
    return oci, reference, raw, sbom, scan


class ArchScannerTests(unittest.TestCase):
    def test_untrusted_executable_never_runs_and_trusted_backend_gets_isolated_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tools").mkdir()
            (root / "tools/syft").write_text("untrusted input")
            with patch.object(arch.subprocess, "run") as execute, self.assertRaisesRegex(ValueError, "untrusted"):
                arch.run_tool(root, "syft", ["version", "-o", "json"])
            execute.assert_not_called()

            def backend(command, **options):
                config = arch.read_json(Path(command[command.index("--config") + 1]))
                self.assertEqual(config, {"check-for-app-update": False, "scope": "squashed"})
                self.assertEqual(options["cwd"], root)
                self.assertEqual(options["timeout"], 600)
                self.assertNotIn("SYFT_SCOPE", options["env"])
                self.assertNotIn("SYFT_CONFIG", options["env"])
                self.assertTrue(Path(options["env"]["HOME"]).is_relative_to(root))
                self.assertEqual(options["env"]["HOME"], options["env"]["XDG_CONFIG_HOME"])
                return SimpleNamespace(stdout=b"scanner stdout")

            with patch.object(arch.native, "file_digest", return_value=arch.PINS["syft"][2]), \
                    patch.object(arch.subprocess, "run", side_effect=backend), \
                    patch.dict(os.environ, SYFT_SCOPE="all-layers", SYFT_CONFIG="ambient-config"):
                self.assertEqual(arch.run_tool(root, "syft", ["version", "-o", "json"]), b"scanner stdout")
            self.assertFalse(list(root.glob(".runtime-*")))

    def test_native_database_freshness_and_recorded_source_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "db/6").mkdir(parents=True)
            source = "https://grype.anchore.io/databases/v6/native.tar.zst?checksum=sha256%3A" + "a" * 64
            imported = {"source": source, "client_version": "v6.1.10"}
            arch.write_json(root / "db/6/import.json", imported)
            status = {"valid": True, "schemaVersion": "v6.1.10", "from": source, "built": "2026-10-08T00:00:00Z"}
            arch.validate_database(root, status, "2026-10-08T01:00:00Z")
            for recorded_time in ("2026-10-07T00:00:00Z", "2026-10-14T00:00:00Z"):
                with self.subTest(recorded_time=recorded_time), self.assertRaisesRegex(ValueError, "stale or future"):
                    arch.validate_database(root, status, recorded_time)
            imported["source"] = source.replace("grype.anchore.io", "untrusted.test")
            arch.write_json(root / "db/6/import.json", imported)
            with self.assertRaisesRegex(ValueError, "database source"):
                arch.validate_database(root, status, "2026-10-08T01:00:00Z")

    def test_replay_ignores_presentation_paths_but_compares_packages_findings_and_db(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, _, sbom, scan = arch_image_fixture(Path(temporary))
            sbom["source"]["name"] = "/original/oci"
            sbom["source"]["metadata"]["userInput"] = "/original/oci"
            sbom["descriptor"] = {"configuration": {"packages": {"java-archive": {"maven-localrepository-dir": "/original/cache"},
                                   "golang": {"local-mod-cache-dir": "/original/modules"}}}}
            relocated = copy.deepcopy(sbom)
            relocated["source"]["name"] = relocated["source"]["metadata"]["userInput"] = "/relocated/oci"
            relocated["descriptor"]["configuration"]["packages"]["java-archive"]["maven-localrepository-dir"] = "/relocated/cache"
            relocated["descriptor"]["configuration"]["packages"]["golang"]["local-mod-cache-dir"] = "/relocated/modules"
            self.assertEqual(arch.semantic(sbom), arch.semantic(relocated))
            relocated["artifacts"][0]["version"] = "1:2.16.0-1"
            self.assertNotEqual(arch.semantic(sbom), arch.semantic(relocated))
            scan["source"] = {"type": "image", "target": {"userInput": "/original/oci"}}
            scan["descriptor"].update(timestamp="original-time", configuration={"db": {"validate-age": True}},
                                      db={"status": {"path": "/original/db", "built": "2026-10-08T00:00:00Z"}})
            replay = copy.deepcopy(scan)
            replay["source"]["target"]["userInput"] = "/relocated/oci"
            replay["descriptor"]["timestamp"] = "replay-time"
            replay["descriptor"]["configuration"]["db"]["validate-age"] = False
            replay["descriptor"]["db"]["status"]["path"] = "/relocated/db"
            self.assertEqual(arch.semantic(scan), arch.semantic(replay))
            replay["matches"][0]["vulnerability"]["id"] = "AVG-9999"
            self.assertNotEqual(arch.semantic(scan), arch.semantic(replay))
            replay["matches"] = copy.deepcopy(scan["matches"])
            replay["descriptor"]["db"]["status"]["built"] = "2026-10-09T00:00:00Z"
            self.assertNotEqual(arch.semantic(scan), arch.semantic(replay))

    def test_hash_checked_oci_exact_syft_inventory_and_language_preservation(self):
        with tempfile.TemporaryDirectory() as temporary:
            oci, reference, raw, sbom, scan = arch_image_fixture(Path(temporary))
            native = arch.inventory(oci, reference, raw)
            self.assertEqual(native["packages"], [{"name": "libxml2", "version": "1:2.15.4-1", "arch": "x86_64",
                            "path": "/var/lib/pacman/local/libxml2-1:2.15.4-1/desc"}])
            full = arch.supplement(raw, native, sbom, scan, reference, "arch-before/capsule.json")
            self.assertEqual(full["Results"][:-1], raw["Results"])
            os_row = full["Results"][-1]
            self.assertEqual(os_row["Packages"][0]["Identifier"]["PURL"], sbom["artifacts"][0]["purl"])
            self.assertEqual({v["VulnerabilityID"] for v in os_row["Vulnerabilities"]}, {"AVG-2898", "CVE-2025-49794"})
            fixed = arch.supplement(raw, native, sbom, scan, reference, "arch-before/capsule.json", fixable=True)
            self.assertEqual(fixed["Results"][-1]["Vulnerabilities"], [])
            policy.validate_arch_fixable(full, fixed)
            sbom["artifacts"][0]["metadata"]["architecture"] = "any"
            with self.assertRaisesRegex(ValueError, "PURL"):
                arch.supplement(raw, native, sbom, scan, reference, "arch-before/capsule.json")
            manifest = arch.read_json(oci / "blobs/sha256" / reference.rsplit(":", 1)[1])
            layer = oci / "blobs/sha256" / manifest["layers"][0]["digest"][7:]
            layer.write_bytes(layer.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValueError, "descriptor digest or size"):
                arch.inventory(oci, reference, raw)

    def test_known_non_arch_skips_oci_but_unknown_and_arch_still_probe(self):
        args = SimpleNamespace(report=Path("report.json"), oci=Path("oci"), reference="image@digest")
        workflow = policy.yaml.safe_load((Path(__file__).resolve().parents[1] / ".github/workflows/promote.yaml").read_text())
        step = next(s for j in workflow["jobs"].values() for s in j.get("steps", [])
                    if s.get("name") == "Inventory native Chisel published packages")
        predicate = shlex.split(next(line for line in step["run"].splitlines() if "if jq -e --argjson known" in line))[6]
        for family in ("debian", "ubuntu", "alpine", "sles", None, "archlinux", "unsupported"):
            raw: dict = {"Metadata": {"OS": None if family is None else {"Family": family}}}
            with self.subTest(family=family), patch.object(arch, "read_json", return_value=raw), \
                    patch.object(arch, "inventory", return_value=None) as inventory:
                arch.scan_image(args)
                self.assertEqual(inventory.called, family in (None, "archlinux", "unsupported"))
            raw["Results"] = [{"Class": "os-pkgs", "Packages": [{"Name": "existing"}]}]
            result = subprocess.run(["jq", "-e", "--argjson", "known", json.dumps(list(policy.VERSION_CLASSES)), predicate],
                                    input=json.dumps(raw), capture_output=True, text=True)
            self.assertEqual(result.returncode == 0, family in (None, "archlinux", "unsupported"), result.stderr)
            if family == "ubuntu":
                raw["Results"] = []
                result = subprocess.run(["jq", "-e", "--argjson", "known", json.dumps(list(policy.VERSION_CLASSES)), predicate],
                                        input=json.dumps(raw), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
        for raw in ({"Metadata": {}}, {"Metadata": {"OS": {}}}):
            with patch.object(arch, "read_json", return_value=raw), patch.object(arch, "inventory", return_value=None) as inventory:
                arch.scan_image(args)
                inventory.assert_called_once()
        with patch.object(arch, "read_json", return_value={"Metadata": {"OS": {"Family": []}}}), \
                patch.object(arch, "inventory") as inventory:
            with self.assertRaisesRegex(ValueError, "OS family"):
                arch.scan_image(args)
            inventory.assert_not_called()

    def test_arch_rows_require_independent_evidence(self):
        report = {"SchemaVersion": 2, "Results": [{"Class": "os-pkgs", "Type": "archlinux", "Packages": []}]}
        with self.assertRaisesRegex(ValueError, "Arch.*evidence"):
            policy.validate_native_inventory(report, Path("report.json"))

    def test_all_advisory_aliases_and_genuine_fix_state(self):
        package = {"id": "xml", "name": "libxml2", "version": "1:2.15.4-1", "type": "alpm",
                   "purl": "pkg:alpm/arch/libxml2@1%3A2.15.4-1?arch=x86_64"}
        aliases = ["CVE-2025-6170", "CVE-2025-49796", "CVE-2025-49795", "CVE-2025-49794"]
        match: dict = {"artifact": package, "vulnerability": {"id": "AVG-2898", "severity": "High",
                 "namespace": "arch:distro:archlinux:rolling", "dataSource": "https://security.archlinux.org/AVG-2898",
                 "fix": {"state": "not-fixed", "versions": []}},
                 "relatedVulnerabilities": [{"id": value} for value in aliases]}
        rows = arch.finding_rows(match, {"xml": package})
        self.assertEqual({row["VulnerabilityID"] for row in rows}, {"AVG-2898", *aliases})
        self.assertTrue(all(row["PkgIdentifier"]["PURL"] == package["purl"] and not row["FixedVersion"] for row in rows))
        report = {"SchemaVersion": 2, "Results": [{"Target": "Arch", "Class": "os-pkgs", "Type": "archlinux", "Vulnerabilities": rows}]}
        self.assertIn("linux/amd64|libxml2|CVE-2025-49794", policy.findings(report, "alias report"))
        findings = policy.findings(report, "alias report")
        alias_key = "linux/amd64|libxml2|CVE-2025-49794"
        self.assertEqual(policy.finding_delta(set(), set(findings), set())["introduced"], sorted(findings))
        self.assertEqual(policy.unresolved_requested({"findings": [{"class": "os-pkgs", "type": "archlinux",
                         "id": "CVE-2025-49794"}]}, findings), [alias_key])
        with tempfile.TemporaryDirectory() as temporary:
            feed = Path(temporary) / "kev.json"
            feed.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2025-49794"}]}))
            args = SimpleNamespace(kev=str(feed), app="app", validation_result="pass", patch_policy="enabled",
                patch_disabled_class=None, patch_disabled_detail=None, candidate_digest=None, copa_classification=None,
                source_sha="a" * 40, run_id="1", run_attempt=1, proposed_tag="v1-bocklabs.1", upstream_index_digest="sha256:" + "a" * 64)
            decision = policy.build_decision(args, "sha256:" + "a" * 64, findings, {}, None, {}, {}, {}, None, None)
            self.assertFalse(decision["eligible"])
            self.assertEqual(decision["reason"], "missing_kev_acceptance")
            self.assertEqual(decision["policy"]["kev"]["matched"], ["CVE-2025-49794"])
        match["vulnerability"]["fix"] = {"state": "fixed", "versions": ["1:2.16.0-2", "1:2.16.0-1"]}
        self.assertEqual(arch.finding_rows(match, {"xml": package})[0]["FixedVersion"], "1:2.16.0-1")
        match["vulnerability"]["fix"]["state"] = "malformed"
        with self.assertRaisesRegex(ValueError, "fix"):
            arch.finding_rows(match, {"xml": package})

    def test_cyclonedx_keeps_encoded_native_purl_and_truthful_tools(self):
        purl = "pkg:alpm/arch/xml@1%3A2-1?arch=x86_64"
        provenance = {"dataSource": "https://security.archlinux.org/AVG-2898", "primary": "AVG-2898",
                      "namespace": "arch:distro:archlinux:rolling"}
        report = {"ArchScanner": {"schema": "arch-scanner-v1", "capsule": "arch-before/capsule.json"},
                  "Results": [{"Type": "archlinux", "Packages": [{"Name": "xml", "Version": "1:2-1", "Identifier": {"PURL": purl}}],
                   "Vulnerabilities": [{"VulnerabilityID": "CVE-2025-49794", "PkgIdentifier": {"PURL": purl}, "ArchProvenance": provenance}]}]}
        cdx = {"bomFormat": "CycloneDX", "components": [{"name": "xml", "version": "1:2-1", "purl": purl.replace("%3A", ":"), "bom-ref": "original"}],
               "vulnerabilities": [{"id": "CVE-2025-49794", "affects": [{"ref": "original"}]}],
               "metadata": {"tools": {"components": [{"name": "trivy", "version": "0.75.0"}]}}}
        with tempfile.TemporaryDirectory() as temporary, patch.object(policy, "validate_native_inventory"):
            root = Path(temporary)
            arch.write_json(root / "report.json", report)
            arch.write_json(root / "cdx.json", cdx)
            arch.annotate_cyclonedx(root / "report.json", root / "cdx.json")
            output = arch.read_json(root / "cdx.json")
            self.assertEqual(output["components"][0]["purl"], purl)
            self.assertEqual(output["vulnerabilities"][0]["affects"], [{"ref": "original"}])
            self.assertEqual(output["vulnerabilities"][0]["source"]["name"], "Grype / Arch Linux")
            self.assertEqual({t["name"] for t in output["metadata"]["tools"]["components"]}, {"trivy", "syft", "grype"})

    def test_capsule_rejects_missing_tampered_and_unsafe_input_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "arch-before"
            root.mkdir()
            (root / "input").write_text("original")
            capsule = {"schema": "arch-scanner-capsule-v1", "reference": "test", "scanned_at": "test",
                       "grype_db_sha256": "test", "hashes": arch.regular_files(root)}
            (root / "capsule.json").write_text(json.dumps(capsule))
            (root / "input").write_text("tampered")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                arch.verify_capsule(root / "capsule.json")
            (root / "input").unlink()
            with self.assertRaisesRegex(ValueError, "file set"):
                arch.verify_capsule(root / "capsule.json")
            (root / "input").symlink_to("/etc/hosts")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                arch.verify_capsule(root / "capsule.json")

    def test_arch_version_epoch_release_equality_and_downgrade(self):
        report: dict = {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "archlinux", "Name": "rolling"}},
                  "Results": [{"Target": "Arch", "Class": "os-pkgs", "Type": "archlinux",
                  "Packages": [{"Name": "libxml2", "Version": "1:2.15.4-2"}]}]}
        before = policy.package_inventory(report, "Arch")
        self.assertEqual(policy.package_changes(before, before), ([], []))
        after = copy.deepcopy(report)
        after["Results"][0]["Packages"][0]["Version"] = "1:2.15.4-1"
        self.assertTrue(policy.package_changes(before, policy.package_inventory(after, "Arch"))[1])


if __name__ == "__main__":
    unittest.main()
