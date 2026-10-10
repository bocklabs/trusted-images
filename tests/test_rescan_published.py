"""Producer-owned daily monitoring and remediation contracts."""

import copy
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
rescan = importlib.import_module("rescan_published")


class PublishedRescanTests(unittest.TestCase):
    def test_retention_hashes_nested_files_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(rescan, "ARTIFACT", Path(directory)):
            nested = Path(directory) / "arch-published" / "db"
            nested.mkdir(parents=True)
            (nested / "evidence").write_text("frozen")
            rescan.retain("decision.json", {"proceed": False})
            checksums = (Path(directory) / "SHA256SUMS").read_text()
            self.assertIn("  arch-published/db/evidence\n", checksums)
            self.assertIn("  decision.json\n", checksums)
            (nested / "unsafe").symlink_to("/etc/hosts")
            with self.assertRaisesRegex(ValueError, "unsafe rescan"):
                rescan.retain("decision.json", {"proceed": False})

    def setUp(self):
        self.record = json.loads((ROOT / "provenance/postgres-exporter/current.json").read_text())
        self.spec = yaml.safe_load((ROOT / "inventory/postgres-exporter/image.yaml").read_text())["spec"]
        self.ref = "ghcr.io/bocklabs/postgres-exporter:v0.20.1-bocklabs.7@" + self.record["internal"]["digest"]
        self.selection = {"app": "postgres-exporter", "ref": self.ref, "spec": self.spec, "published": self.record}
        self.report = {"SchemaVersion": 2, "ArtifactName": self.ref, "Metadata": {"OS": {"EOSL": False}},
                       "Results": [{"Class": "os-pkgs", "Type": "debian", "Target": "root",
                                    "Packages": [{"Name": "openssl", "Version": "1"}],
                                    "Vulnerabilities": [{"VulnerabilityID": "CVE-2026-1234", "PkgName": "openssl",
                                                         "InstalledVersion": "1", "FixedVersion": "2", "Severity": "LOW"}]}]}

    def test_fixable_os_enters_existing_policy_with_canonical_need(self):
        value = rescan.decide(self.selection, self.report, True)
        self.assertTrue(value["proceed"])
        self.assertTrue(value["force_repromote"])
        self.assertEqual(value["requested_remediation"]["need_sha256"],
                         rescan.findings_hash(value["requested_remediation"]["findings"]))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "published-rescan"
            work.mkdir()
            (work / "selection.json").write_text(json.dumps(self.selection))
            (work / "trivy-full.json").write_text(json.dumps(self.report))
            output = Path(directory) / "output"
            env = {**os.environ, "REMEDIATION_ENABLED": "true", "GITHUB_OUTPUT": str(output),
                   "GITHUB_STEP_SUMMARY": str(Path(directory) / "summary")}
            result = subprocess.run([sys.executable, str(ROOT / "scripts/rescan_published.py"), "decide"],
                                    cwd=directory, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("proceed=true", output.read_text())
            self.assertIn("trivy-full.json", (work / "SHA256SUMS").read_text())
            manifest = json.loads((work / "secobserve-upload.json").read_text())
            self.assertEqual(manifest["upstream_ref"] + ":" + manifest["upstream_tag"], self.ref)

    def test_monitoring_disabled_clean_and_no_fix_do_not_mutate(self):
        value = rescan.decide(self.selection, self.report, False)
        self.assertFalse(value["proceed"])
        self.assertEqual(value["actionable"], 1)
        self.report["Results"][0]["Vulnerabilities"][0]["FixedVersion"] = ""
        value = rescan.decide(self.selection, self.report, True)
        self.assertFalse(value["proceed"])
        self.assertEqual(value["no_fix"], 1)
        self.report["Results"][0]["Vulnerabilities"] = []
        self.assertEqual(rescan.decide(self.selection, self.report, True)["findings"], 0)

    def test_language_requires_reviewed_upstream_change_and_disabled_os_is_unsupported(self):
        self.spec["patchPolicy"] = "disabled"
        self.assertEqual(rescan.decide(self.selection, self.report, True)["unsupported"], 1)
        self.report["Results"][0]["Class"] = "lang-pkgs"
        self.report["Results"][0]["Type"] = "gobinary"
        self.assertFalse(rescan.decide(self.selection, self.report, True)["proceed"])
        self.spec["upstream"]["digest"] = "sha256:" + "a" * 64
        self.assertTrue(rescan.decide(self.selection, self.report, True)["proceed"])

    def test_incomplete_coverage_wrong_reference_and_eol_fail_closed(self):
        incomplete: tuple[None | list[dict[str, str]], ...] = (None, [])
        for packages in incomplete:
            self.report["Results"][0]["Packages"] = packages
            self.assertFalse(rescan.decide(self.selection, self.report, True)["proceed"])
        self.report["Results"] = []
        self.assertFalse(rescan.decide(self.selection, self.report, True)["package_coverage"])
        self.report["ArtifactName"] = "other"
        with self.assertRaisesRegex(ValueError, "scan reference"):
            rescan.decide(self.selection, self.report, True)
        self.report["ArtifactName"] = self.ref
        self.report["Metadata"]["OS"]["EOSL"] = True
        with self.assertRaisesRegex(ValueError, "end-of-life"):
            rescan.decide(self.selection, self.report, True)

    def test_latest_merged_signed_record_and_corrupt_identity(self):
        older = copy.deepcopy(self.record)
        older["promoted_at"] = "2026-09-26T00:00:00Z"
        older.pop("signing")
        older["internal"]["tag"] = "v0.20.1-bocklabs.6"
        with patch.object(rescan, "merged_commit", return_value="a" * 40), patch.object(rescan, "load_current", return_value=self.record):
            self.assertEqual(rescan.latest_record("postgres-exporter")[1], self.ref)
            with patch.object(rescan, "load_current", return_value=older):
                self.assertIsNone(rescan.latest_record("postgres-exporter"))
            self.record["internal"]["package"] = "ghcr.io/bocklabs/other"
            with self.assertRaisesRegex(ValueError, "provenance identity"):
                rescan.latest_record("postgres-exporter")

    def test_selection_without_publication_is_monitor_only_and_stale_queue_is_blocked(self):
        env = {"GITHUB_REF": "refs/heads/main", "INPUT_APP": "postgres-exporter"}
        with patch.dict(os.environ, env, clear=True), patch.object(rescan, "git", return_value="a" * 40), patch.object(rescan, "latest_record", return_value=None), patch.object(rescan, "retain"), patch.object(rescan, "output") as output:
            rescan.select()
            self.assertFalse(output.call_args.args[0]["proceed"])
        with patch.dict(os.environ, env, clear=True), patch.object(rescan, "git", side_effect=["a" * 40, "b" * 40]):
            with self.assertRaisesRegex(ValueError, "stale"):
                rescan.select()
        with patch.dict(os.environ, {**env, "INPUT_FORCE_REPROMOTE": "true"}, clear=True):
            with self.assertRaisesRegex(ValueError, "manual overrides"):
                rescan.select()

    def test_schedule_dispatch_scope_and_immutable_scan_contract(self):
        daily = yaml.safe_load((ROOT / ".github/workflows/daily-rescan.yaml").read_text())
        self.assertIn("schedule", daily.get("on", daily.get(True)))
        steps = daily["jobs"]["dispatch"]["steps"]
        token = next(s for s in steps if s.get("id") == "token")["with"]
        self.assertEqual(token["permission-actions"], "write")
        self.assertEqual(token["repositories"], "${{ github.event.repository.name }}")
        root = yaml.safe_load((ROOT / ".github/workflows/promote.yaml").read_text())
        self.assertEqual(root["concurrency"]["group"], "promote-${{ inputs.app }}")
        scan = next(s for s in root["jobs"]["rescan"]["steps"] if s.get("id") == "scan")
        self.assertEqual(scan["with"]["ignore-unfixed"], "false")
        self.assertEqual(scan["with"]["list-all-pkgs"], "true")
        self.assertEqual(root["jobs"]["rescan"]["permissions"], {"contents": "read"})
        upload = next(s for s in root["jobs"]["rescan"]["steps"] if s.get("with", {}).get("name") == "trivy-full-report")
        self.assertIn("steps.decision.outputs.proceed != 'true'", upload["if"])
        self.assertIn("published-rescan/secobserve-upload.json", upload["with"]["path"])


if __name__ == "__main__":
    unittest.main()
