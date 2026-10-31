#!/usr/bin/env python3
"""Tests for the Go file-build evidence generator."""

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
generator = importlib.import_module("generate_go_file_build")


class GenerateGoFileBuildTests(unittest.TestCase):
    def test_parse_build_info_counts_and_vcs(self):
        info = generator.parse_build_info(
            "/work/app: go1.26.9\n"
            "\tpath\tgithub.com/example/app/cmd\n"
            "\tmod\tgithub.com/example/app\t(devel)\t\n"
            "\tdep\tgithub.com/example/dep\tv1.2.3\th1:abc=\n"
            "\tdep\tgithub.com/example/app/pkg\t(devel)\t\n"
            "\tbuild\tvcs.revision=deadbeef\n"
        )
        self.assertEqual(info["go_version"], "go1.26.9")
        self.assertEqual(info["main_module"], "github.com/example/app")
        self.assertEqual(info["go_package_count"], 2)
        self.assertEqual(info["versioned_go_package_count"], 1)
        self.assertEqual(info["build"]["vcs.revision"], "deadbeef")

    def test_parse_build_info_supports_command_line_arguments(self):
        info = generator.parse_build_info(
            "/work/app: go1.25.11\n"
            "\tpath\tcommand-line-arguments\n"
            "\tdep\tgithub.com/example/app\t(devel)\t\n"
        )
        self.assertEqual(info["main_module"], "")
        self.assertEqual(info["first_party_module"], "github.com/example/app")
        self.assertEqual(info["module_version"], "(devel)")

    def assert_source_matches(self, source, info, labels):
        rescan = importlib.import_module("rescan_published")
        validator = importlib.import_module("validate_inventory")
        layer = {"Digest": "sha256:" + "b" * 64, "DiffID": "sha256:" + "c" * 64}
        config = "sha256:" + "d" * 64
        child = "sha256:" + "e" * 64
        ref = "example/app:full-tag@sha256:" + "a" * 64
        review = {"schema": "trusted-images.bocklabs.dev/go-file-build-v1", "ref": ref,
                  "config_digest": config, "upstream_child_digest": child,
                  "target": "app", "module": info["first_party_module"], "layer": layer,
                  "binary_sha256": "f" * 64, "source": source,
                  "build_info": {"vcs_revision": info["build"]["vcs.revision"]}}
        validator.parse_go_file_build(json.dumps(review).encode(), Path("review.json"))
        selection = {"ref": ref, "published": {"upstream": {"selected_child_digest": child}}}
        self.assertTrue(rescan.review_matches_image(review, selection, {"ImageID": config}, labels, [layer["DiffID"]]))

    def test_unknown_source_tag_is_omitted_and_existing_gate_accepts_vcs(self):
        revision = "92639f8432a16ec1dbd16ffa9f6b786ca085d64a"
        info = generator.parse_build_info(
            "app: go1.26.6\n\tpath\tgithub.com/portainer/portainer/api/cmd/portainer\n"
            "\tmod\tgithub.com/portainer/portainer\t(devel)\t\n"
            f"\tbuild\tvcs.revision={revision}\n"
        )
        labels = {"org.opencontainers.image.revision": revision[:7]}
        with patch.object(generator.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")):
            source = generator.source_info(labels, info)
        self.assertNotIn("tag", source)
        self.assertEqual(source["revision"], revision)
        self.assert_source_matches(source, info, labels)

    def test_opaque_module_requires_unique_matching_tag_and_binary_vcs(self):
        revision = "72dd0fb067f6d7826c7f79907670ba4a713bfe37"
        info = generator.parse_build_info(
            "caddy: go1.26.8\n\tpath\tcaddy\n\tmod\tcaddy\t(devel)\t\n"
            "\tdep\tgithub.com/caddyserver/caddy/v2\tv2.11.7\th1:example\n"
            f"\tbuild\tvcs.revision={revision}\n"
        )
        labels = {"org.opencontainers.image.source": "https://github.com/caddyserver/caddy-docker",
                  "org.opencontainers.image.version": "v2.11.7",
                  "org.opencontainers.image.base.name": "caddy:2.11.7-alpine"}
        tag_result = f"{revision}\trefs/tags/v2.11.7^{{}}\n"
        with patch.object(generator, "run", return_value=tag_result), patch.object(
            generator.urllib.request, "urlopen", side_effect=urllib.error.URLError("offline")
        ):
            source = generator.source_info(labels, info)
        self.assertEqual(source["repository"], "https://github.com/caddyserver/caddy")
        self.assertEqual(source["tag"], "v2.11.7")
        self.assert_source_matches(source, info, labels)
        ambiguous = {**info, "deps": info["deps"] + [["github.com/other/project", "v2.11.7"]]}
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            generator.source_info(labels, ambiguous)
        with patch.object(generator, "run", return_value=f"{'a' * 40}\trefs/tags/v2.11.7^{{}}\n"), self.assertRaisesRegex(ValueError, "revision|VCS"):
            generator.source_info(labels, info)
        with patch.object(generator, "run", return_value=""), self.assertRaisesRegex(ValueError, "not resolvable"):
            generator.source_info(labels, info)
        with patch.object(generator, "run", return_value=f"{revision}\trefs/tags/other^{{}}\n"), self.assertRaisesRegex(ValueError, "not resolvable"):
            generator.source_info(labels, info)
        with patch.object(generator, "run", side_effect=subprocess.CalledProcessError(1, ["git"])), self.assertRaisesRegex(ValueError, "not resolvable"):
            generator.source_info(labels, info)

    def test_native_go_build_info_hash_is_stable_across_temp_directories(self):
        directories = []

        def docker(*args):
            if args[0] == "create":
                return "container-id\n"
            if args[0] == "cp":
                Path(args[-1]).write_bytes(b"binary fixture")
                return ""
            self.assertEqual(args[0], "rm")
            return ""

        def run(*args, cwd=None):
            self.assertEqual(args, ("go", "version", "-m", "app"))
            self.assertEqual((Path(cwd) / "app").read_bytes(), b"binary fixture")
            directories.append(cwd)
            return "app: go1.26.6\n\tpath\texample/app\n\tmod\texample/app\t(devel)\t\n\tdep\texample/dep\tv1.2.3\th1:example\n"

        with patch.object(generator, "docker", side_effect=docker), patch.object(generator, "run", side_effect=run):
            first = generator.binary_build_info("example@sha256:abc", "usr/bin/app")
            second = generator.binary_build_info("example@sha256:abc", "usr/bin/app")
        self.assertNotEqual(directories[0], directories[1])
        self.assertEqual(first, second)
        self.assertEqual(first[1]["go_package_count"], 1)
        self.assertEqual(first[1]["versioned_go_package_count"], 1)

    def test_versionless_targets_ignore_versioned_packages(self):
        report = {
            "Results": [
                {
                    "Class": "lang-pkgs",
                    "Type": "gobinary",
                    "Target": "app",
                    "Packages": [
                        {"Name": "example/app/pkg", "AnalyzedBy": "gobinary"},
                        {"Name": "example/dep", "Version": "v1", "AnalyzedBy": "gobinary"},
                    ],
                }
            ]
        }
        targets = generator.versionless_targets(report)
        self.assertEqual(list(targets), ["app"])
        self.assertEqual([item["Name"] for item in targets["app"]], ["example/app/pkg"])

    def test_infer_modules_uses_devel_root_or_relative_packages(self):
        packages = [{"Name": "example/app/pkg"}]
        devel = {
            "module_version": "(devel)",
            "main_module": "example/app",
            "first_party_module": "example/app",
        }
        self.assertEqual(generator.infer_modules(packages, devel), ["example/app"])
        versioned = {
            "module_version": "v1.0.0",
            "main_module": "example/plugin",
            "first_party_module": "example/plugin",
        }
        self.assertEqual(
            generator.infer_modules([{"Name": "./pkg/local"}], versioned),
            ["./pkg/local"],
        )

    def test_source_tag_fallback_rejects_non_github_repository(self):
        with self.assertRaisesRegex(ValueError, "GitHub"):
            generator.source_info(
                {
                    "org.opencontainers.image.source": "https://example.invalid/app",
                    "org.opencontainers.image.base.name": "app:1.0",
                },
                {
                    "first_party_module": "example.invalid/app",
                    "module_version": "(devel)",
                    "build": {},
                },
            )

    def test_write_records_is_idempotent_and_marks_structural_drift(self):
        record = {
            "target": "app",
            "module": "example/app",
            "source": {"repository": "https://github.com/example/app"},
            "value": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory)
            app = inventory / "example"
            app.mkdir()
            self.assertEqual(generator.write_records(inventory, "example", [record], {}), (True, True))
            existing = generator.load_existing(inventory, "example")
            self.assertEqual(generator.write_records(inventory, "example", [record], existing), (False, False))
            moved = {**record, "target": "other"}
            self.assertEqual(generator.write_records(inventory, "example", [moved], existing), (True, True))
            self.assertEqual(
                [json.loads(path.read_text())["target"] for path in app.glob("*.json")],
                ["other"],
            )

    def test_write_records_keeps_colliding_module_names(self):
        records = [
            {"target": "app", "module": module, "source": {"repository": "example"}}
            for module in ("example/first", "example/Bar", "example/bar", "other/bar", "example/!!!")
        ]
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory)
            app = inventory / "example"
            app.mkdir()
            generator.write_records(inventory, "example", records, {})
            existing = generator.load_existing(inventory, "example")
            self.assertEqual(len(existing), len(records))
            self.assertEqual(len(list(app.glob("*.json"))), len(records))
            self.assertFalse(generator.write_records(inventory, "example", records, existing)[0])

    def test_write_records_preserves_evidence_run_when_unchanged(self):
        record = {
            "target": "app",
            "module": "example/app",
            "source": {"repository": "https://github.com/example/app"},
            "build_info": {"main_module": "example/app"},
            "evidence_run": "https://example.invalid/run1",
        }
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory)
            (inventory / "example").mkdir()
            generator.write_records(inventory, "example", [record], {})
            existing = generator.load_existing(inventory, "example")
            changed, structural = generator.write_records(
                inventory,
                "example",
                [{**record, "evidence_run": "https://example.invalid/run2"}],
                existing,
            )
            self.assertFalse(changed)
            self.assertFalse(structural)

    def test_missing_go_scan_preserves_evidence_but_versioned_scan_can_retire_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "inventory/example"
            app.mkdir(parents=True)
            proof = app / "go-file-build.json"
            original = json.dumps({
                "target": "app", "module": "example/app", "source": {"repository": "example"},
            })
            proof.write_text(original)
            (root / "selection.json").write_text(json.dumps({"ref": "example@sha256:abc"}))
            reports = (
                [{"Class": "os-pkgs", "Type": "alpine", "Packages": [{"Name": "musl", "Version": "1"}]}],
                [{"Class": "lang-pkgs", "Type": "gobinary", "Target": "app",
                  "Packages": [{"Name": "example/app", "Version": "v1"}]}],
            )
            for results, expected in zip(reports, (False, True)):
                (root / "report.json").write_text(json.dumps({"Results": results}))
                result = subprocess.run(
                    [sys.executable, str(ROOT / "scripts/generate_go_file_build.py"),
                     "--app", "example", "--inventory", str(root / "inventory"),
                     "--report", str(root / "report.json"), "--selection", str(root / "selection.json")],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, expected, result.stderr)
                if not expected:
                    self.assertIn("missing previously reviewed Go targets", result.stderr)
                    self.assertEqual(proof.read_text(), original)
                else:
                    self.assertFalse(proof.exists())

    def test_promote_workflow_auto_merges_only_without_structural_drift(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/promote.yaml").read_text(encoding="utf-8")
        )
        job = workflow["jobs"]["go-evidence"]
        uses = [step.get("uses") for step in job["steps"]]
        self.assertIn("./.github/actions/validate/push-generated-pr", uses)
        merge = next(
            step
            for step in job["steps"]
            if step.get("uses") == "./.github/actions/publish/auto-merge-pr"
        )
        self.assertIn("evidence_structural_drift == 'false'", merge["if"])
        self.assertIn("steps.evidence.outputs.pr_url != ''", merge["if"])
        self.assertIn("steps.evidence.outputs.head_sha != ''", merge["if"])

    def test_rescan_refreshes_evidence_before_remediation_decision(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/promote.yaml").read_text(encoding="utf-8")
        )
        names = [step["name"] for step in workflow["jobs"]["rescan"]["steps"]]
        self.assertLess(
            names.index("Generate Go file-build evidence for this scan"),
            names.index("Decide producer remediation need"),
        )


if __name__ == "__main__":
    unittest.main()
