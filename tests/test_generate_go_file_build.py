#!/usr/bin/env python3
"""Tests for the Go file-build evidence generator."""

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

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
