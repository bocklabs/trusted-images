#!/usr/bin/env python3
"""Positive- and negative-case tests for scripts/validate_inventory.py.

Builds throwaway inventory roots with yaml.safe_dump, runs the validator as a
subprocess against each root, and asserts the exit code plus — for every
negative case — that the failure output names the offending file, field, or
value. stdlib unittest only; PyYAML is used to build the fixtures.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "validate_inventory.py"
GOOD_DIGEST = "sha256:" + "a1" * 32


def valid_entry() -> dict:
    return {
        "apiVersion": "trusted-images.bocklabs.dev/v1",
        "kind": "Image",
        "metadata": {"name": "app-a"},
        "spec": {
            "upstream": {
                "ref": "quay.io/example/app-a",
                "tag": "v1.2.3",
                "digest": GOOD_DIGEST,
            },
            "destination": {"package": "ghcr.io/bocklabs/app-a"},
            "patchPolicy": "enabled",
            "validationProfile": "http",
            "version": 1,
        },
    }


def run_validator(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(root)],
        capture_output=True,
        text=True,
    )


class ValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "inventory"
        self.root.mkdir()

    def write_entry(self, folder: str, entry: dict) -> Path:
        path = self.root / folder / "image.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(entry), encoding="utf-8")
        return path

    def test_valid_entry_passes(self) -> None:
        self.write_entry("app-a", valid_entry())
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK: inventory valid", result.stdout)

    def test_missing_digest_field_fails(self) -> None:
        entry = valid_entry()
        del entry["spec"]["upstream"]["digest"]
        path = self.write_entry("app-a", entry)
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("spec.upstream.digest", output)
        self.assertIn(str(path), output)

    def test_malformed_digest_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["upstream"]["digest"] = "sha256:deadbeef"
        self.write_entry("app-a", entry)
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("sha256:deadbeef", output)
        self.assertIn("app-a", output)

    def test_duplicate_package_fails(self) -> None:
        self.write_entry("app-a", valid_entry())
        second_entry = valid_entry()
        second_entry["metadata"]["name"] = "app-b"
        second_entry["spec"]["destination"]["package"] = "ghcr.io/bocklabs/app-a"
        second = self.write_entry("app-b", second_entry)
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("duplicate", output)
        self.assertIn("ghcr.io/bocklabs/app-a", output)
        self.assertIn(str(second), output)

    def test_bad_patch_policy_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["patchPolicy"] = "sometimes"
        self.write_entry("app-a", entry)
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("sometimes", output)
        self.assertIn("app-a", output)


if __name__ == "__main__":
    unittest.main()
