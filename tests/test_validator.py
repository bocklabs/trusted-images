#!/usr/bin/env python3
"""Positive- and negative-case tests for scripts/validate_inventory.py.

Builds throwaway inventory roots with yaml.safe_dump, runs the validator as a
subprocess against each root, and asserts the exit code plus — for every
negative case — that the failure output names the offending file, field, or
value. stdlib unittest only; PyYAML is used to build the fixtures.
"""


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
            "validation": {"type": "http", "port": 9187},
            "version": 2,
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

    def assert_valid(self, entry: dict | None = None) -> None:
        self.write_entry("app-a", entry if entry is not None else valid_entry())
        result = run_validator(self.root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK: inventory valid", result.stdout)

    def assert_fails(self, entry: dict, *needles: str, folder: str = "app-a") -> str:
        path = self.write_entry(folder, entry)
        result = run_validator(self.root)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, output)
        for needle in needles:
            self.assertIn(needle, output)
        self.assertIn(str(path), output)
        return output

    def test_valid_entry_passes(self) -> None:
        self.assert_valid()

    def test_missing_digest_field_fails(self) -> None:
        entry = valid_entry()
        del entry["spec"]["upstream"]["digest"]
        self.assert_fails(entry, "spec.upstream.digest")

    def test_malformed_digest_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["upstream"]["digest"] = "sha256:deadbeef"
        self.assert_fails(entry, "sha256:deadbeef")

    def test_duplicate_package_fails(self) -> None:
        self.write_entry("app-a", valid_entry())
        second_entry = valid_entry()
        second_entry["metadata"]["name"] = "app-b"
        second_entry["spec"]["destination"]["package"] = "ghcr.io/bocklabs/app-a"
        self.assert_fails(
            second_entry, "duplicate", "ghcr.io/bocklabs/app-a", folder="app-b"
        )

    def test_bad_patch_policy_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["patchPolicy"] = "sometimes"
        self.assert_fails(entry, "sometimes")

    def test_wrong_validation_type_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["validation"]["type"] = "grpc"
        self.assert_fails(entry, "spec.validation.type", "grpc")

    def test_http_without_port_fails(self) -> None:
        entry = valid_entry()
        del entry["spec"]["validation"]["port"]
        self.assert_fails(entry, "spec.validation.port", "required for type 'http'")

    def test_http_port_out_of_range_fails(self) -> None:
        for bad_port in (0, 70000):
            with self.subTest(port=bad_port):
                entry = valid_entry()
                entry["spec"]["validation"]["port"] = bad_port
                self.assert_fails(entry, "spec.validation.port", str(bad_port))

    def test_unknown_validation_key_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["validation"]["ports"] = 9187
        self.assert_fails(entry, "spec.validation.ports", "not a known param")

    def test_version_1_rejected(self) -> None:
        entry = valid_entry()
        entry["spec"]["version"] = 1
        self.assert_fails(entry, "spec.version", "1")

    def test_version_string_rejected(self) -> None:
        entry = valid_entry()
        entry["spec"]["version"] = "2"
        self.assert_fails(entry, "spec.version", "'2'")

    def test_expected_platforms_list_passes(self) -> None:
        entry = valid_entry()
        entry["spec"]["validation"]["expectedPlatforms"] = ["linux/amd64", "linux/arm64"]
        self.assert_valid(entry)

    def test_expected_platforms_non_list_fails(self) -> None:
        entry = valid_entry()
        entry["spec"]["validation"]["expectedPlatforms"] = "linux/amd64"
        self.assert_fails(entry, "spec.validation.expectedPlatforms")


if __name__ == "__main__":
    unittest.main()
