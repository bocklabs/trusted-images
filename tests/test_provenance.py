#!/usr/bin/env python3
"""Positive- and negative-case tests for scripts/generate_provenance.py.

Builds argv flag sets from one valid pilot-shaped baseline (the
postgres-exporter promotion values), runs the generator as a subprocess,
and asserts the exit code plus — for every negative case — that the failure
output names the offending field and that no output file was written.
stdlib unittest only.
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "scripts" / "generate_provenance.py"

PILOT_UPSTREAM_DIGEST = (
    "sha256:ac5ec343104fae0e2d84a27bb8d69b38430a11910c5382cad85d478d2bab713e"
)
PILOT_SKOPEO_DIGEST = (
    "sha256:8d25aabcf965e267b6a6ad02ff8da5512f77de1490063625093ff564797e88bc"
)
SCHEMA = "trusted-images.bocklabs.dev/provenance-v1"


def valid_flags(out: Path) -> dict[str, str]:
    """One valid pilot-shaped flag baseline (postgres-exporter v0.20.1)."""
    return {
        "--app": "postgres-exporter",
        "--upstream-ref": "quay.io/prometheuscommunity/postgres-exporter",
        "--upstream-tag": "v0.20.1",
        "--upstream-digest": PILOT_UPSTREAM_DIGEST,
        "--media-type": "application/vnd.docker.distribution.manifest.list.v2+json",
        "--internal-package": "ghcr.io/bocklabs/postgres-exporter",
        "--internal-tag": "v0.20.1-bocklabs.1",
        "--internal-digest": PILOT_UPSTREAM_DIGEST,
        "--platforms": "linux/amd64,linux/arm64",
        "--run-url": "https://example.invalid/run/1",
        "--workflow": "promote",
        "--dispatched-by": "test",
        "--trivy-version": "0.74.0",
        "--trivy-action-sha": "ed142fd0673e97e23eac54620cfb913e5ce36c25",
        "--skopeo-version": "1.22.2",
        "--skopeo-image-digest": PILOT_SKOPEO_DIGEST,
        "--trivy-db-check-bundle-digest": "sha256:" + "a" * 64,
        "--trivy-db-updated-at": "2026-09-06T00:00:00Z",
        "--full-report-sha256": "b" * 64,
        "--copa-report-sha256": "c" * 64,
        "--secobserve-product": "trusted-images",
        "--secobserve-origin": "quay.io/prometheuscommunity/postgres-exporter:v0.20.1",
        "--out": str(out),
    }


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = (
            Path(tmp.name) / "provenance" / "postgres-exporter" / "v0.20.1-bocklabs.1.json"
        )

    def run_generator(self, flags: dict[str, str]) -> subprocess.CompletedProcess:
        argv = [sys.executable, str(GENERATOR)]
        for key, value in flags.items():
            argv += [key, value]
        return subprocess.run(argv, capture_output=True, text=True)

    def mutated(self, **changes: str | None) -> dict[str, str]:
        """Baseline flags with one flag dropped (None) or replaced."""
        flags = valid_flags(self.out)
        for name, value in changes.items():
            key = "--" + name.replace("_", "-")
            if value is None:
                del flags[key]
            else:
                flags[key] = value
        return flags

    def assert_fails_closed(
        self, result: subprocess.CompletedProcess, field: str
    ) -> None:
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("[provenance]", output)
        self.assertIn(field, output)
        self.assertFalse(self.out.exists())

    def test_valid_record_passes(self) -> None:
        result = self.run_generator(valid_flags(self.out))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.out.exists())
        record = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], SCHEMA)
        self.assertEqual(record["app"], "postgres-exporter")
        self.assertEqual(record["upstream"]["digest"], PILOT_UPSTREAM_DIGEST)
        self.assertEqual(
            record["internal"]["package"], "ghcr.io/bocklabs/postgres-exporter"
        )
        self.assertEqual(record["internal"]["platforms"], ["linux/amd64", "linux/arm64"])
        self.assertEqual(record["tools"]["skopeo"], "1.22.2")
        self.assertIn("promoted_at", record)
        self.assertTrue(record["promoted_at"].endswith("Z"))
        self.assertEqual(record["notes"], "")

    def test_missing_required_flag_fails(self) -> None:
        result = self.run_generator(self.mutated(run_url=None))
        self.assert_fails_closed(result, "run-url")

    def test_malformed_digest_fails(self) -> None:
        result = self.run_generator(self.mutated(upstream_digest="sha256:deadbeef"))
        self.assert_fails_closed(result, "upstream-digest")

    def test_wrong_package_prefix_fails(self) -> None:
        result = self.run_generator(self.mutated(internal_package="ghcr.io/other/app"))
        self.assert_fails_closed(result, "internal-package")

    def test_bad_internal_tag_fails(self) -> None:
        result = self.run_generator(self.mutated(internal_tag="v0.20.1"))
        self.assert_fails_closed(result, "internal-tag")

    def test_empty_platforms_fails(self) -> None:
        result = self.run_generator(self.mutated(platforms=""))
        self.assert_fails_closed(result, "platforms")


if __name__ == "__main__":
    unittest.main()
