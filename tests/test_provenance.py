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
    "sha256:e5d9c4af8ec327785c7ca938d1e4f8452c6a05014850e58e2ff9456899ebd97c"
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
        "--validation-type": "http",
        "--validation-result": "pass",
        "--validation-params": '{"port":9187,"expectStatus":200,"path":"/","durationSeconds":30}',
        "--validation-timings": (
            '{"started_at":"2026-09-06T00:00:00Z",'
            '"finished_at":"2026-09-06T00:00:35Z","duration_seconds":35}'
        ),
        "--validation-health": '{"defined":false,"final_status":"none-defined"}',
        "--validation-runner": "ubuntu-latest",
        "--validation-entrypoint": '["/bin/postgres_exporter"]',
        "--validation-cmd": "[]",
        "--validation-env": "[]",
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

    def test_validation_block_present_in_record(self) -> None:
        result = self.run_generator(valid_flags(self.out))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.out.exists())
        record = json.loads(self.out.read_text(encoding="utf-8"))
        validation = record["validation"]
        self.assertEqual(validation["profile"], "http")
        self.assertEqual(validation["result"], "pass")
        self.assertEqual(
            validation["params"],
            {"port": 9187, "expectStatus": 200, "path": "/", "durationSeconds": 30},
        )
        self.assertEqual(
            validation["timings"],
            {
                "started_at": "2026-09-06T00:00:00Z",
                "finished_at": "2026-09-06T00:00:35Z",
                "duration_seconds": 35,
            },
        )
        self.assertEqual(
            validation["health"], {"defined": False, "final_status": "none-defined"}
        )
        self.assertEqual(validation["runner"], "ubuntu-latest")
        self.assertEqual(
            validation["baseline"],
            {
                "entrypoint": ["/bin/postgres_exporter"],
                "cmd": [],
                "env": [],
            },
        )

    def test_missing_validation_result_fails(self) -> None:
        result = self.run_generator(self.mutated(validation_result=None))
        self.assert_fails_closed(result, "validation-result")

    def test_malformed_validation_entrypoint_json_fails(self) -> None:
        result = self.run_generator(self.mutated(validation_entrypoint="not-json"))
        self.assert_fails_closed(result, "validation-entrypoint")

    def test_non_object_validation_timings_fails(self) -> None:
        result = self.run_generator(self.mutated(validation_timings="[]"))
        self.assert_fails_closed(result, "validation-timings")

    def recovery_flags(self) -> dict[str, str]:
        flags = valid_flags(self.out)
        flags["--run-url"] = "https://github.com/bocklabs/trusted-images/actions/runs/99"
        flags.update(
            {
                "--original-run-url": "https://github.com/bocklabs/trusted-images/actions/runs/42",
                "--original-source-sha": "d" * 40,
                "--recovered-tag": "v0.20.1-bocklabs.1",
                "--recovered-digest": PILOT_UPSTREAM_DIGEST,
            }
        )
        return flags

    def test_recovery_records_original_binding_and_new_run(self) -> None:
        result = self.run_generator(self.recovery_flags())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(
            record["pipeline"]["run_url"],
            "https://github.com/bocklabs/trusted-images/actions/runs/99",
        )
        self.assertEqual(
            record["recovery"],
            {
                "original_run_url": "https://github.com/bocklabs/trusted-images/actions/runs/42",
                "original_source_sha": "d" * 40,
                "recovered_tag": "v0.20.1-bocklabs.1",
                "recovered_digest": PILOT_UPSTREAM_DIGEST,
            },
        )

    def test_incomplete_recovery_metadata_fails(self) -> None:
        flags = self.recovery_flags()
        del flags["--original-source-sha"]
        result = self.run_generator(flags)
        self.assert_fails_closed(result, "recovery")

    def test_recovery_tag_and_digest_must_match_internal(self) -> None:
        flags = self.recovery_flags()
        flags["--recovered-tag"] = "v0.20.1-bocklabs.2"
        result = self.run_generator(flags)
        self.assert_fails_closed(result, "recovered-tag")
        flags = self.recovery_flags()
        flags["--recovered-digest"] = "sha256:" + "e" * 64
        result = self.run_generator(flags)
        self.assert_fails_closed(result, "recovered-digest")

    def test_recovery_requires_a_new_run_url(self) -> None:
        flags = self.recovery_flags()
        flags["--run-url"] = flags["--original-run-url"]
        result = self.run_generator(flags)
        self.assert_fails_closed(result, "run-url")


if __name__ == "__main__":
    unittest.main()
