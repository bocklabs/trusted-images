"""Promotion tag allocation and workflow contract tests."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote.yaml"
RESOLVER = REPO_ROOT / "scripts" / "resolve_internal_tag.py"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class TagAllocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(REPO_ROOT))
        from scripts.resolve_internal_tag import select_internal_tag

        cls.select = staticmethod(select_internal_tag)

    def observation(self, revision: int, digest: str = DIGEST_A) -> dict[str, str]:
        return {"tag": f"v1.2.3-bocklabs.{revision}", "digest": digest}

    def test_normal_rerun_uses_newest_matching_revision(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_A,
            [self.observation(2), self.observation(10), self.observation(9)],
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.10", True))

    def test_normal_changed_digest_allocates_after_numeric_maximum(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_B,
            [self.observation(9), self.observation(10)],
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.11", False))

    def test_force_allocates_next_revision_for_identical_digest(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_A,
            [self.observation(9), self.observation(10)],
            force_repromote=True,
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.11", False))

    def test_recovery_selects_exact_older_revision(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_A,
            [self.observation(2), self.observation(10)],
            recover_tag="v1.2.3-bocklabs.2",
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.2", True))

    def test_recovery_rejects_absent_or_mismatched_revision(self) -> None:
        with self.assertRaisesRegex(ValueError, "not published"):
            self.select("v1.2.3", DIGEST_A, [], recover_tag="v1.2.3-bocklabs.2")
        with self.assertRaisesRegex(ValueError, "digest"):
            self.select(
                "v1.2.3",
                DIGEST_B,
                [self.observation(2)],
                recover_tag="v1.2.3-bocklabs.2",
            )

    def test_force_and_recovery_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            self.select("v1.2.3", DIGEST_A, [], True, "v1.2.3-bocklabs.2")

    def test_malformed_or_incomplete_observations_fail_closed(self) -> None:
        invalid = (
            None,
            {},
            [{"tag": "v1.2.3-bocklabs.1"}],
            [{"tag": "v1.2.3-bocklabs.1", "digest": "bad"}],
        )
        for observations in invalid:
            with self.subTest(observations=observations):
                with self.assertRaises(ValueError):
                    self.select("v1.2.3", DIGEST_A, observations)

    def test_cli_emits_validated_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            observations = Path(tmp) / "observations.json"
            observations.write_text(json.dumps([self.observation(1)]), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(RESOLVER),
                    "--upstream-tag",
                    "v1.2.3",
                    "--upstream-digest",
                    DIGEST_A,
                    "--observations",
                    str(observations),
                    "--force-repromote",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            {"internal_tag": "v1.2.3-bocklabs.2", "skip_copy": False},
        )


class PromoteWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_dispatch_exposes_force_and_recovery_modes(self) -> None:
        for text in ("force_repromote:", "recover_tag:", "recovery_run_id:"):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)

    def test_validation_still_gates_promotion(self) -> None:
        self.assertIn("promote:\n    needs: validate", self.workflow)
        self.assertIn("cancel-in-progress: true", self.workflow)

    def test_registry_reads_and_copy_fail_closed(self) -> None:
        for text in (
            "--observations registry-observations.json",
            "Assert destination tag is still absent",
            "curl --fail-with-body",
            'rel="next"',
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)
        self.assertNotIn("tags/list?n=1000", self.workflow)

    def test_recovery_uses_original_inventory_as_data(self) -> None:
        for text in (
            "validation-context",
            "original_source_sha",
            "actions/runs/${ORIGINAL_RUN_ID}",
            "scripts/validate_image.py",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)

    def test_skip_and_recovery_still_verify_platforms(self) -> None:
        platform_step = self.workflow.split("- name: Assert platform-set equality", 1)[1]
        platform_step = platform_step.split("- name:", 1)[0]
        self.assertNotIn("skip_copy != 'true'", platform_step)

    def test_provenance_writeback_is_scoped_and_reusable(self) -> None:
        for text in (
            'git add "provenance/${APP}/${INTERNAL_TAG}.json"',
            "git diff --cached --quiet",
            "--force-with-lease=refs/heads/${BRANCH}:",
            "--state all",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)
        self.assertNotIn("git add provenance/", self.workflow)


if __name__ == "__main__":
    unittest.main()
