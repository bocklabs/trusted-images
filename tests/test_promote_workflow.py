"""Promotion tag allocation and workflow contract tests."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ORCHESTRATOR_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote.yaml"
CANDIDATE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote-candidate.yaml"
PUBLISHER_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "promote-publish.yaml"
WORKFLOW = CANDIDATE_WORKFLOW
RESOLVER = REPO_ROOT / "scripts" / "resolve_internal_tag.py"
SCRIPTS = REPO_ROOT / "scripts"
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64
DIGEST_D = "sha256:" + "d" * 64


class TagAllocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(REPO_ROOT))
        from scripts.resolve_internal_tag import select_internal_tag

        cls.select = staticmethod(select_internal_tag)

    def observation(
        self,
        revision: int,
        digest: str = DIGEST_A,
        child: str | None = DIGEST_A,
        index: str = DIGEST_C,
        platforms: tuple[str, ...] = ("linux/amd64",),
    ) -> dict:
        return {
            "tag": f"v1.2.3-bocklabs.{revision}",
            "digest": digest,
            "upstream_index_digest": index,
            "selected_child_digest": child,
            "platforms": list(platforms),
        }

    def test_normal_rerun_uses_newest_matching_revision(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_C,
            DIGEST_A,
            [self.observation(2), self.observation(10), self.observation(9)],
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.10", True, False, False))

    def test_same_child_with_changed_index_reuses_clean_or_patched_revision(
        self,
    ) -> None:
        for digest in (DIGEST_A, DIGEST_B):
            with self.subTest(digest=digest):
                result = self.select(
                    "v1.2.3",
                    DIGEST_C,
                    DIGEST_A,
                    [
                        self.observation(2),
                        self.observation(10, digest=digest, index=DIGEST_D),
                    ],
                )
                self.assertEqual(result, ("v1.2.3-bocklabs.10", True, True, False))

    def test_normal_changed_digest_allocates_after_numeric_maximum(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_C,
            DIGEST_B,
            [self.observation(9, index=DIGEST_D), self.observation(10, index=DIGEST_D)],
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.11", False, True, True))

    def test_historical_multi_platform_revision_is_never_reused(self) -> None:
        historical = self.observation(
            10, platforms=("linux/amd64", "linux/arm64"), child=None, index=""
        )
        result = self.select("v1.2.3", DIGEST_C, DIGEST_A, [historical])
        self.assertEqual(result, ("v1.2.3-bocklabs.11", False, False, False))

    def test_force_allocates_next_revision_for_identical_digest(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_C,
            DIGEST_A,
            [self.observation(9), self.observation(10)],
            force_repromote=True,
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.11", False, False, False))

    def test_recovery_selects_exact_older_revision(self) -> None:
        result = self.select(
            "v1.2.3",
            DIGEST_C,
            DIGEST_A,
            [self.observation(2), self.observation(10, digest=DIGEST_B)],
            recover_tag="v1.2.3-bocklabs.2",
            recover_candidate_digest=DIGEST_A,
        )
        self.assertEqual(result, ("v1.2.3-bocklabs.2", True, False, False))

    def test_recovery_rejects_absent_revision(self) -> None:
        with self.assertRaisesRegex(ValueError, "not published"):
            self.select(
                "v1.2.3",
                DIGEST_C,
                DIGEST_A,
                [],
                recover_tag="v1.2.3-bocklabs.2",
                recover_candidate_digest=DIGEST_A,
            )

    def test_recovery_rejects_mismatched_revision(self) -> None:
        observation = self.observation(2)
        with self.assertRaisesRegex(ValueError, "digest"):
            self.select(
                "v1.2.3",
                DIGEST_C,
                DIGEST_A,
                [observation],
                recover_tag="v1.2.3-bocklabs.2",
                recover_candidate_digest=DIGEST_B,
            )

    def test_recovery_rejects_historical_revision(self) -> None:
        observation = self.observation(
            2, child=None, index="", platforms=("linux/amd64", "linux/arm64")
        )
        with self.assertRaisesRegex(ValueError, "Phase 05"):
            self.select(
                "v1.2.3",
                DIGEST_C,
                DIGEST_A,
                [observation],
                recover_tag="v1.2.3-bocklabs.2",
                recover_candidate_digest=DIGEST_A,
            )

    def test_force_and_recovery_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot be combined"):
            self.select("v1.2.3", DIGEST_C, DIGEST_A, [], True, "v1.2.3-bocklabs.2")

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
                    self.select("v1.2.3", DIGEST_C, DIGEST_A, observations)

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
                    DIGEST_C,
                    "--selected-child-digest",
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
            {
                "internal_tag": "v1.2.3-bocklabs.2",
                "skip_copy": False,
                "supersedes": {
                    "higher_upstream": False,
                    "original_child_selected": False,
                },
            },
        )


class PromoteWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.orchestrator = ORCHESTRATOR_WORKFLOW.read_text(encoding="utf-8")
        cls.candidate_workflow = CANDIDATE_WORKFLOW.read_text(encoding="utf-8")
        cls.publisher_workflow = PUBLISHER_WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = cls.candidate_workflow + "\n" + cls.publisher_workflow

    def loaded_workflow(self):
        candidate = yaml.safe_load(self.candidate_workflow)
        publisher = yaml.safe_load(self.publisher_workflow)
        return {
            "jobs": {
                "validate": candidate["jobs"]["validate"],
                "promote": publisher["jobs"]["promote"],
            }
        }

    def test_final_report_precedes_complete_cyclonedx_export(self) -> None:
        steps = self.loaded_workflow()["jobs"]["validate"]["steps"]
        names = [step["name"] for step in steps]
        select = steps[names.index("Select the exact final candidate")]["run"]
        convert = steps[names.index("Convert full report to CycloneDX with parity check")]["run"]
        export = steps[names.index("Export checksum-bound candidate artifact")]["run"]
        for digest in ("PATCHED_DIGEST", "RESUME_DIGEST", "RECOVERED_DIGEST"):
            self.assertIn(digest, select)
        self.assertEqual(select.count("cp trivy-after-full.json trivy-full.json"), 3)
        self.assertLess(names.index("Rescan the exact patched bytes with the frozen DB"), names.index("Select the exact final candidate"))
        self.assertLess(names.index("Select the exact final candidate"), names.index("Convert full report to CycloneDX with parity check"))
        self.assertLess(names.index("Convert full report to CycloneDX with parity check"), names.index("Export checksum-bound candidate artifact"))
        self.assertIn("trivy-full.cdx.json", export)
        self.assertIn("rm -f candidate-final.tar resume-final.tar", export)
        self.assertIn("mv candidate-oci candidate-artifact/candidate-oci", export)
        self.assertIn("Packages", convert)
        self.assertIn("components", convert)
        self.assertIn("operating-system", convert)
        self.assertIn("vulnerabilities", convert)

    def test_patched_conversion_rejects_original_child_components(self) -> None:
        steps = self.loaded_workflow()["jobs"]["validate"]["steps"]
        by_name = {step["name"]: step for step in steps}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "trivy-full.json").write_text(json.dumps({"Results": [{"Packages": [{"Name": "old", "Identifier": {"PURL": "pkg:generic/old@1"}}]}]}))
            (root / "trivy-after-full.json").write_text(json.dumps({"Results": [{"Packages": [
                {"Name": "deb", "Version": "2", "Identifier": {"PURL": "pkg:deb/debian/deb@2-1?arch=amd64"}},
                {"Name": "lang", "Version": "3", "Identifier": {"PURL": "pkg:pypi/lang@3"}},
            ], "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2026-0001", "PkgIdentifier": {"PURL": "pkg:deb/debian/deb@2-1?arch=amd64"}},
                {"VulnerabilityID": "CVE-2026-0001", "PkgIdentifier": {"PURL": "pkg:pypi/lang@3"}},
            ]}]}))
            cdx = root / "fixture-cdx.json"
            cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
                {"type": "operating-system", "name": "os"},
                {"type": "library", "name": "deb", "version": "2-1", "purl": "pkg:deb/debian/deb@2-1?arch=amd64"},
                {"type": "library", "name": "lang", "version": "3", "purl": "pkg:pypi/lang@3"}],
                "vulnerabilities": [{"id": "CVE-2026-0001", "affects": [
                    {"ref": "pkg:deb/debian/deb@2-1?arch=amd64"},
                    {"ref": "pkg:pypi/lang@3"},
                ]}]}))
            fake_trivy = root / "trivy"
            fake_trivy.write_text('#!/bin/sh\ncp "$CDX_FIXTURE" trivy-full.cdx.json\n')
            fake_trivy.chmod(0o755)
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", CDX_FIXTURE=str(cdx),
                       PATCHED_DIGEST=DIGEST_B, RESUME_DIGEST="", RECOVERED_DIGEST="",
                       SELECTED_DIGEST=DIGEST_A, UPSTREAM_REF="registry.example/app",
                       GITHUB_OUTPUT=str(root / "output"), GITHUB_STEP_SUMMARY=str(root / "summary"))
            select = subprocess.run(["bash", "-c", by_name["Select the exact final candidate"]["run"]], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(select.returncode, 0, select.stdout + select.stderr)
            convert = by_name["Convert full report to CycloneDX with parity check"]["run"]
            result = subprocess.run(["bash", "-c", convert], cwd=root, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            cdx.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [{"type": "library", "name": "old", "version": "1"}], "vulnerabilities": []}))
            result = subprocess.run(["bash", "-c", convert], cwd=root, env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("components differ", result.stdout)

    def test_trivy_result_counts_treat_null_as_empty(self) -> None:
        self.assertEqual(
            self.workflow.count("((.Results // [])[] | .Vulnerabilities[]?)"), 3
        )

    def test_dispatch_exposes_force_and_recovery_modes(self) -> None:
        for text in (
            "force_repromote:",
            "recover_tag:",
            "recovery_run_id:",
            "accepted_candidate_run_id:",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)

    def test_kev_block_preserves_candidate_for_acceptance_resume(self) -> None:
        workflow = self.loaded_workflow()
        candidate_job = workflow["jobs"]["validate"]
        self.assertEqual(
            candidate_job["permissions"],
            {
                "contents": "read",
                "actions": "read",
                "packages": "read",
                "pull-requests": "read",
                "issues": "read",
            },
        )
        entry = next(
            step
            for step in candidate_job["steps"]
            if step["name"] == "Resolve inventory entry and validation params"
        )["run"]
        for text in (
            "force_repromote and accepted_candidate_run_id cannot be combined",
            "recover inputs and accepted_candidate_run_id cannot be combined",
            "accepted_candidate_run_id must be numeric",
        ):
            with self.subTest(text=text):
                self.assertIn(text, entry)
        policy = next(
            step
            for step in candidate_job["steps"]
            if step["name"] == "Evaluate one promotion decision"
        )
        self.assertTrue(policy["continue-on-error"])
        candidate_text = self.workflow.split("  validate:\n", 1)[1].split(
            "\n  promote:\n", 1
        )[0]
        self.assertLess(
            candidate_text.index("name: candidate\n"),
            candidate_text.index("Fail blocked candidate after preservation"),
        )

    def test_acceptance_resume_reuses_exact_preserved_bytes(self) -> None:
        workflow = self.loaded_workflow()
        steps = workflow["jobs"]["validate"]["steps"]
        by_name = {step["name"]: step for step in steps}
        restore = by_name["Restore the exact accepted candidate"]
        self.assertEqual(restore["if"], "inputs.accepted_candidate_run_id != ''")
        self.assertIn(
            "python3 scripts/promote_resume_artifact_id.py",
            restore["run"],
        )
        self.assertIn(
            "python3 scripts/promote_resume_candidate.py",
            restore["run"],
        )
        artifact_id = (SCRIPTS / "promote_resume_artifact_id.py").read_text(
            encoding="utf-8"
        )
        candidate = (SCRIPTS / "promote_resume_candidate.py").read_text(
            encoding="utf-8"
        )
        for text in ('.get("expired") is False',):
            with self.subTest(text=text):
                self.assertIn(text, artifact_id)
        for text in (
            "SHA256SUMS",
            "path traversal",
            "is_symlink()",
            "undeclared files",
            'decision.get("reason") != "missing_kev_acceptance"',
            "candidate-oci",
        ):
            with self.subTest(text=text):
                self.assertIn(text, candidate)
        copa = by_name["Run pinned Copa from the original child"]
        self.assertIn("inputs.accepted_candidate_run_id == ''", copa["if"])
        after = by_name["Rescan the exact preserved accepted bytes with the frozen DB"]
        self.assertIn("inputs.accepted_candidate_run_id != ''", after["if"])
        recovered = by_name["Materialize the exact recovered candidate"]
        self.assertIn("resume-final.tar", recovered["run"])
        self.assertNotIn("recovery-final.tar", recovered["run"])
        self.assertEqual(after["with"]["input"], "resume-final.tar")
        policy_script = (SCRIPTS / "promote_candidate_decision.py").read_text(
            encoding="utf-8"
        )
        for text in ("--acceptance", "--github-evidence", "--github-repository"):
            with self.subTest(text=text):
                self.assertIn(text, policy_script)
        evidence = (SCRIPTS / "promote_github_evidence.py").read_text(encoding="utf-8")
        for text in (
            '"base_repository": value["base"]["repo"]["full_name"]',
            '"is_pull_request": "pull_request" in value',
            "acceptance commit does not bind the current file bytes",
        ):
            with self.subTest(text=text):
                self.assertIn(text, evidence)
        risk = by_name["Resolve current KEV risk acceptance"]["run"]
        self.assertIn('[ "${CURL_STATUS}" -eq 22 ] && [ "${STATUS}" = 404 ]', risk)
        validation = by_name["Run validation"]["run"]
        self.assertIn(
            '--local-image "${CANDIDATE_REF}" --local-image-id "${LOCAL_IMAGE_ID}"',
            validation,
        )
        self.assertIn(
            "steps.patched.outputs.image_id",
            by_name["Run validation"]["env"]["LOCAL_IMAGE_ID"],
        )

    def test_resume_publishes_only_when_destination_is_absent_or_identical(
        self,
    ) -> None:
        workflow = self.loaded_workflow()
        steps = workflow["jobs"]["promote"]["steps"]
        by_name = {step["name"]: step for step in steps}
        occupancy = by_name["Assert destination tag is absent or byte-identical"]
        copy = by_name["Digest-preserving copy to GHCR"]
        verify = by_name["Verify candidate artifact"]
        for key in (
            "RESUME_ORIGINAL_RUN_ATTEMPT",
            "RESUME_ORIGINAL_SOURCE_SHA",
            "RESUME_ARTIFACT_ID",
        ):
            with self.subTest(env=key):
                self.assertIn(key, verify["env"])
        integrity = (SCRIPTS / "promote_decision_integrity.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            'api_run.get("path") != ".github/workflows/promote.yaml"', integrity
        )
        self.assertIn(
            'api_artifact.get("workflow_run", {}).get("id") != int(accepted_run)',
            integrity,
        )
        self.assertIn('"${STATUS}" = 404', occupancy["run"])
        self.assertIn('[ "${TOKEN_STATUS}" = "403" ]', occupancy["run"])
        self.assertIn('any(.code == "DENIED")', occupancy["run"])
        self.assertIn("destination package does not exist yet", occupancy["run"])
        self.assertIn('echo "skip_copy=false" >> "$GITHUB_OUTPUT"', occupancy["run"])
        self.assertIn('"${PUSHED}" != "${CANDIDATE_DIGEST}"', occupancy["run"])
        self.assertIn("conflicting occupied tag", occupancy["run"])
        self.assertEqual(copy["if"], "steps.occupancy.outputs.skip_copy != 'true'")

    def test_workflow_contains_no_inline_python_heredocs(self) -> None:
        self.assertNotIn("<<'PY'", self.workflow)
        self.assertNotIn("python3 - <<", self.workflow)

    def test_validation_still_gates_promotion(self) -> None:
        self.assertIn(
            "candidate:\n    uses: ./.github/workflows/promote-candidate.yaml",
            self.orchestrator,
        )
        self.assertIn("publish:\n    needs: candidate", self.orchestrator)
        self.assertIn(
            "uses: ./.github/workflows/promote-publish.yaml", self.orchestrator
        )
        self.assertIn("cancel-in-progress: true", self.orchestrator)

    def test_registry_reads_and_copy_fail_closed(self) -> None:
        for text in (
            "--observations registry-observations.json",
            "Assert destination tag is absent or byte-identical",
            "curl --fail-with-body",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)
        self.assertIn(
            'rel="next"',
            (SCRIPTS / "promote_registry_next_link.py").read_text(encoding="utf-8"),
        )
        self.assertNotIn("tags/list?n=1000", self.workflow)

    def test_absent_destination_package_is_an_explicit_first_run_case(self) -> None:
        workflow = yaml.safe_load(self.candidate_workflow)
        tag_step = next(
            step
            for step in workflow["jobs"]["validate"]["steps"]
            if step["name"] == "Compute internal tag and detect skip"
        )
        run = tag_step["run"]
        for text in (
            '[ "${TOKEN_STATUS}" = "403" ]',
            'any(.code == "DENIED")',
            "GHCR package is not created yet",
            'if [ -z "${TOKEN}" ]; then',
            'URL=""',
            "FATAL: GHCR token request failed",
            '${AUTH[@]+"${AUTH[@]}"}',
        ):
            with self.subTest(text=text):
                self.assertIn(text, run)

    def test_registry_artifacts_come_from_verbatim_oci_blobs(self) -> None:
        workflow = self.loaded_workflow()
        steps = workflow["jobs"]["validate"]["steps"]
        fetch = next(step for step in steps if step["name"] == "Fetch upstream index")[
            "run"
        ]
        resolve = next(
            step
            for step in steps
            if step["name"] == "Resolve the exact linux/amd64 child"
        )["run"]
        self.assertIn("inspect --raw", fetch)
        self.assertIn(
            '"docker://${UPSTREAM_REF}@${UPSTREAM_DIGEST}" > upstream-index.json',
            fetch,
        )
        self.assertNotIn("copy --all", fetch)
        self.assertIn("CREDS=(--creds", fetch)
        self.assertNotIn("--src-creds", fetch)
        self.assertIn("copy --preserve-digests", resolve)
        self.assertIn(
            '"docker://${UPSTREAM_REF}@${SELECTED_DIGEST}" "oci:/workspace/upstream-oci:child"',
            resolve,
        )
        self.assertLess(
            resolve.index("copy --preserve-digests"),
            resolve.index('cp "upstream-oci/blobs/sha256/${SELECTED_DIGEST#sha256:}" child-manifest.json'),
        )
        self.assertIn(
            'cp "upstream-oci/blobs/sha256/${SELECTED_DIGEST#sha256:}" child-manifest.json',
            resolve,
        )
        self.assertIn(
            'cp "upstream-oci/blobs/sha256/${CONFIG_DIGEST#sha256:}" child-config.json',
            resolve,
        )
        self.assertNotIn("inspect --config", resolve)
        self.assertIn("'.Metadata.OS.EOSL != true'", self.workflow)
        self.assertNotIn("'.Metadata.OS.EOSL == false'", self.workflow)

    def test_skopeo_copy_writes_workspace_files_as_runner(self) -> None:
        self.assertIn(
            'docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/workspace "$SKOPEO"',
            self.workflow,
        )

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
        platform_step = self.workflow.split(
            "- name: Assert exact linux/amd64 manifest", 1
        )[1]
        platform_step = platform_step.split("- name:", 1)[0]
        self.assertNotIn("skip_copy != 'true'", platform_step)

    def test_candidate_job_is_read_only_and_drives_publisher(self) -> None:
        caller = yaml.safe_load(self.orchestrator)
        rank = {"read": 0, "write": 1}
        for workflow in (
            yaml.safe_load(self.candidate_workflow),
            yaml.safe_load(self.publisher_workflow),
        ):
            for scope, level in workflow["permissions"].items():
                self.assertIn(scope, caller["permissions"])
                self.assertLessEqual(
                    rank[level], rank[caller["permissions"][scope]]
                )
        candidate = self.workflow.split("  validate:\n", 1)[1].split(
            "\n  promote:\n", 1
        )[0]
        publisher = self.workflow.split("\n  promote:\n", 1)[1]
        self.assertIn("packages: read", candidate)
        self.assertIn("packages: write", publisher)
        self.assertIn("publish:\n    needs: candidate", self.orchestrator)
        self.assertIn(
            "uses: ./.github/workflows/promote-publish.yaml", self.orchestrator
        )
        self.assertIn(
            "${{ needs.candidate.outputs.candidate_manifest_sha256 }}", self.orchestrator
        )
        self.assertNotIn("jobs.candidate.outputs", self.orchestrator)
        for text in (
            "scripts/evaluate_promotion.py",
            "known_exploited_vulnerabilities.json",
            "list-all-pkgs: 'true'",
            "candidate-decision.json",
            "SHA256SUMS",
            "retention-days: 8",
        ):
            with self.subTest(text=text):
                self.assertIn(text, candidate)
        self.assertIn("Verify candidate artifact", publisher)
        self.assertNotIn("                --all \\\n", self.workflow)
        self.assertNotIn("platform: linux/amd64", candidate)

    def test_copa_classification_follows_inline_success_or_original_decision(
        self,
    ) -> None:
        policy = (SCRIPTS / "promote_candidate_decision.py").read_text(encoding="utf-8")
        self.assertIn(
            'classification = original["copa"]["classification"] if original else "succeeded"',
            policy,
        )
        self.assertNotIn('else "not-required"', self.workflow)

    def test_pinned_copa_path_patches_final_bytes_before_publication(self) -> None:
        steps = self.loaded_workflow()["jobs"]["validate"]["steps"]
        by_name = {step["name"]: step for step in steps}
        copa = by_name["Run pinned Copa from the original child"]
        self.assertEqual(
            copa["uses"],
            "project-copacetic/copa-action@7de81b0830c8a4d1edb4a63a77e65a6d7ef8dc95",
        )
        self.assertEqual(str(copa["with"]["copa-version"]), "0.15.0")
        self.assertEqual(copa["with"]["patched-tag"], "copa:candidate")
        self.assertEqual(copa["with"]["image-report"], "trivy-copa.json")
        self.assertEqual(
            copa["with"]["image"],
            "${{ steps.entry.outputs.upstream_ref }}@${{ steps.child.outputs.digest }}",
        )
        self.assertNotIn("severity", copa["if"])
        patched = by_name["Add only provenance labels and export final bytes"]
        self.assertEqual(patched["if"], copa["if"])
        allocation = by_name["Allocate the immutable patched revision before metadata"]
        self.assertIn("--force-repromote", allocation["run"])
        self.assertIn("skip_copy=false", allocation["run"])
        self.assertIn(
            "steps.patchtag.outputs.internal_tag",
            by_name["Add only provenance labels and export final bytes"]["env"][
                "INTERNAL_TAG"
            ],
        )
        pin = by_name["Pin and verify the Copa action runtime"]["run"]
        self.assertIn(
            "b20772e7b2ec82d94d5350a2e70f9281ce70fc7296d1f839f3f1cc38d605995b", pin
        )
        self.assertIn("sha256sum -c", pin)
        diagnostics = by_name["Capture Copa diagnostics and fail closed"]["run"]
        self.assertIn("docker logs copa-action", diagnostics)
        self.assertNotIn("docker run", diagnostics)
        scan = by_name["Rescan the exact patched bytes with the frozen DB"]
        self.assertEqual(scan["with"]["input"], "candidate-final.tar")
        self.assertEqual(scan["env"]["TRIVY_SKIP_DB_UPDATE"], "true")
        self.assertEqual(scan["env"]["TRIVY_EXIT_ON_EOL"], "1")
        self.assertEqual(scan["with"]["list-all-pkgs"], "true")
        policy = by_name["Evaluate one promotion decision"]
        self.assertIn("CANDIDATE_DIGEST", policy["env"])
        policy_script = (SCRIPTS / "promote_candidate_decision.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("--full-report", policy_script)
        self.assertIn("trivy-before-full.json", policy_script)
        self.assertIn(
            "trivy-full.cdx.json\n            secobserve-upload.json", self.workflow
        )

    def test_patched_metadata_uses_a_stopped_container_and_emits_digest(self):
        workflow = yaml.safe_load(self.candidate_workflow)
        steps = workflow["jobs"]["validate"]["steps"]
        step = next(
            step
            for step in steps
            if step["name"] == "Add only provenance labels and export final bytes"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "docker"
            executable.write_text("""#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['SPOOL'], 'a') as fh: fh.write(json.dumps(args) + '\\n')
if args[:2] == ['image', 'inspect']:
    if args[-1] == '{{.Id}}':
        print('sha256:' + 'd' * 64)
    else:
        print('{}')
elif args[0] == 'create': print('metadata-container')
elif args[0] == 'commit':
    if args[-2] != 'metadata-container': sys.exit('commit requires a container')
    print('sha256:config')
elif args[0] == 'save':
    from pathlib import Path
    Path(args[args.index('--output') + 1]).write_text('final bytes')
elif args[0] == 'run':
    import hashlib
    from pathlib import Path as P
    layout = P(os.environ.get('PWD', '.')) / 'candidate-oci' / 'index.json'
    layout.parent.mkdir(parents=True, exist_ok=True)
    if not layout.exists():
        manifest_text = '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}'
        digest = 'sha256:' + hashlib.sha256(manifest_text.encode()).hexdigest()
        blob_dir = layout.parent / 'blobs' / 'sha256'
        blob_dir.mkdir(parents=True, exist_ok=True)
        P(blob_dir / digest.split(':')[1]).write_text(manifest_text)
        layout.write_text('{"manifests":[{"digest":"' + digest + '"}]}')
    print(layout.read_text())
""")
            executable.chmod(0o755)
            (root / "scripts").symlink_to(
                REPO_ROOT / "scripts", target_is_directory=True
            )
            env = dict(
                os.environ,
                PATH=f"{root}:{os.environ['PATH']}",
                SPOOL=str(root / "spool"),
                SKOPEO_IMAGE=workflow["env"]["SKOPEO_IMAGE"],
                GITHUB_OUTPUT=str(root / "output"),
                UPSTREAM_REF="registry.example/app",
                UPSTREAM_TAG="v1",
                SELECTED_DIGEST=DIGEST_A,
                INTERNAL_TAG="v1-bocklabs.1",
            )
            self.assertNotIn("${{", step["run"])
            result = subprocess.run(
                ["bash", "-c", step["run"]],
                cwd=root,
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            output = (root / "output").read_text()
            self.assertRegex(output, r"(?m)^digest=sha256:[a-f0-9]{64}\n")
            self.assertRegex(output, r"(?m)^image_id=sha256:[a-f0-9]{64}\n")
            calls = [
                json.loads(line) for line in (root / "spool").read_text().splitlines()
            ]
            self.assertTrue(any(call[:1] == ["create"] for call in calls))
            self.assertTrue(any(call[:1] == ["rm"] for call in calls))

    def test_copa_diagnostics_classify_failures_and_redact_credentials(self):
        steps = self.loaded_workflow()["jobs"]["validate"]["steps"]
        step = next(
            step
            for step in steps
            if step["name"] == "Capture Copa diagnostics and fail closed"
        )
        cases = {
            "unsupported OS": "unsupported",
            "nothing to patch": "no-fix",
            "end of life distro": "eol",
            "unsupported OS; GPG signature verification failed": "gpg",
            "unexpected panic": "unknown",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "docker"
            executable.write_text(
                "#!/usr/bin/env python3\nimport os, sys\nprint(os.environ['LOG'] if sys.argv[1] == 'logs' else 'runtime-id')\n"
            )
            executable.chmod(0o755)
            (root / "copa-action-image-id.txt").write_text("runtime-id\n")
            for message, classification in cases.items():
                with self.subTest(classification=classification):
                    env = dict(
                        os.environ,
                        PATH=f"{root}:{os.environ['PATH']}",
                        COPA_OUTCOME="failure",
                        LOG=message
                        + " https://user:secret@example.com password=private Bearer hidden-token",
                    )
                    result = subprocess.run(
                        ["bash", "-c", step["run"]],
                        cwd=root,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        result.returncode, 1, result.stdout + result.stderr
                    )
                    diagnostic = (root / "copa-diagnostics.txt").read_text()
                    self.assertIn(f"classification={classification}", diagnostic)
                    for secret in ("user:secret", "private", "hidden-token"):
                        self.assertNotIn(secret, diagnostic)

    def test_provenance_writeback_is_scoped_and_reusable(self) -> None:
        for text in (
            "MEDIA_TYPE: application/vnd.oci.image.index.v1+json",
            '--upstream-child-digest "${SELECTED_CHILD_DIGEST}"',
            'git add "provenance/${APP}/${INTERNAL_TAG}.json"',
            "git diff --cached --quiet",
            "--force-with-lease=refs/heads/${BRANCH}:",
            "--state all",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)
        self.assertNotIn("git add provenance/", self.workflow)

    def test_publisher_requires_verified_signing_for_success_or_quarantine(self) -> None:
        steps = self.loaded_workflow()["jobs"]["promote"]["steps"]
        by_name = {step["name"]: step for step in steps}
        quarantine = by_name["Record quarantined publication after failed verification"]
        self.assertIn("probe.outputs.result == 'pass'", quarantine["if"])
        self.assertIn("signing-gate.outcome == 'failure'", quarantine["if"])
        self.assertIn(".eligible = false", quarantine["run"])
        self.assertIn(".published.digest", quarantine["run"])
        provenance = by_name["Generate provenance record"]
        self.assertIn("quarantine-decision.outcome == 'success'", provenance.get("if", ""))
        self.assertIn("--signing-evidence", provenance["run"])
        self.assertIn("--signing-result", provenance["run"])
        self.assertIn("signing-gate.outcome == 'success'", by_name["Verify merged provenance and publish the final decision"].get("if", ""))
        for name in ("Mint bocklabs-release app token", "Open provenance PR and enable merge"):
            self.assertIn("quarantine-decision.outcome == 'success'", by_name[name].get("if", ""))
        self.assertEqual(by_name["Job summary evidence panel"]["run"].count("promotion unsuccessful"), 2)
        self.assertNotIn("cosign attest", self.publisher_workflow[self.publisher_workflow.index("Generate provenance record"):])
        self.assertNotIn("gh api -X DELETE", self.publisher_workflow)

    def test_same_child_reuse_and_patch_recovery_preserve_identity(self) -> None:
        for text in (
            "--selected-child-digest",
            "selected_child_digest",
            "--recover-candidate-digest",
            "Materialize the exact recovered candidate",
            "original-child patching cannot recover",
        ):
            with self.subTest(text=text):
                self.assertIn(text, self.workflow)
        observations = (SCRIPTS / "promote_registry_observations.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("upstream_index_digest", observations)
        self.assertNotIn(
            "--recover-tag",
            self.workflow[self.workflow.index("Digest-preserving copy to GHCR") :],
        )

    def test_decision_writers_and_evidence_rendering_are_bounded(self) -> None:
        workflow = self.loaded_workflow()
        steps = workflow["jobs"]["promote"]["steps"]
        names = {step["name"] for step in steps}
        self.assertIn("Write the verified publication digest into the decision", names)
        self.assertIn("Verify merged provenance and publish the final decision", names)
        summary = (SCRIPTS / "promote_summary.py").read_text(encoding="utf-8")
        pr = (SCRIPTS / "promote_provenance_body.py").read_text(encoding="utf-8")
        steps_text = next(
            step for step in steps if step["name"] == "Job summary evidence panel"
        )["run"]
        self.assertIn("python3 scripts/promote_summary.py", steps_text)
        for text in (
            "Before/final CVE evidence",
            "Package changes",
            "Warnings",
            "KEV snapshot",
            "Acceptance expiry",
        ):
            self.assertIn(text, summary)
            self.assertIn(text, pr)
        self.assertIn("name: candidate-decision", self.workflow)


if __name__ == "__main__":
    unittest.main()


class CleanChildTracerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.spool = self.tmp / "argv.jsonl"
        self.child = self.tmp / "child-manifest.json"
        child_value = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {},
        }
        config_value = {"architecture": "amd64", "os": "linux"}
        self.child.write_text(
            json.dumps(child_value, indent=2) + "\n", encoding="utf-8"
        )
        child_digest = (
            "sha256:"
            + hashlib.sha256(
                (json.dumps(child_value, indent=2) + "\n").encode()
            ).hexdigest()
        )
        config_digest = (
            "sha256:"
            + hashlib.sha256(
                (json.dumps(config_value, indent=2) + "\n").encode()
            ).hexdigest()
        )
        child_value["config"] = {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": len(json.dumps(config_value, indent=2).encode()) + 1,
        }
        self.child.write_text(
            json.dumps(child_value, indent=2) + "\n", encoding="utf-8"
        )
        child_digest = (
            "sha256:"
            + hashlib.sha256(
                (json.dumps(child_value, indent=2) + "\n").encode()
            ).hexdigest()
        )
        self.index = self.tmp / "upstream-index.json"
        self.index.write_text(
            json.dumps(
                {
                    "schemaVersion": 2,
                    "mediaType": "application/vnd.oci.image.index.v1+json",
                    "manifests": [
                        {
                            "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": child_digest,
                            "size": self.child.stat().st_size,
                            "platform": {"os": "linux", "architecture": "amd64"},
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.index_digest = (
            "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        )
        self.config = self.tmp / "child-config.json"
        self.config.write_text(
            json.dumps(config_value, indent=2) + "\n", encoding="utf-8"
        )
        self.full = self.tmp / "trivy-full.json"
        self.full.write_text(
            json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8"
        )
        self.fixable = self.tmp / "trivy-fixable.json"
        self.fixable.write_text(
            json.dumps({"SchemaVersion": 2, "Results": []}), encoding="utf-8"
        )
        self.kev = self.tmp / "kev.json"
        self.kev.write_text(
            json.dumps(
                {
                    "title": "CISA Catalog of Known Exploited Vulnerabilities",
                    "catalogVersion": "2026.09.13",
                    "dateReleased": "2026-09-13T00:00:00.00000Z",
                    "count": 0,
                    "vulnerabilities": [],
                }
            ),
            encoding="utf-8",
        )
        self.decision = self.tmp / "candidate-decision.json"
        self.provenance = self.tmp / "provenance.json"

    def write_fake(self, name, body):
        path = self.bin / name
        path.write_text("#!/usr/bin/env python3\n" + body, encoding="utf-8")
        path.chmod(0o755)
        return path

    def run_cli(self, argv):
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["FAKE_SPOOL"] = str(self.spool)
        return subprocess.run(argv, capture_output=True, text=True, env=env)

    def blocked_candidate_artifact(self):
        from tests.test_policy import kev_feed, report, vuln, write_json

        artifact = self.tmp / "preserved-candidate"
        if artifact.exists():
            shutil.rmtree(artifact)
        artifact.mkdir()
        finding = vuln("CVE-2026-0001")
        full = write_json(artifact / "trivy-full.json", report([finding]))
        fixable = write_json(artifact / "trivy-copa.json", report())
        write_json(artifact / "trivy-before-full.json", report([finding]))
        write_json(artifact / "trivy-full.cdx.json", {"vulnerabilities": []})
        write_json(artifact / "secobserve-upload.json", {"app": "app"})
        write_json(
            artifact / "validation-evidence.json", {"validation": {"result": "pass"}}
        )
        write_json(artifact / "kev.json", kev_feed(("CVE-2026-0001",)))
        (artifact / "kev-fetched-at.txt").write_text("2026-09-14T00:00:00Z\n")
        (artifact / "trivy-db-meta-1.txt").write_text("DB\n")
        (artifact / "trivy-db-meta-2.txt").write_text("DB\n")
        (artifact / "source.sha").write_text("a" * 40 + "\n")
        (artifact / "inventory-image.yaml").write_text(
            "spec:\n  upstream:\n    ref: registry.example/app\n    tag: v1\n    digest: "
            + self.index_digest
            + "\n"
            "  destination:\n    package: ghcr.io/bocklabs/app\n  patchPolicy: enabled\n",
            encoding="utf-8",
        )
        write_json(
            artifact / "tag-decision.json",
            {"internal_tag": "v1-bocklabs.1", "skip_copy": False},
        )
        shutil.copyfile(self.child, artifact / "child-manifest.json")
        shutil.copyfile(self.child, artifact / "candidate-manifest.json")
        shutil.copyfile(self.config, artifact / "child-config.json")
        shutil.copyfile(self.index, artifact / "upstream-index.json")
        blob = (
            artifact
            / "candidate-oci"
            / "blobs"
            / "sha256"
            / self._child_digest().split(":", 1)[1]
        )
        blob.parent.mkdir(parents=True)
        shutil.copyfile(self.child, blob)
        (artifact / "candidate-oci" / "oci-layout").write_text(
            '{"imageLayoutVersion":"1.0.0"}\n'
        )
        write_json(artifact / "candidate-oci" / "index.json", {"manifests": []})
        decision = artifact / "candidate-decision.json"
        result = self.run_cli(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "evaluate_promotion.py"),
                "--app",
                "app",
                "--source-sha",
                "a" * 40,
                "--run-id",
                "123",
                "--run-attempt",
                "1",
                "--proposed-tag",
                "v1-bocklabs.1",
                "--index",
                str(self.index),
                "--upstream-index-digest",
                self.index_digest,
                "--child-manifest",
                str(self.child),
                "--child-config",
                str(self.config),
                "--full-report",
                str(full),
                "--fixable-report",
                str(fixable),
                "--kev",
                str(artifact / "kev.json"),
                "--kev-fetched-at",
                "2026-09-14T00:00:00Z",
                "--now",
                "2026-09-14T01:00:00Z",
                "--validation-result",
                "pass",
                "--out",
                str(decision),
            ]
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(decision.read_text())["reason"], "missing_kev_acceptance"
        )
        subprocess.run(
            [
                "bash",
                "-c",
                "find . -type f ! -name SHA256SUMS -printf '%P\\0' | sort -z | xargs -0 sha256sum > SHA256SUMS",
            ],
            capture_output=True,
            check=True,
            cwd=artifact,
        )
        return artifact

    def _child_digest(self):
        return "sha256:" + hashlib.sha256(self.child.read_bytes()).hexdigest()

    def fake_gh(self, fixture, run_id=123):
        return self.write_fake(
            "gh",
            f"""import json, shutil, sys
args=sys.argv[1:]
if args[:1] == ['api']:
    url=next((arg for arg in args if arg.startswith('repos/')), '')
    if '/artifacts' in url:
        print(json.dumps({{'id':9001,'name':'candidate','expired':False,'workflow_run':{{'id':{run_id}}}}}))
    elif '/branches/main' in url:
        print(json.dumps({{'name':'main','commit':{{'sha':'{"a"*40}'}},'protected':True}}))
    elif '/actions/runs/{run_id}' in url:
        print(json.dumps({{'id':{run_id},'repository':{{'full_name':'bocklabs/trusted-images'}},'path':'.github/workflows/promote.yaml','event':'workflow_dispatch','head_branch':'main','head_sha':'{"a"*40}','run_attempt':1,'status':'completed','conclusion':'failure'}}))
    else:
        print({{}})
elif args[:2] == ['run', 'download']:
    shutil.copytree(r'{fixture}', args[args.index('--dir')+1], dirs_exist_ok=True)
""",
        )

    def test_blocked_candidate_resume_command_exact_tampered_and_wrong_run(self):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        step = next(
            step
            for step in steps
            if step["name"] == "Restore the exact accepted candidate"
        )
        fixture = self.blocked_candidate_artifact()
        (self.tmp / "scripts").symlink_to(
            REPO_ROOT / "scripts", target_is_directory=True
        )
        (self.tmp / "inventory" / "app").mkdir(parents=True)
        shutil.copyfile(
            fixture / "inventory-image.yaml",
            self.tmp / "inventory" / "app" / "image.yaml",
        )
        self.fake_gh(fixture)
        env = dict(os.environ, **{key: "" for key in step["env"]})
        env.update(
            PATH=f"{self.bin}:{Path(sys.executable).parent}:{os.environ['PATH']}",
            ACCEPTED_CANDIDATE_RUN_ID="123",
            GH_TOKEN="test-token",
            REPO="bocklabs/trusted-images",
            APP="app",
            GITHUB_REPOSITORY="bocklabs/trusted-images",
            GITHUB_OUTPUT=str(self.tmp / "github-output"),
        )
        result = subprocess.run(
            ["bash", "-c", step["run"]],
            cwd=self.tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = (self.tmp / "github-output").read_text()
        for text in (
            "candidate_digest=",
            "selected_child_digest=",
            "internal_tag=v1-bocklabs.1",
            "skip_copy=false",
        ):
            self.assertIn(text, output)
        self.assertTrue((self.tmp / "candidate-oci").is_dir())

        (fixture / "undeclared.txt").write_text("tampered\n")
        subprocess.run(
            [
                "bash",
                "-c",
                "find . -type f ! -name SHA256SUMS -printf '%P\\0' | sort -z | xargs -0 sha256sum > SHA256SUMS",
            ],
            cwd=fixture,
            capture_output=True,
            check=True,
        )
        self.fake_gh(fixture)
        env["GITHUB_OUTPUT"] = str(self.tmp / "tampered-output")
        result = subprocess.run(
            ["bash", "-c", step["run"]],
            cwd=self.tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("undeclared files", result.stdout + result.stderr)
        self.assertFalse((self.tmp / "tampered-output").exists())

        exact_fixture = self.blocked_candidate_artifact()
        self.fake_gh(exact_fixture, run_id=999)
        env["GITHUB_OUTPUT"] = str(self.tmp / "wrong-run-output")
        result = subprocess.run(
            ["bash", "-c", step["run"]],
            cwd=self.tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("wrong run", result.stdout + result.stderr)
        self.assertFalse((self.tmp / "wrong-run-output").exists())

    def test_failed_patched_runtime_validation_never_executes_publication(self):
        from tests.test_validate_image import FAKE_DOCKER

        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["validate"]["steps"]
        step = next(step for step in steps if step["name"] == "Run validation")
        self.assertNotIn("continue-on-error", step)
        self.write_fake("docker", FAKE_DOCKER.split("\n", 1)[1])
        scenario = self.tmp / "scenario.json"
        committed_image_id = "sha256:" + "d" * 64
        scenario.write_text(
            json.dumps(
                {
                    "image_inspect": [
                        {
                            "Id": committed_image_id,
                            "Os": "linux",
                            "Architecture": "amd64",
                            "Config": {"Entrypoint": ["/app"], "Cmd": None, "Env": []},
                        }
                    ],
                    "inspect_states": [{"State": {"Running": False}}],
                }
            )
        )
        (self.tmp / "candidate-manifest.json").write_bytes(self.child.read_bytes())
        (self.tmp / "scripts").symlink_to(
            REPO_ROOT / "scripts", target_is_directory=True
        )
        publisher = self.write_fake(
            "skopeo", "from pathlib import Path\nPath('published').write_text('ran')\n"
        )
        env = dict(os.environ, **{key: "" for key in step["env"]})
        env.update(
            PATH=f"{self.bin}:{Path(sys.executable).parent}:{os.environ['PATH']}",
            FAKE_DOCKER_SPOOL=str(self.spool),
            FAKE_DOCKER_SCENARIO=str(scenario),
            APP="app",
            UPSTREAM_REF="registry.example/app",
            SELECTED_DIGEST=DIGEST_A,
            CANDIDATE_REF="copa:final",
            CANDIDATE_DIGEST="sha256:"
            + hashlib.sha256(self.child.read_bytes()).hexdigest(),
            LOCAL_IMAGE_ID=committed_image_id,
            PATCHED="true",
            VALIDATION_TYPE="process",
            VALIDATION_DURATION_SECONDS="0",
        )
        result = subprocess.run(
            ["bash", "-c", step["run"] + "\n" + str(publisher) + " copy"],
            cwd=self.tmp,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        evidence = json.loads((self.tmp / "validation-evidence.json").read_text())
        self.assertEqual(evidence["validation"]["result"], "fail")
        self.assertIn("container not running", result.stdout)
        self.assertFalse((self.tmp / "published").exists())
        calls = [json.loads(line) for line in self.spool.read_text().splitlines()]
        self.assertTrue(
            any(call[0] == "run" and committed_image_id in call for call in calls)
        )

    def test_clean_child_reaches_publisher_only_after_policy_validation_and_provenance(
        self,
    ):
        docker = self.write_fake(
            "docker",
            """import json, os\nspool=os.environ["FAKE_SPOOL"]\nargs=sys.argv[1:] if False else None\n""",
        )
        # The validator suite owns the detailed fake-docker behavior; this tracer only needs its pass evidence.
        docker.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ['FAKE_SPOOL'], 'a') as fh: fh.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1:3] == ['image', 'inspect']:
    print(json.dumps([{'Os':'linux','Architecture':'amd64','Config':{'Entrypoint':['/app'],'Cmd':None,'Env':[]}}]))
elif sys.argv[1] == 'inspect': print(json.dumps([{'State':{'Running':True}}]))
elif sys.argv[1] == 'run': print('container')
else: print('')
""")
        policy = self.run_cli(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "evaluate_promotion.py"),
                "--app",
                "app",
                "--source-sha",
                "a" * 40,
                "--run-id",
                "123",
                "--run-attempt",
                "1",
                "--proposed-tag",
                "v1-bocklabs.1",
                "--index",
                str(self.index),
                "--upstream-index-digest",
                self.index_digest,
                "--child-manifest",
                str(self.child),
                "--child-config",
                str(self.config),
                "--full-report",
                str(self.full),
                "--fixable-report",
                str(self.fixable),
                "--kev",
                str(self.kev),
                "--kev-fetched-at",
                "2026-09-14T00:00:00Z",
                "--now",
                "2026-09-14T01:00:00Z",
                "--validation-result",
                "pass",
                "--out",
                str(self.decision),
            ]
        )
        self.assertEqual(policy.returncode, 0, policy.stdout + policy.stderr)
        decision = json.loads(self.decision.read_text())
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["platform"], "linux/amd64")
        self.assertEqual(
            decision["candidate"]["digest"], decision["selected_child_digest"]
        )
        self.assertIsNone(decision["published"]["digest"])
        self.assertFalse(decision["provenance"]["merged"])

        evidence = self.tmp / "validation-evidence.json"
        validation = self.run_cli(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "validate_image.py"),
                "--app",
                "app",
                "--ref",
                "registry.example/app",
                "--digest",
                decision["candidate"]["digest"],
                "--baseline-ref",
                "registry.example/app",
                "--baseline-digest",
                decision["selected_child_digest"],
                "--validation-type",
                "process",
                "--index-file",
                str(self.child),
                "--evidence-out",
                str(evidence),
                "--duration-seconds",
                "0",
            ]
        )
        self.assertEqual(
            validation.returncode, 0, validation.stdout + validation.stderr
        )

        decision["published"]["digest"] = decision["candidate"]["digest"]
        self.decision.write_text(json.dumps(decision), encoding="utf-8")
        identity = json.loads((REPO_ROOT / "config" / "signing-identity.json").read_text())
        rekor = {"log_index": 1, "log_id": "log-id", "signed_entry_timestamp": "set", "inclusion_root_hash": None}
        signing = self.tmp / "signing-evidence.json"
        signing_files = {
            "sign-bundle.json": b"signature bundle", "signature-attachment.json": b"signature attachment",
            "sbom-bundle.json": b"SBOM bundle", "sbom-attestation-attachment.json": b"attestation attachment",
            "trivy-full.cdx.json": b'{"bomFormat":"CycloneDX","components":[]}',
        }
        for name, content in signing_files.items():
            (self.tmp / name).write_bytes(content)
        def sha(name):
            return hashlib.sha256(signing_files[name]).hexdigest()
        signing.write_text(json.dumps({
            "result": "pass", "image": f"ghcr.io/bocklabs/app@{decision['candidate']['digest']}",
            "digest": decision["candidate"]["digest"], **identity,
            "cosign_version": "v3.1.3", "trivy_version": "0.74.0",
            "signature": {"bundle_sha256": sha("sign-bundle.json"), "attachment_sha256": sha("signature-attachment.json"), "rekor": rekor},
            "sbom_attestation": {"predicate_type": "https://cyclonedx.org/bom", "predicate_sha256": sha("trivy-full.cdx.json"),
                                 "bundle_sha256": sha("sbom-bundle.json"), "attachment_sha256": sha("sbom-attestation-attachment.json"), "rekor": rekor},
        }))
        provenance = self.run_cli(
            [
                sys.executable,
                str(REPO_ROOT / "scripts" / "generate_provenance.py"),
                "--app",
                "app",
                "--upstream-ref",
                "registry.example/app",
                "--upstream-tag",
                "v1",
                "--upstream-digest",
                decision["upstream_index_digest"],
                "--upstream-child-digest",
                decision["selected_child_digest"],
                "--decision-sha256",
                hashlib.sha256(self.decision.read_bytes()).hexdigest(),
                "--decision",
                str(self.decision),
                "--before-report",
                str(self.full),
                "--final-report",
                str(self.full),
                "--fixable-report",
                str(self.fixable),
                "--kev-report",
                str(self.kev),
                "--now",
                "2026-09-14T01:00:00Z",
                "--media-type",
                "application/vnd.oci.image.index.v1+json",
                "--internal-package",
                "ghcr.io/bocklabs/app",
                "--internal-tag",
                "v1-bocklabs.1",
                "--internal-digest",
                decision["candidate"]["digest"],
                "--platforms",
                "linux/amd64",
                "--run-url",
                "https://example.invalid/runs/1",
                "--workflow",
                "promote",
                "--dispatched-by",
                "test",
                "--trivy-version",
                "0.74.0",
                "--trivy-action-sha",
                "a" * 40,
                "--skopeo-version",
                "1.22.2",
                "--skopeo-image-digest",
                "sha256:" + "b" * 64,
                "--trivy-db-check-bundle-digest",
                "sha256:" + "c" * 64,
                "--trivy-db-updated-at",
                "2026-09-14T00:00:00Z",
                "--full-report-sha256",
                hashlib.sha256(self.full.read_bytes()).hexdigest(),
                "--copa-report-sha256",
                hashlib.sha256(self.fixable.read_bytes()).hexdigest(),
                "--secobserve-product",
                "trusted-images",
                "--secobserve-origin",
                "app:v1",
                "--validation-type",
                "process",
                "--validation-result",
                "pass",
                "--validation-params",
                "{}",
                "--validation-timings",
                "{}",
                "--validation-health",
                "{}",
                "--validation-runner",
                "test",
                "--validation-entrypoint",
                "[]",
                "--validation-cmd",
                "[]",
                "--validation-env",
                "[]",
                "--signing-evidence",
                str(signing),
                "--signing-result",
                "pass",
                "--out",
                str(self.provenance),
            ]
        )
        self.assertEqual(
            provenance.returncode, 0, provenance.stdout + provenance.stderr
        )
        record = json.loads(self.provenance.read_text())
        self.assertEqual(
            record["upstream"]["digest"], decision["upstream_index_digest"]
        )
        self.assertEqual(
            record["upstream"]["selected_child_digest"],
            decision["selected_child_digest"],
        )
        self.assertEqual(record["internal"]["digest"], decision["candidate"]["digest"])
        self.assertEqual(
            decision["published"]["digest"], decision["candidate"]["digest"]
        )
        self.assertFalse(decision["provenance"]["merged"])

        skopeo = self.write_fake(
            "skopeo",
            """#!/usr/bin/env python3\nimport os, sys\nwith open(os.environ['FAKE_SPOOL'], 'a') as fh: fh.write(' '.join(sys.argv) + '\\n')\n""",
        )
        publisher = self.run_cli(
            [
                str(skopeo),
                "copy",
                "--dest-creds",
                "redacted",
                f"docker://registry.example/app@{decision['candidate']['digest']}",
                "docker://ghcr.io/bocklabs/app:v1-bocklabs.1",
            ]
        )
        self.assertEqual(publisher.returncode, 0, publisher.stdout + publisher.stderr)
        argv = self.spool.read_text().splitlines()[-1]
        self.assertNotIn("--all", argv.split())
        self.assertIn(decision["candidate"]["digest"], argv)
