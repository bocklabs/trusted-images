#!/usr/bin/env python3
"""Behavioral subprocess tests for the extracted promotion scripts."""

import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
APP = "app"
SOURCE_SHA = "a" * 40
RUN_ID = "123"
INTERNAL_TAG = "v1.2.3-bocklabs.1"
DIGEST_A = "sha256:" + "b" * 64
DIGEST_B = "sha256:" + "c" * 64
IMAGE_ID = "sha256:" + "d" * 64
CONFIG_VALUE = {
    "architecture": "amd64",
    "os": "linux",
    "rootfs": {"type": "layers", "diff_ids": []},
}


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    raw = json.dumps(value, indent=2) + "\n"
    return digest_bytes(raw.encode())


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def child_config() -> dict:
    return dict(CONFIG_VALUE)


def child_manifest() -> dict:
    encoded = json.dumps(CONFIG_VALUE, indent=2) + "\n"
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest_bytes(encoded.encode()),
            "size": len(encoded.encode()),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": DIGEST_A,
                "size": 456,
            }
        ],
    }


def index() -> dict:
    manifest = child_manifest()
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": manifest["mediaType"],
                "digest": digest(manifest),
                "size": len((json.dumps(manifest, indent=2) + "\n").encode()),
                "platform": {"os": "linux", "architecture": "amd64"},
            },
            {
                "mediaType": manifest["mediaType"],
                "digest": DIGEST_B,
                "size": 301,
                "platform": {"os": "linux", "architecture": "arm64"},
            },
        ],
    }


def inventory(app: str = APP) -> dict:
    return {
        "apiVersion": "trusted-images.bocklabs.dev/v1",
        "kind": "Image",
        "metadata": {"name": app},
        "spec": {
            "upstream": {
                "ref": "example.invalid/app",
                "tag": "v1.2.3",
                "digest": digest(index()),
            },
            "destination": {"package": f"ghcr.io/bocklabs/{app}"},
            "patchPolicy": "enabled",
            "validation": {
                "type": "http",
                "port": 8080,
                "path": "/health",
                "expectStatus": 200,
            },
        },
    }


def report(vulnerabilities=None) -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": "app@candidate",
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": IMAGE_ID,
            "ImageConfig": CONFIG_VALUE,
            "OS": {"Family": "debian", "Name": "12"},
        },
        "Results": [
            {
                "Target": "app (debian 12)",
                "Class": "os-pkgs",
                "Type": "debian",
                "Vulnerabilities": vulnerabilities or [],
                "Packages": [{"Name": "libexample", "Version": "1.0"}],
            }
        ],
    }


def vuln(cve: str = "CVE-2026-0001") -> dict:
    return {
        "VulnerabilityID": cve,
        "PkgName": "libexample",
        "InstalledVersion": "1.0",
        "FixedVersion": "",
        "Severity": "HIGH",
        "SeveritySource": "debian",
    }


def kev_feed(cves=("CVE-2026-0001",)) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.13",
        "dateReleased": "2026-09-13T00:00:00.00000Z",
        "count": len(cves),
        "vulnerabilities": [{"cveID": cve} for cve in cves],
    }


def acceptance_record() -> dict:
    return {
        "schema": "trusted-images.bocklabs.dev/risk-acceptance-v1",
        "candidateDigest": DIGEST_A,
        "kevs": ["CVE-2026-0001"],
        "reason": "compensating controls",
        "expiresAt": "2026-09-20T00:00:00Z",
        "likelihood": {"level": "MEDIUM", "rationale": "exploit public"},
        "impact": {"level": "HIGH", "rationale": "data could be exposed"},
        "owner": "supply-chain-operator",
        "reviewNotes": ["reviewed"],
        "trackingIssue": 77,
    }


def decision(**changes: object) -> dict:
    value = {
        "schema": "trusted-images.bocklabs.dev/candidate-decision-v1",
        "eligible": True,
        "reason": "clean",
        "platform": "linux/amd64",
        "app": APP,
        "source_sha": SOURCE_SHA,
        "run_id": RUN_ID,
        "run_attempt": 1,
        "proposed_tag": INTERNAL_TAG,
        "upstream_index_digest": digest(index()),
        "selected_child_digest": digest(child_manifest()),
        "candidate": {"digest": digest(child_manifest())},
        "before": {"fixable_os": []},
        "copa": {"classification": "not-required", "original_child_input": False},
        "delta": {
            "resolved": [],
            "remaining": [],
            "introduced": [],
            "unresolved_fixable": [],
            "cves": {
                "resolved": [],
                "remaining": [],
                "introduced": [],
                "unresolved_fixable": [],
            },
        },
        "packages": {
            "changes": [
                {
                    "ecosystem": "debian",
                    "name": "libexample",
                    "change": "upgraded",
                    "before": "1.0",
                    "after": "2.0",
                }
            ],
            "downgrades": [],
        },
        "patching": {"disabled": False},
        "policy": {
            "kev": {
                "matched": [],
                "catalog": {
                    "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    "sha256": "e" * 64,
                    "fetched_at": "2026-09-20T01:00:00Z",
                    "count": 0,
                    "unique_cves": 0,
                    "catalog_version": "2026.09.13",
                    "date_released": "2026-09-13T00:00:00.00000Z",
                },
            },
            "acceptance": None,
        },
        "validation": {"result": "pass"},
        "resume": None,
        "published": {"digest": None},
        "provenance": {"merged": False},
        "supersedes": {"higher_upstream": False, "original_child_selected": False},
    }
    value.update(changes)
    return value


def checksums(root: Path) -> None:
    lines = []
    for path in sorted(
        item for item in root.rglob("*") if item.is_file() and item.name != "SHA256SUMS"
    ):
        relative = path.relative_to(root).as_posix()
        lines.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + relative)
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def artifact_files() -> dict[str, object]:
    child = child_manifest()
    return {
        "candidate-decision.json": decision(),
        "candidate-manifest.json": child,
        "child-config.json": child_config(),
        "child-manifest.json": child,
        "inventory-image.yaml": inventory(),
        "secobserve-upload.json": {"findings": []},
        "source.sha": SOURCE_SHA,
        "tag-decision.json": {"internal_tag": INTERNAL_TAG, "skip_copy": False},
        "trivy-before-full.json": report(),
        "trivy-copa.json": report(),
        "trivy-full.cdx.json": {"components": []},
        "trivy-full.json": report(),
        "upstream-index.json": index(),
        "validation-evidence.json": {"validation": {"result": "pass"}},
        "kev.json": kev_feed(()),
        "kev-fetched-at.txt": "2026-09-20T01:00:00Z\n",
        "trivy-db-meta-1.txt": "db-1\n",
        "trivy-db-meta-2.txt": "db-2\n",
    }


def candidate_tree(root: Path, decision_value: dict | None = None) -> None:
    root.mkdir(parents=True)
    child = child_manifest()
    values = artifact_files()
    if decision_value is not None:
        values["candidate-decision.json"] = decision_value
    for name, value in values.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if name.endswith(".yaml"):
            path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")
        elif name in {
            "source.sha",
            "kev-fetched-at.txt",
            "trivy-db-meta-1.txt",
            "trivy-db-meta-2.txt",
        }:
            path.write_text(str(value), encoding="utf-8")
        else:
            write_json(path, value)
    blob = root / "candidate-oci" / "blobs" / "sha256" / digest(child).split(":", 1)[1]
    blob.parent.mkdir(parents=True)
    blob.write_bytes((json.dumps(child, indent=2) + "\n").encode())
    checksums(root)


def github_api_fixtures(path: str) -> tuple[dict, dict, dict, dict, dict]:
    content_sha = "b" * 40
    commit_sha = "c" * 40
    content = {"path": path, "sha": content_sha, "encoding": "base64", "content": ""}
    commits = [{"sha": commit_sha}]
    commit = {"sha": commit_sha, "files": [{"filename": path, "sha": content_sha}]}
    pull = {
        "number": 42,
        "html_url": "https://github.com/bocklabs/trusted-images/pull/42",
        "state": "closed",
        "merged": True,
        "merged_at": "2026-09-15T00:00:00Z",
        "merged_by": {"login": "approver"},
        "base": {"repo": {"full_name": "bocklabs/trusted-images"}, "ref": "main"},
    }
    issue = {
        "number": 77,
        "html_url": "https://github.com/bocklabs/trusted-images/issues/77",
        "state": "open",
    }
    return content, commits, commit, [pull], pull, issue


class PromotionScriptTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        (self.tmp / "scripts").symlink_to(
            REPO_ROOT / "scripts", target_is_directory=True
        )

    def run_script(
        self, name: str, *args: str, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        child_env = os.environ.copy()
        child_env.update(env or {})
        process_start = child_env.get("COVERAGE_PROCESS_START")
        if process_start:
            site = self.tmp / "coverage-site"
            site.mkdir(exist_ok=True)
            (site / "sitecustomize.py").write_text(
                "import coverage\ncoverage.process_startup()\n", encoding="utf-8"
            )
            existing = child_env.get("PYTHONPATH")
            child_env["PYTHONPATH"] = str(site) + (
                os.pathsep + existing if existing else ""
            )
        return subprocess.run(
            [sys.executable, f"scripts/{name}", *args],
            cwd=self.tmp,
            env=child_env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )


class RecoveryTests(PromotionScriptTestCase):
    def write_recovery_tree(self) -> tuple[Path, dict]:
        root = self.tmp / "recovery-candidate"
        candidate_tree(root)
        child = child_manifest()
        record = {
            "upstream": {
                "index_digest": digest(index()),
                "selected_child_digest": digest(child),
            },
            "internal": {"digest": digest(child)},
        }
        return root, record

    def test_recovery_candidate_materializes_exact_provenance_bytes(self) -> None:
        root, record = self.write_recovery_tree()
        provenance = self.tmp / "provenance.json"
        write_json(provenance, record)
        result = self.run_script(
            "promote_recovery_candidate.py", str(provenance), "recovery-candidate"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        copied = self.tmp / "original-candidate-decision.json"
        self.assertTrue(copied.is_file())
        self.assertEqual(
            copied.read_bytes(), (root / "candidate-decision.json").read_bytes()
        )

    def test_recovery_candidate_rejects_mismatched_provenance(self) -> None:
        root, record = self.write_recovery_tree()
        record["internal"]["digest"] = DIGEST_B
        provenance = self.tmp / "provenance.json"
        write_json(provenance, record)
        result = self.run_script(
            "promote_recovery_candidate.py", str(provenance), "recovery-candidate"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: recovery candidate bytes do not match provenance", result.stderr
        )

    def test_recovery_report_binding_accepts_exact_inventory_identity(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        report_manifest = self.tmp / "report-manifest.json"
        write_json(
            report_manifest,
            {
                "app": APP,
                "upstream_ref": "example.invalid/app",
                "upstream_tag": "v1.2.3",
            },
        )
        result = self.run_script(
            "promote_recovery_report_binding.py", str(image), str(report_manifest), APP
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_recovery_report_binding_rejects_a_different_app(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        report_manifest = self.tmp / "report-manifest.json"
        write_json(
            report_manifest,
            {
                "app": "other",
                "upstream_ref": "example.invalid/app",
                "upstream_tag": "v1.2.3",
            },
        )
        result = self.run_script(
            "promote_recovery_report_binding.py", str(image), str(report_manifest), APP
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: original report artifact is not bound", result.stderr)

    def test_recovery_context_emits_inventory_outputs_in_workflow_order(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        result = self.run_script(
            "promote_recovery_context.py", str(image), APP, INTERNAL_TAG
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "upstream_ref=example.invalid/app",
                "upstream_tag=v1.2.3",
                f"upstream_digest={digest(index())}",
                f"dest_package=ghcr.io/bocklabs/{APP}",
                "patch_policy=enabled",
                f"app={APP}",
                "validation_type=http",
                "validation_port=8080",
                "validation_path=/health",
                "validation_expect_status=200",
            ],
        )

    def test_recovery_context_rejects_a_mismatched_recover_tag(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        result = self.run_script(
            "promote_recovery_context.py", str(image), APP, "v9.9.9-bocklabs.1"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: recover_tag does not match", result.stderr)


class ResumeTests(PromotionScriptTestCase):
    def test_resume_artifact_id_selects_the_single_live_run_artifact(self) -> None:
        (self.tmp / "resume-artifacts.jsonl").write_text(
            json.dumps({"id": 321, "expired": False, "workflow_run": {"id": 123}})
            + "\n",
            encoding="utf-8",
        )
        result = self.run_script("promote_resume_artifact_id.py", RUN_ID)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "321")

    def test_resume_artifact_id_rejects_ambiguous_artifacts(self) -> None:
        row = {"id": 321, "expired": False, "workflow_run": {"id": 123}}
        (self.tmp / "resume-artifacts.jsonl").write_text(
            json.dumps(row) + "\n" + json.dumps(row) + "\n", encoding="utf-8"
        )
        result = self.run_script("promote_resume_artifact_id.py", RUN_ID)
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: candidate artifact is missing, expired, or ambiguous", result.stderr
        )

    def test_resume_candidate_restores_the_exact_preserved_artifact(self) -> None:
        root = self.tmp / "resume-download"
        blocker = decision(eligible=False, reason="missing_kev_acceptance")
        candidate_tree(root, blocker)
        run = {"head_sha": SOURCE_SHA, "run_attempt": 1}
        write_json(self.tmp / "resume-run.json", run)
        (self.tmp / "inventory" / APP).mkdir(parents=True)
        (self.tmp / "inventory" / APP / "image.yaml").write_bytes(
            (root / "inventory-image.yaml").read_bytes()
        )
        output = self.tmp / "github-output.txt"
        result = self.run_script(
            "promote_resume_candidate.py",
            RUN_ID,
            "321",
            env={"APP": APP, "GITHUB_OUTPUT": str(output)},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            output.read_text().splitlines(),
            [
                f"candidate_digest={blocker['candidate']['digest']}",
                f"selected_child_digest={blocker['selected_child_digest']}",
                f"internal_tag={INTERNAL_TAG}",
                "skip_copy=false",
                "patched=false",
                "artifact_id=321",
                f"original_run_id={RUN_ID}",
                "original_run_attempt=1",
                f"original_source_sha={SOURCE_SHA}",
            ],
        )

    def test_resume_candidate_rejects_the_wrong_app_inventory(self) -> None:
        root = self.tmp / "resume-download"
        blocker = decision(eligible=False, reason="missing_kev_acceptance")
        candidate_tree(root, blocker)
        write_json(
            self.tmp / "resume-run.json", {"head_sha": SOURCE_SHA, "run_attempt": 1}
        )
        result = self.run_script(
            "promote_resume_candidate.py",
            RUN_ID,
            "321",
            env={"APP": "other", "GITHUB_OUTPUT": "/dev/null"},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: candidate inventory app/package mismatch", result.stderr)


class RegistryTests(PromotionScriptTestCase):
    def test_registry_next_link_returns_the_exact_pagination_url(self) -> None:
        (self.tmp / "registry-page.headers").write_text(
            'Link: <https://example.invalid/next?after=2>; rel="next"\n',
            encoding="utf-8",
        )
        result = self.run_script("promote_registry_next_link.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "https://example.invalid/next?after=2")

    def test_registry_next_link_fails_when_headers_are_missing(self) -> None:
        result = self.run_script("promote_registry_next_link.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("registry-page.headers", result.stderr)

    def test_registry_candidates_filters_only_this_upstreams_revisions(self) -> None:
        tags = self.tmp / "tags.txt"
        tags.write_text(
            "v1.2.3-bocklabs.1\nv1.2.3-bocklabs.10\nv1.2.4-bocklabs.2\nv1.2.3\n",
            encoding="utf-8",
        )
        result = self.run_script("promote_registry_candidates.py", "v1.2.3", str(tags))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines(), ["v1.2.3-bocklabs.1", "v1.2.3-bocklabs.10"]
        )

    def test_registry_candidates_ignores_a_missing_tags_file(self) -> None:
        result = self.run_script(
            "promote_registry_candidates.py", "v1.2.3", str(self.tmp / "missing")
        )
        self.assertNotEqual(result.returncode, 0)

    def test_registry_observations_merges_trusted_and_untrusted_rows(self) -> None:
        record = {
            "schema": "trusted-images.bocklabs.dev/provenance-v1",
            "upstream": {
                "digest": DIGEST_B,
                "index_digest": DIGEST_A,
                "selected_child_digest": DIGEST_B,
            },
            "internal": {
                "tag": "v1.2.3-bocklabs.1",
                "digest": DIGEST_A,
                "platforms": ["linux/amd64"],
            },
        }
        (self.tmp / "provenance" / APP).mkdir(parents=True)
        write_json(self.tmp / "provenance" / APP / "v1.2.3-bocklabs.1.json", record)
        observations = self.tmp / "registry-observations.tsv"
        observations.write_text(
            "v1.2.3-bocklabs.1\t" + DIGEST_A + "\nunknown\t" + DIGEST_B + "\n",
            encoding="utf-8",
        )
        result = self.run_script("promote_registry_observations.py", APP)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            json.loads(result.stdout),
            [
                {
                    "tag": "v1.2.3-bocklabs.1",
                    "digest": DIGEST_A,
                    "upstream_index_digest": DIGEST_A,
                    "selected_child_digest": DIGEST_B,
                    "platforms": ["linux/amd64"],
                },
                {
                    "tag": "unknown",
                    "digest": DIGEST_B,
                    "upstream_index_digest": "",
                    "selected_child_digest": None,
                    "platforms": None,
                },
            ],
        )

    def test_registry_observations_fail_closed_on_unbound_provenance(self) -> None:
        provenance = self.tmp / "provenance" / APP
        provenance.mkdir(parents=True)
        record = {
            "schema": "trusted-images.bocklabs.dev/provenance-v1",
            "internal": {"tag": "other", "digest": DIGEST_A},
        }
        write_json(provenance / "v1.2.3-bocklabs.1.json", record)
        observations = self.tmp / "registry-observations.tsv"
        observations.write_text(
            "v1.2.3-bocklabs.1\t" + DIGEST_A + "\n", encoding="utf-8"
        )
        result = self.run_script("promote_registry_observations.py", APP)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: provenance does not bind observed tag", result.stderr)

    def test_reused_candidate_accepts_matching_layout_bytes(self) -> None:
        root = self.tmp / "reused-candidate"
        candidate_tree(root)
        result = self.run_script(
            "promote_reused_candidate.py", digest(child_manifest()), "reused-candidate"
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_reused_candidate_rejects_changed_manifest_bytes(self) -> None:
        root = self.tmp / "reused-candidate"
        candidate_tree(root)
        (root / "candidate-manifest.json").write_text("{}\n", encoding="utf-8")
        result = self.run_script(
            "promote_reused_candidate.py", digest(child_manifest()), "reused-candidate"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: reused candidate bytes do not match", result.stderr)


class LabelTests(PromotionScriptTestCase):
    def test_proposed_labels_add_only_missing_provenance_labels(self) -> None:
        before = self.tmp / "before.json"
        write_json(before, {"existing": "same"})
        result = self.run_script(
            "promote_proposed_labels.py",
            str(before),
            env={
                "SELECTED_DIGEST": DIGEST_A,
                "UPSTREAM_REF": "example.invalid/app",
                "UPSTREAM_TAG": "v1.2.3",
                "INTERNAL_TAG": INTERNAL_TAG,
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = json.loads(result.stdout)
        self.assertEqual(len(values), 4)
        self.assertIn(
            'LABEL org.opencontainers.image.base.digest="' + DIGEST_A + '"', values
        )
        self.assertIn(
            'LABEL org.opencontainers.image.version="' + INTERNAL_TAG + '"', values
        )

    def test_proposed_labels_fail_closed_without_upstream_identity(self) -> None:
        before = self.tmp / "before.json"
        write_json(before, {})
        result = self.run_script(
            "promote_proposed_labels.py", str(before), env={"SELECTED_DIGEST": DIGEST_A}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("UPSTREAM_REF", result.stderr)

    def test_label_changes_accept_preserved_labels_and_allowed_additions(self) -> None:
        before = self.tmp / "before.json"
        after = self.tmp / "after.json"
        write_json(before, {"existing": "same"})
        write_json(
            after,
            {
                "existing": "same",
                "org.opencontainers.image.base.name": "example.invalid/app:v1.2.3",
            },
        )
        result = self.run_script("promote_label_changes.py", str(before), str(after))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_label_changes_reject_any_change_to_an_existing_label(self) -> None:
        before = self.tmp / "before.json"
        after = self.tmp / "after.json"
        write_json(before, {"existing": "same"})
        write_json(after, {"existing": "changed"})
        result = self.run_script("promote_label_changes.py", str(before), str(after))
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: patched labels violate the add-only provenance contract",
            result.stderr,
        )


class AcceptanceTests(PromotionScriptTestCase):
    def test_acceptance_paths_compute_the_exact_content_path(self) -> None:
        write_json(self.tmp / "trivy-full.json", report([vuln()]))
        write_json(self.tmp / "kev.json", kev_feed())
        manifest = self.tmp / "candidate-manifest.json"
        manifest.write_bytes(b"candidate-manifest\n")
        result = self.run_script("promote_acceptance_paths.py", env={"APP": APP})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        candidate_digest = digest_bytes(manifest.read_bytes())
        expected = (
            "risk-acceptances/app/"
            + hashlib.sha256(candidate_digest.encode()).hexdigest()
            + "-"
            + hashlib.sha256(b"CVE-2026-0001").hexdigest()
            + ".json"
        )
        self.assertEqual(
            (self.tmp / "acceptance-path.txt").read_text(), expected + "\n"
        )
        self.assertEqual(
            (self.tmp / "acceptance-matched.txt").read_text(), "CVE-2026-0001\n"
        )

    def test_acceptance_paths_reject_a_malformed_final_report(self) -> None:
        bad = report([vuln()])
        bad["SchemaVersion"] = 1
        write_json(self.tmp / "trivy-full.json", bad)
        write_json(self.tmp / "kev.json", kev_feed())
        write_json(self.tmp / "candidate-manifest.json", {"schemaVersion": 2})
        result = self.run_script("promote_acceptance_paths.py", env={"APP": APP})
        self.assertEqual(result.returncode, 1)
        self.assertIn("final report.SchemaVersion must be 2", result.stderr)

    def test_acceptance_decode_writes_exact_base64_bytes(self) -> None:
        encoded = base64.b64encode(b"exact-acceptance-bytes\n").decode()
        write_json(
            self.tmp / "acceptance-content.json",
            {"encoding": "base64", "content": encoded},
        )
        result = self.run_script("promote_acceptance_decode.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.tmp / "acceptance.json").read_bytes(), b"exact-acceptance-bytes\n"
        )

    def test_acceptance_decode_rejects_non_base64_content_api_responses(self) -> None:
        write_json(
            self.tmp / "acceptance-content.json", {"encoding": "utf-8", "content": "{}"}
        )
        result = self.run_script("promote_acceptance_decode.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: acceptance content API did not return base64 bytes", result.stderr
        )

    def test_github_evidence_binds_record_bytes_commit_and_pull(self) -> None:
        record = acceptance_record()
        write_json(self.tmp / "acceptance.json", record)
        path = "risk-acceptances/app/bound.json"
        content, commits, commit, associated, pull, issue = github_api_fixtures(path)
        write_json(self.tmp / "acceptance-content.json", content)
        write_json(self.tmp / "acceptance-commits.json", commits)
        write_json(self.tmp / "acceptance-commit.json", commit)
        write_json(self.tmp / "acceptance-prs.json", associated)
        write_json(self.tmp / "acceptance-pr.json", pull)
        write_json(self.tmp / "acceptance-issue.json", issue)
        result = self.run_script(
            "promote_github_evidence.py", path, env={"REPO": "bocklabs/trusted-images"}
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        proof = json.loads((self.tmp / "github-evidence.json").read_text())
        self.assertEqual(proof["path"], path)
        self.assertEqual(
            proof["record_sha256"],
            hashlib.sha256((self.tmp / "acceptance.json").read_bytes()).hexdigest(),
        )
        self.assertEqual(proof["pull_request"]["number"], 42)
        self.assertEqual(proof["issue"]["number"], 77)

    def test_github_evidence_rejects_an_ambiguous_commit_list(self) -> None:
        write_json(self.tmp / "acceptance.json", acceptance_record())
        path = "risk-acceptances/app/bound.json"
        content, _, commit, associated, pull, issue = github_api_fixtures(path)
        write_json(self.tmp / "acceptance-content.json", content)
        write_json(self.tmp / "acceptance-commits.json", [])
        write_json(self.tmp / "acceptance-commit.json", commit)
        write_json(self.tmp / "acceptance-prs.json", associated)
        write_json(self.tmp / "acceptance-pr.json", pull)
        write_json(self.tmp / "acceptance-issue.json", issue)
        result = self.run_script(
            "promote_github_evidence.py", path, env={"REPO": "bocklabs/trusted-images"}
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: acceptance commit/path is ambiguous", result.stderr)


class DecisionTests(PromotionScriptTestCase):
    def policy_inputs(self, full=None, fixable=None) -> None:
        write_json(self.tmp / "upstream-index.json", index())
        write_json(self.tmp / "child-manifest.json", child_manifest())
        write_json(self.tmp / "child-config.json", child_config())
        write_json(
            self.tmp / "trivy-before-full.json", report() if full is None else full
        )
        write_json(
            self.tmp / "trivy-copa.json", report() if fixable is None else fixable
        )
        write_json(self.tmp / "kev.json", kev_feed(()))
        now = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        (self.tmp / "kev-fetched-at.txt").write_text(now + "\n", encoding="utf-8")
        (self.tmp / "validation-context").mkdir()
        write_json(
            self.tmp / "validation-context" / "patch-policy.json",
            {"patchPolicy": "enabled"},
        )
        write_json(
            self.tmp / "validation-evidence.json", {"validation": {"result": "pass"}}
        )

    def test_candidate_decision_exports_eligible_policy_and_supersede_outputs(
        self,
    ) -> None:
        self.policy_inputs()
        output = self.tmp / "github-output.txt"
        result = self.run_script(
            "promote_candidate_decision.py",
            env={
                "APP": APP,
                "SOURCE_SHA": SOURCE_SHA,
                "RUN_ID": RUN_ID,
                "RUN_ATTEMPT": "1",
                "INTERNAL_TAG": INTERNAL_TAG,
                "UPSTREAM_INDEX_DIGEST": digest(index()),
                "CANDIDATE_DIGEST": DIGEST_A,
                "GITHUB_REPOSITORY": "bocklabs/trusted-images",
                "GITHUB_OUTPUT": str(output),
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        exported = json.loads((self.tmp / "candidate-decision.json").read_text())
        self.assertTrue(exported["eligible"])
        self.assertEqual(exported["reason"], "clean")
        self.assertEqual(output.read_text(), "eligible=true\n")

    def test_candidate_decision_retains_the_candidate_when_evaluation_fails(
        self,
    ) -> None:
        self.policy_inputs(fixable=report([vuln()]))
        result = self.run_script(
            "promote_candidate_decision.py",
            env={
                "APP": APP,
                "SOURCE_SHA": SOURCE_SHA,
                "RUN_ID": RUN_ID,
                "RUN_ATTEMPT": "1",
                "INTERNAL_TAG": INTERNAL_TAG,
                "UPSTREAM_INDEX_DIGEST": digest(index()),
                "CANDIDATE_DIGEST": DIGEST_A,
                "GITHUB_REPOSITORY": "bocklabs/trusted-images",
                "GITHUB_OUTPUT": "/dev/null",
            },
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "Candidate retained for operator review; publisher will not run.",
            result.stdout,
        )

    def test_candidate_artifact_accepts_a_complete_checksum_bound_tree(self) -> None:
        candidate_tree(self.tmp / "candidate-artifact")
        result = self.run_script("promote_candidate_artifact.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_candidate_artifact_rejects_tampered_file_bytes(self) -> None:
        root = self.tmp / "candidate-artifact"
        candidate_tree(root)
        target = root / "child-manifest.json"
        target.write_text('{"tampered": true}\n', encoding="utf-8")
        result = self.run_script("promote_candidate_artifact.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: fresh candidate checksum failed:", result.stderr)

    def test_github_evidence_rejects_an_unmerged_pull_request(self) -> None:
        write_json(self.tmp / "acceptance.json", acceptance_record())
        path = "risk-acceptances/app/bound.json"
        content, commits, commit, associated, pull, issue = github_api_fixtures(path)
        unmerged = {**pull, "merged": False, "merged_at": None}
        write_json(self.tmp / "acceptance-content.json", content)
        write_json(self.tmp / "acceptance-commits.json", commits)
        write_json(self.tmp / "acceptance-commit.json", commit)
        write_json(self.tmp / "acceptance-prs.json", associated)
        write_json(self.tmp / "acceptance-pr.json", unmerged)
        write_json(self.tmp / "acceptance-issue.json", issue)
        result = self.run_script(
            "promote_github_evidence.py", path, env={"REPO": "bocklabs/trusted-images"}
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: acceptance pull request is not a merged main-branch approval",
            result.stderr,
        )

    def test_candidate_artifact_rejects_an_undeclared_file(self) -> None:
        root = self.tmp / "candidate-artifact"
        candidate_tree(root)
        (root / "undeclared.txt").write_text("unexpected\n", encoding="utf-8")
        result = self.run_script("promote_candidate_artifact.py")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: fresh candidate artifact has undeclared or missing files",
            result.stderr,
        )

    def test_decision_integrity_accepts_a_valid_current_binding(self) -> None:
        path = write_json(self.tmp / "decision.json", decision())
        result = self.run_script(
            "promote_decision_integrity.py",
            str(path),
            env={
                "APP": APP,
                "SOURCE_SHA": SOURCE_SHA,
                "RUN_ID": RUN_ID,
                "RUN_ATTEMPT": "1",
                "UPSTREAM_INDEX_DIGEST": digest(index()),
                "REPO": "bocklabs/trusted-images",
            },
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_decision_integrity_rejects_a_different_app(self) -> None:
        path = write_json(self.tmp / "decision.json", decision())
        result = self.run_script(
            "promote_decision_integrity.py",
            str(path),
            env={
                "APP": "other",
                "SOURCE_SHA": SOURCE_SHA,
                "RUN_ID": RUN_ID,
                "RUN_ATTEMPT": "1",
                "UPSTREAM_INDEX_DIGEST": digest(index()),
                "REPO": "bocklabs/trusted-images",
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: candidate decision binding failed", result.stderr)
        self.assertIn("app='app'", result.stderr)

    def test_published_decision_accepts_the_verified_candidate_identity(self) -> None:
        published = decision()
        published["published"] = {"digest": published["candidate"]["digest"]}
        write_json(self.tmp / "candidate-decision.json", published)
        result = self.run_script("promote_published_decision.py", APP, env={"APP": APP})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_published_decision_rejects_a_different_app(self) -> None:
        published = decision()
        published["published"] = {"digest": published["candidate"]["digest"]}
        write_json(self.tmp / "candidate-decision.json", published)
        result = self.run_script(
            "promote_published_decision.py", APP, env={"APP": "other"}
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("FATAL: published decision identity is invalid", result.stderr)

    def test_final_decision_requires_a_merged_provenance_record(self) -> None:
        final = decision()
        final["published"] = {"digest": final["candidate"]["digest"]}
        final["provenance"] = {"merged": True}
        write_json(self.tmp / "candidate-decision.json", final)
        result = self.run_script(
            "promote_final_decision.py",
            APP,
            final["candidate"]["digest"],
            env={"APP": APP, "CANDIDATE_DIGEST": final["candidate"]["digest"]},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_final_decision_rejects_unmerged_provenance(self) -> None:
        final = decision()
        final["published"] = {"digest": final["candidate"]["digest"]}
        write_json(self.tmp / "candidate-decision.json", final)
        result = self.run_script(
            "promote_final_decision.py",
            APP,
            final["candidate"]["digest"],
            env={"APP": APP, "CANDIDATE_DIGEST": final["candidate"]["digest"]},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: final candidate decision merge state is invalid", result.stderr
        )


class ContextAndEvidenceTests(PromotionScriptTestCase):
    def test_patch_policy_emits_enabled_and_disabled_forms(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        result = self.run_script("promote_patch_policy.py", str(image))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), {"patchPolicy": "enabled"})

    def test_patch_policy_fails_when_the_policy_field_is_absent(self) -> None:
        image = self.tmp / "image.yaml"
        value = inventory()
        del value["spec"]["patchPolicy"]
        image.write_text(yaml.safe_dump(value), encoding="utf-8")
        result = self.run_script("promote_patch_policy.py", str(image))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("patchPolicy", result.stderr)

    def test_validation_context_preserves_inventory_argument_order(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        result = self.run_script("promote_validation_context.py", str(image), APP)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"upstream_digest={digest(index())}", result.stdout.splitlines())
        self.assertIn(f"app={APP}", result.stdout.splitlines())

    def test_validation_context_rejects_a_different_app(self) -> None:
        image = self.tmp / "image.yaml"
        image.write_text(yaml.safe_dump(inventory()), encoding="utf-8")
        result = self.run_script("promote_validation_context.py", str(image), "other")
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FATAL: validation context destination does not match app", result.stderr
        )

    def test_summary_renders_reports_and_decision_tables(self) -> None:
        write_json(self.tmp / "trivy-before-full.json", report([vuln()]))
        write_json(self.tmp / "trivy-copa.json", report())
        write_json(self.tmp / "trivy-full.json", report())
        write_json(self.tmp / "candidate-decision.json", decision())
        result = self.run_script("promote_summary.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "| before | CVE-2026-0001 | libexample | HIGH | debian |", result.stdout
        )
        self.assertIn("| debian | libexample | upgraded | 1.0 | 2.0 |", result.stdout)
        self.assertIn("N/A — no KEV exception", result.stdout)

    def test_summary_fails_closed_on_a_malformed_report(self) -> None:
        (self.tmp / "trivy-before-full.json").write_text("{\n", encoding="utf-8")
        result = self.run_script("promote_summary.py")
        self.assertNotEqual(result.returncode, 0)

    def test_provenance_body_renders_the_exact_machine_generated_header(self) -> None:
        write_json(self.tmp / "candidate-decision.json", decision())
        result = self.run_script(
            "promote_provenance_body.py",
            "https://example.invalid/run/123",
            DIGEST_A,
            INTERNAL_TAG,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            result.stdout.splitlines()[:6],
            [
                "Machine-generated provenance record per docs/pipeline.md.",
                "",
                "- Run: https://example.invalid/run/123",
                f"- Candidate digest: `{DIGEST_A}`",
                f"- Internal tag: {INTERNAL_TAG}",
                "",
            ],
        )
        self.assertIn("- resolved: -", result.stdout)
        self.assertIn("N/A — no KEV exception", result.stdout)

    def test_provenance_body_fails_without_a_candidate_decision(self) -> None:
        result = self.run_script(
            "promote_provenance_body.py",
            "https://example.invalid/run/123",
            DIGEST_A,
            INTERNAL_TAG,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
