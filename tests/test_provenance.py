#!/usr/bin/env python3
"""Focused tests for the extended provenance-v1 writer."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "scripts" / "generate_provenance.py"
SCHEMA = "trusted-images.bocklabs.dev/provenance-v1"
PILOT_UPSTREAM_DIGEST = "sha256:" + "a" * 64
CHILD_DIGEST = "sha256:" + "f" * 64
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def trivy_report(cves=()) -> dict:
    vulnerabilities = [
        {
            "VulnerabilityID": cve,
            "PkgName": "openssl",
            "InstalledVersion": "1.0",
            "FixedVersion": "",
            "Severity": "HIGH",
            "SeveritySource": "debian",
        }
        for cve in cves
    ]
    return {
        "SchemaVersion": 2,
        "Metadata": {"OS": {"Family": "debian", "EOSL": False}},
        "Results": [
            {
                "Class": "os-pkgs",
                "Type": "debian",
                "Target": "debian",
                "Vulnerabilities": vulnerabilities,
                "Packages": [
                    {"Name": "openssl", "Version": "1.0", "Epoch": 0, "Release": ""}
                ],
            }
        ],
    }


def kev_report(cves=()) -> dict:
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.13",
        "dateReleased": "2026-09-13T00:00:00Z",
        "count": len(cves),
        "vulnerabilities": [{"cveID": cve} for cve in cves],
    }


def valid_decision(cves=()) -> dict:
    identities = [f"linux/amd64|openssl|{cve}" for cve in cves]
    return {
        "schema": "trusted-images.bocklabs.dev/candidate-decision-v1",
        "eligible": True,
        "reason": "eligible with no-fix warnings: "
        + ",".join(f"{cve}:HIGH:debian" for cve in cves),
        "platform": "linux/amd64",
        "app": "postgres-exporter",
        "source_sha": "d" * 40,
        "run_id": "123",
        "run_attempt": 1,
        "proposed_tag": "v0.20.1-bocklabs.1",
        "upstream_index_digest": PILOT_UPSTREAM_DIGEST,
        "selected_child_digest": CHILD_DIGEST,
        "candidate": {"digest": CHILD_DIGEST},
        "before": {"fixable_os": []},
        "copa": {"classification": "not-required", "original_child_input": False},
        "delta": {
            "resolved": [],
            "remaining": identities,
            "introduced": [],
            "unresolved_fixable": [],
            "cves": {
                "resolved": [],
                "remaining": list(cves),
                "introduced": [],
                "unresolved_fixable": [],
            },
        },
        "packages": {"changes": [], "downgrades": []},
        "patching": {"disabled": False},
        "policy": {"kev": {"matched": list(cves), "catalog": {}}, "acceptance": None},
        "validation": {"result": "pass"},
        "resume": None,
        "published": {"digest": CHILD_DIGEST},
        "provenance": {"merged": False},
        "supersedes": {"higher_upstream": False, "original_child_selected": False},
    }


def github_evidence(path: str, issue: int = 77) -> dict:
    pull = {
        "number": 42,
        "html_url": "https://github.com/bocklabs/trusted-images/pull/42",
        "state": "closed",
        "merged": True,
        "merged_at": "2026-09-13T00:00:00Z",
        "merged_by": {"login": "approver"},
        "base_repository": "bocklabs/trusted-images",
        "base_ref": "main",
    }
    return {
        "repository": "bocklabs/trusted-images",
        "path": path,
        "record_sha256": "0" * 64,
        "content_blob_sha": "b" * 40,
        "commit": {"sha": "c" * 40, "path": path, "blob_sha": "b" * 40},
        "associated_pull_requests": [pull],
        "pull_request": pull,
        "issue": {
            "number": issue,
            "html_url": f"https://github.com/bocklabs/trusted-images/issues/{issue}",
            "state": "open",
            "is_pull_request": False,
        },
    }


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.out = root / "provenance" / "postgres-exporter" / "v0.20.1-bocklabs.1.json"
        self.before = root / "before.json"
        self.final = root / "final.json"
        self.fixable = root / "fixable.json"
        self.kev = root / "kev.json"
        self.decision_path = root / "candidate-decision.json"
        self.github = root / "github-evidence.json"
        self.signing_evidence = root / "signing-evidence.json"
        signing_files = {
            "sign-bundle.json": b"signature bundle",
            "signature-attachment.json": b"signature attachment",
            "sbom-bundle.json": b"SBOM bundle",
            "sbom-attestation-attachment.json": b"attestation attachment",
            "trivy-full.cdx.json": b'{"bomFormat":"CycloneDX","components":[]}',
        }
        for name, content in signing_files.items():
            (root / name).write_bytes(content)
        def sha(name):
            return hashlib.sha256(signing_files[name]).hexdigest()
        self.signing_evidence.write_text(json.dumps({
            "result": "pass", "image": f"ghcr.io/bocklabs/postgres-exporter@{CHILD_DIGEST}",
            "digest": CHILD_DIGEST,
            "certificate_identity": "https://github.com/bocklabs/trusted-images/.github/workflows/promote-publish.yaml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
            "cosign_version": "v3.1.3", "trivy_version": "0.74.0",
            "signature": {"bundle_sha256": sha("sign-bundle.json"), "attachment_sha256": sha("signature-attachment.json"),
                          "rekor": {"log_index": 1, "log_id": "log-id", "signed_entry_timestamp": "set", "inclusion_root_hash": None}},
            "sbom_attestation": {"predicate_type": "https://cyclonedx.org/bom", "predicate_sha256": sha("trivy-full.cdx.json"),
                                 "bundle_sha256": sha("sbom-bundle.json"), "attachment_sha256": sha("sbom-attestation-attachment.json"),
                                 "rekor": {"log_index": 2, "log_id": "log-id", "signed_entry_timestamp": "set", "inclusion_root_hash": None}},
        }), encoding="utf-8")
        self.write_inputs(())

    def write_inputs(self, cves) -> None:
        self.before.write_text(json.dumps(trivy_report(cves)), encoding="utf-8")
        self.final.write_text(json.dumps(trivy_report(cves)), encoding="utf-8")
        self.fixable.write_text(json.dumps(trivy_report()), encoding="utf-8")
        self.kev.write_text(json.dumps(kev_report(cves)), encoding="utf-8")
        decision = valid_decision(cves)
        decision["policy"]["kev"]["catalog"] = {
            "url": KEV_URL,
            "sha256": hashlib.sha256(self.kev.read_bytes()).hexdigest(),
            "fetched_at": "2026-09-14T00:00:00Z",
            "count": len(cves),
            "unique_cves": len(cves),
            "catalog_version": "2026.09.13",
            "date_released": "2026-09-13T00:00:00Z",
        }
        self.decision = decision
        self.decision_path.write_text(json.dumps(decision), encoding="utf-8")

    def flags(self) -> dict[str, str]:
        return {
            "--app": "postgres-exporter",
            "--upstream-ref": "quay.io/prometheuscommunity/postgres-exporter",
            "--upstream-tag": "v0.20.1",
            "--upstream-digest": PILOT_UPSTREAM_DIGEST,
            "--upstream-child-digest": CHILD_DIGEST,
            "--media-type": "application/vnd.oci.image.index.v1+json",
            "--internal-package": "ghcr.io/bocklabs/postgres-exporter",
            "--internal-tag": "v0.20.1-bocklabs.1",
            "--internal-digest": CHILD_DIGEST,
            "--platforms": "linux/amd64",
            "--run-url": "https://example.invalid/runs/99",
            "--workflow": "promote",
            "--dispatched-by": "test",
            "--trivy-version": "0.74.0",
            "--trivy-action-sha": "a" * 40,
            "--skopeo-version": "1.22.2",
            "--skopeo-image-digest": "sha256:" + "b" * 64,
            "--trivy-db-check-bundle-digest": "sha256:" + "c" * 64,
            "--trivy-db-updated-at": "2026-09-14T00:00:00Z",
            "--full-report-sha256": hashlib.sha256(self.final.read_bytes()).hexdigest(),
            "--copa-report-sha256": hashlib.sha256(
                self.fixable.read_bytes()
            ).hexdigest(),
            "--decision-sha256": hashlib.sha256(
                self.decision_path.read_bytes()
            ).hexdigest(),
            "--decision": str(self.decision_path),
            "--before-report": str(self.before),
            "--final-report": str(self.final),
            "--fixable-report": str(self.fixable),
            "--kev-report": str(self.kev),
            "--now": "2026-09-14T01:00:00Z",
            "--secobserve-product": "trusted-images",
            "--secobserve-origin": "app:v0.20.1",
            "--validation-type": "http",
            "--validation-result": "pass",
            "--validation-params": "{}",
            "--validation-timings": "{}",
            "--validation-health": "{}",
            "--validation-runner": "ubuntu-latest",
            "--validation-entrypoint": "[]",
            "--validation-cmd": "[]",
            "--validation-env": "[]",
            "--signing-evidence": str(self.signing_evidence),
            "--signing-result": "pass",
            "--out": str(self.out),
        }

    def run_generator(self, flags: dict[str, str]) -> subprocess.CompletedProcess:
        argv = [sys.executable, str(GENERATOR)]
        for key, value in flags.items():
            argv += [key, value]
        return subprocess.run(argv, capture_output=True, text=True)

    def mutated(self, **changes: str | None) -> dict[str, str]:
        flags = self.flags()
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
        self.assertIn("[provenance]", result.stdout + result.stderr)
        self.assertIn(field, result.stdout + result.stderr)
        self.assertFalse(self.out.exists())

    def test_valid_record_persists_complete_policy_evidence(self) -> None:
        result = self.run_generator(self.flags())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], SCHEMA)
        self.assertEqual(record["upstream"]["selected_platform"], "linux/amd64")
        self.assertEqual(record["upstream"]["index_digest"], PILOT_UPSTREAM_DIGEST)
        self.assertEqual(record["upstream"]["selected_child_digest"], CHILD_DIGEST)
        self.assertEqual(record["internal"]["digest"], CHILD_DIGEST)
        self.assertEqual(
            record["scan"]["reports"]["before_sha256"],
            record["scan"]["reports"]["final_sha256"],
        )
        self.assertEqual(record["policy"]["outcome"], self.decision["reason"])
        self.assertEqual(record["policy"]["patching"], self.decision["patching"])
        self.assertEqual(record["policy"]["copa"], self.decision["copa"])
        self.assertEqual(record["policy"]["supersedes"], self.decision["supersedes"])
        self.assertEqual(record["policy"]["warnings"], [])
        self.assertEqual(record["cves"]["before"], [])
        self.assertEqual(record["cves"]["final"], [])
        self.assertEqual(record["cves"]["summary"]["remaining"], [])
        self.assertEqual(record["packages"]["changes"], [])
        self.assertFalse(record["packages"]["downgrade_blocked"])
        self.assertEqual(
            record["policy"]["kev"]["catalog"]["catalogVersion"], "2026.09.13"
        )
        self.assertIsNone(record["policy"]["acceptance"])
        self.assertEqual(record["signing"]["result"], "pass")
        self.assertEqual(record["signing"]["image_signature"]["certificate_identity"], json.loads(self.signing_evidence.read_text())["certificate_identity"])
        self.assertEqual(record["signing"]["sbom_attestation"]["predicate_sha256"], hashlib.sha256((self.signing_evidence.parent / "trivy-full.cdx.json").read_bytes()).hexdigest())
        self.assertEqual(record["signing"]["tools"], {"cosign": "v3.1.3", "trivy": "0.74.0"})

    def test_signing_evidence_is_required_and_digest_bound(self) -> None:
        self.assert_fails_closed(self.run_generator(self.mutated(signing_evidence=None)), "signing-evidence")
        original = json.loads(self.signing_evidence.read_text())
        for path, value in (("certificate_identity", ""), ("digest", "sha256:" + "e" * 64),
                            ("cosign_version", ""), ("trivy_version", "")):
            with self.subTest(path=path):
                evidence = dict(original)
                evidence[path] = value
                self.signing_evidence.write_text(json.dumps(evidence))
                self.assert_fails_closed(self.run_generator(self.flags()), path)

        for group, path, value in (("signature", "attachment_sha256", "bad"),
                                   ("sbom_attestation", "predicate_sha256", ""),
                                   ("signature", "rekor", {}),
                                   ("sbom_attestation", "rekor", {})):
            with self.subTest(group=group, path=path):
                evidence = json.loads(json.dumps(original))
                evidence[group][path] = value
                self.signing_evidence.write_text(json.dumps(evidence))
                self.assert_fails_closed(self.run_generator(self.flags()), path)

    def test_new_record_without_signing_result_fails(self) -> None:
        flags = self.flags()
        del flags["--signing-result"]
        self.assert_fails_closed(self.run_generator(flags), "signing-result")

    def test_signing_hashes_must_match_local_evidence_bytes(self) -> None:
        (self.signing_evidence.parent / "sign-bundle.json").write_text("changed")
        self.assert_fails_closed(self.run_generator(self.flags()), "bundle_sha256")

    def test_signing_predicate_must_be_cyclonedx(self) -> None:
        predicate = self.signing_evidence.parent / "trivy-full.cdx.json"
        predicate.write_text("{}")
        evidence = json.loads(self.signing_evidence.read_text())
        evidence["sbom_attestation"]["predicate_sha256"] = hashlib.sha256(predicate.read_bytes()).hexdigest()
        self.signing_evidence.write_text(json.dumps(evidence))
        self.assert_fails_closed(self.run_generator(self.flags()), "predicate")

    def test_quarantine_is_explicit_and_non_promotable(self) -> None:
        self.decision["eligible"] = False
        self.decision["reason"] = "signing verification failed"
        self.decision_path.write_text(json.dumps(self.decision))
        flags = self.flags()
        flags["--decision-sha256"] = hashlib.sha256(self.decision_path.read_bytes()).hexdigest()
        flags["--signing-result"] = "fail"
        flags["--signing-failure"] = "verification failed"
        self.signing_evidence.write_text(json.dumps({"result": "fail", "reason": "verification failed"}))
        result = self.run_generator(flags)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.out.read_text())
        self.assertFalse(record["policy"]["eligible"])
        self.assertEqual(record["policy"]["outcome"], "signing verification failed")
        self.assertEqual(record["signing"], {"result": "fail", "failure": "verification failed"})
        self.out.unlink()
        self.decision["eligible"] = True
        self.decision_path.write_text(json.dumps(self.decision))
        flags["--decision-sha256"] = hashlib.sha256(self.decision_path.read_bytes()).hexdigest()
        self.assert_fails_closed(self.run_generator(flags), "eligible")

    def test_missing_required_flag_fails(self) -> None:
        result = self.run_generator(self.mutated(run_url=None))
        self.assert_fails_closed(result, "run-url")

    def test_malformed_digest_fails(self) -> None:
        result = self.run_generator(self.mutated(upstream_digest="sha256:deadbeef"))
        self.assert_fails_closed(result, "upstream-digest")

    def test_malformed_validation_json_fails(self) -> None:
        result = self.run_generator(self.mutated(validation_entrypoint="not-json"))
        self.assert_fails_closed(result, "validation-entrypoint")

    def test_mismatched_candidate_evidence_writes_no_record(self) -> None:
        flags = self.flags()
        self.decision["candidate"]["digest"] = "sha256:" + "e" * 64
        self.decision_path.write_text(json.dumps(self.decision), encoding="utf-8")
        flags["--decision-sha256"] = hashlib.sha256(
            self.decision_path.read_bytes()
        ).hexdigest()
        self.assert_fails_closed(self.run_generator(flags), "candidate_digest")

    def test_exact_acceptance_is_mapped_and_expires_strictly(self) -> None:
        cves = ("CVE-2026-0001",)
        self.write_inputs(cves)
        flags = self.flags()
        path = (
            "risk-acceptances/postgres-exporter/"
            + hashlib.sha256(CHILD_DIGEST.encode()).hexdigest()
            + "-"
            + hashlib.sha256(b"CVE-2026-0001").hexdigest()
            + ".json"
        )
        self.github.write_text(json.dumps(github_evidence(path)), encoding="utf-8")
        self.decision["policy"]["acceptance"] = {
            "path": path,
            "sha256": "0" * 64,
            "candidate_digest": CHILD_DIGEST,
            "kevs": list(cves),
            "expires_at": "2026-09-18T00:00:00Z",
            "commit_sha": "c" * 40,
            "pull_request": 42,
            "merged_at": "2026-09-13T00:00:00Z",
            "merged_by": "approver",
            "issue": 77,
        }
        self.decision_path.write_text(json.dumps(self.decision), encoding="utf-8")
        flags.update(
            {
                "--decision-sha256": hashlib.sha256(
                    self.decision_path.read_bytes()
                ).hexdigest(),
                "--github-evidence": str(self.github),
                "--github-repository": "bocklabs/trusted-images",
            }
        )
        result = self.run_generator(flags)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.out.read_text(encoding="utf-8"))
        acceptance = record["policy"]["acceptance"]
        self.assertEqual(record["policy"]["warnings"][0]["severity_source"], "debian")
        self.assertEqual(
            acceptance,
            {
                "candidate_digest": CHILD_DIGEST,
                "kevs": list(cves),
                "record_path": path,
                "record_commit": "c" * 40,
                "pr_url": "https://github.com/bocklabs/trusted-images/pull/42",
                "merged_by": "approver",
                "merged_at": "2026-09-13T00:00:00Z",
                "issue_url": "https://github.com/bocklabs/trusted-images/issues/77",
                "issue_state": "open",
                "expires_at": "2026-09-18T00:00:00Z",
            },
        )
        self.decision["policy"]["acceptance"]["expires_at"] = "2026-09-14T01:00:00Z"
        self.decision_path.write_text(json.dumps(self.decision), encoding="utf-8")
        flags["--decision-sha256"] = hashlib.sha256(
            self.decision_path.read_bytes()
        ).hexdigest()
        self.out.unlink()
        self.assert_fails_closed(self.run_generator(flags), "expired")

    def test_legacy_multi_platform_records_remain_readable(self) -> None:
        legacy = (
            REPO_ROOT / "provenance" / "postgres-exporter" / "v0.20.1-bocklabs.1.json"
        )
        record = json.loads(legacy.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], SCHEMA)
        self.assertIn("linux/amd64", record["internal"]["platforms"])
        self.assertNotIn("selected_child_digest", record["upstream"])
        signed_era_marker = REPO_ROOT / "provenance" / "postgres-exporter" / "v0.20.1-bocklabs.5.json"
        self.assertNotIn("signing", json.loads(signed_era_marker.read_text()))

    def test_recovery_preserves_original_and_current_run(self) -> None:
        flags = self.flags()
        flags.update(
            {
                "--original-run-url": "https://example.invalid/runs/42",
                "--original-source-sha": "d" * 40,
                "--recovered-tag": "v0.20.1-bocklabs.1",
                "--recovered-digest": CHILD_DIGEST,
            }
        )
        result = self.run_generator(flags)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        record = json.loads(self.out.read_text(encoding="utf-8"))
        self.assertEqual(
            record["pipeline"]["original_run_url"], "https://example.invalid/runs/42"
        )
        self.assertEqual(record["recovery"]["recovered_digest"], CHILD_DIGEST)

    def test_bad_recovery_digest_writes_no_record(self) -> None:
        flags = self.flags()
        flags.update(
            {
                "--original-run-url": "https://example.invalid/runs/42",
                "--original-source-sha": "d" * 40,
                "--recovered-tag": "v0.20.1-bocklabs.1",
                "--recovered-digest": "sha256:" + "e" * 64,
            }
        )
        self.assert_fails_closed(self.run_generator(flags), "recovered-digest")

    def test_unpublished_decision_writes_no_record(self) -> None:
        flags = self.flags()
        self.decision["published"]["digest"] = None
        self.decision_path.write_text(json.dumps(self.decision), encoding="utf-8")
        flags["--decision-sha256"] = hashlib.sha256(
            self.decision_path.read_bytes()
        ).hexdigest()
        self.assert_fails_closed(self.run_generator(flags), "published")


if __name__ == "__main__":
    unittest.main()
