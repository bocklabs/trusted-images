#!/usr/bin/env python3
"""Candidate-decision policy tests using local scanner and OCI fixtures."""

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = REPO_ROOT / "scripts" / "evaluate_promotion.py"
def fixture_digest(value):
    raw = json.dumps(value, indent=2) + "\n"
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


CONFIG_VALUE = {"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": []}}
CONFIG_DIGEST = fixture_digest(CONFIG_VALUE)
CONFIG_SIZE = len((json.dumps(CONFIG_VALUE, indent=2) + "\n").encode())


def write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    return path


def child_manifest() -> dict:
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": CONFIG_DIGEST, "size": CONFIG_SIZE},
        "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": "sha256:" + "40" * 32, "size": 456}],
    }


def package(name, version, epoch=None, release=None):
    value = {"Name": name, "Version": version}
    if epoch is not None:
        value["Epoch"] = epoch
    if release is not None:
        value["Release"] = release
    return value


def report(vulnerabilities=None, packages=None, *, artifact_name="app@child", image_id=CONFIG_DIGEST, result_type="debian", os_family=None):
    packages = [package("libexample", "1.0")] if packages is None else packages
    family = result_type if os_family is None else os_family
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.74.0"},
        "ArtifactName": artifact_name,
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageID": image_id,
            "ImageConfig": {"architecture": "amd64", "os": "linux"},
            "OS": {"Family": family, "Name": "12", "EOSL": False},
        },
        "Results": [{
            "Target": f"app ({family} 12)",
            "Class": "os-pkgs",
            "Type": result_type,
            "Vulnerabilities": vulnerabilities or [],
            "Packages": packages,
        }],
    }


def vuln(cve, severity="HIGH", fixed="", source="debian", pkg_name="libexample"):
    return {
        "VulnerabilityID": cve,
        "PkgName": pkg_name,
        "InstalledVersion": "1.0",
        "FixedVersion": fixed,
        "Severity": severity,
        "SeveritySource": source,
    }


CHILD_DIGEST = fixture_digest(child_manifest())
CANDIDATE_DIGEST = CHILD_DIGEST
PATCHED_DIGEST = "sha256:" + "c" * 64
PATCHED_IMAGE_ID = "sha256:" + "d" * 64
TRIVY_ACTION_SHA = "ed142fd0673e97e23eac54620cfb913e5ce36c25"
TRIVY_DB_DIGEST = "sha256:" + "f" * 64


def kev_feed(cves=("CVE-2026-0001",)):
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.09.13",
        "dateReleased": "2026-09-13T00:00:00.00000Z",
        "count": len(cves),
        "vulnerabilities": [{"cveID": cve} for cve in cves],
    }


def acceptance_record(*, candidate_digest=CANDIDATE_DIGEST, kevs=("CVE-2026-0001",),
                      expires_at="2026-09-18T00:00:00Z", tracking_issue=77):
    return {
        "schema": "trusted-images.bocklabs.dev/risk-acceptance-v1",
        "candidateDigest": candidate_digest,
        "kevs": list(kevs),
        "reason": "Compensating controls while the upstream fix is pending",
        "expiresAt": expires_at,
        "likelihood": {"level": "MEDIUM", "rationale": "Exploit is public but the service is not exposed"},
        "impact": {"level": "HIGH", "rationale": "A successful exploit would expose service data"},
        "owner": "supply-chain-operator",
        "reviewNotes": ["Reviewed against the current incident report"],
        "trackingIssue": tracking_issue,
    }


def github_evidence(record, *, repository="bocklabs/trusted-images", merged_at="2026-09-13T00:00:00Z",
                    issue_state="open", issue_is_pull_request=False, merged_by="approver",
                    base_repository="bocklabs/trusted-images", base_ref="main"):
    raw = json.dumps(record, indent=2) + "\n"
    path = "risk-acceptances/app/" + hashlib.sha256(record["candidateDigest"].encode()).hexdigest() + "-" + \
        hashlib.sha256("\n".join(record["kevs"]).encode()).hexdigest() + ".json"
    pull_request = {
        "number": 42,
        "html_url": f"https://github.com/{repository}/pull/42",
        "state": "closed",
        "merged": True,
        "merged_at": merged_at,
        "merged_by": {"login": merged_by},
        "base_repository": base_repository,
        "base_ref": base_ref,
    }
    issue = {
        "number": record["trackingIssue"],
        "html_url": f"https://github.com/{repository}/issues/{record['trackingIssue']}",
        "state": issue_state,
        "is_pull_request": issue_is_pull_request,
    }
    return {
        "repository": repository,
        "path": path,
        "record_sha256": hashlib.sha256(raw.encode()).hexdigest(),
        "content_blob_sha": "b" * 40,
        "commit": {"sha": "c" * 40, "path": path, "blob_sha": "b" * 40},
        "associated_pull_requests": [pull_request],
        "pull_request": pull_request,
        "issue": issue,
    }


class PolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.child = write_json(self.tmp / "child.json", child_manifest())
        self.config = write_json(self.tmp / "config.json", CONFIG_VALUE)
        self.index = write_json(self.tmp / "index.json", {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": CHILD_DIGEST, "size": self.child.stat().st_size, "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:" + "21" * 32, "size": 301, "platform": {"os": "linux", "architecture": "arm64"}},
            ],
        })
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        self.full = write_json(self.tmp / "full.json", report())
        self.fixable = write_json(self.tmp / "fixable.json", report())
        self.after = self.tmp / "after-full.json"
        self.receipt = self.tmp / "scan-receipt.json"
        self.kev = write_json(self.tmp / "kev.json", kev_feed(()))
        self.acceptance = self.tmp / "risk-acceptance.json"
        self.github = self.tmp / "github-evidence.json"
        self.out = self.tmp / "candidate-decision.json"

    def run_policy(self, **changes):
        values = {
            "--app": "app",
            "--source-sha": "a" * 40,
            "--run-id": "123",
            "--run-attempt": "1",
            "--proposed-tag": "v1-bocklabs.1",
            "--index": str(self.index),
            "--upstream-index-digest": str(self.index_digest),
            "--child-manifest": str(self.child),
            "--child-config": str(self.config),
            "--full-report": str(self.full),
            "--fixable-report": str(self.fixable),
            "--kev": str(self.kev),
            "--kev-fetched-at": "2026-09-14T00:00:00Z",
            "--now": "2026-09-14T01:00:00Z",
            "--github-repository": "bocklabs/trusted-images",
            "--validation-result": "pass",
            "--out": str(self.out),
        }
        values.update(changes)
        argv = [sys.executable, str(EVALUATOR)]
        for key, value in values.items():
            if value is not None:
                argv += [key, value]
        if self.after.exists():
            argv += ["--after-full-report", str(self.after)]
        if self.receipt.exists():
            argv += ["--scan-receipt", str(self.receipt)]
        if self.acceptance.exists():
            argv += ["--acceptance", str(self.acceptance)]
        if self.github.exists():
            argv += ["--github-evidence", str(self.github)]
        return subprocess.run(argv, capture_output=True, text=True)

    def patched(self, before_vulns, after_vulns, before_pkgs, after_pkgs, *, result_type="debian", os_family=None, extra_after_results=()):
        before = report(before_vulns, before_pkgs, result_type=result_type, os_family=os_family)
        after = report(after_vulns, after_pkgs, artifact_name="app@candidate", image_id=PATCHED_IMAGE_ID, result_type=result_type, os_family=os_family)
        after["Results"].extend(extra_after_results)
        self.full = write_json(self.full, before)
        self.fixable = write_json(self.fixable, report(before_vulns, before_pkgs, result_type=result_type, os_family=os_family))
        self.after = write_json(self.after, after)
        self.receipt = write_json(self.receipt, {
            "trivy_action_sha": TRIVY_ACTION_SHA,
            "trivy_db_digest": TRIVY_DB_DIGEST,
            "trivy_db_updated_at": "2026-09-14T00:00:00Z",
            "before": {
                "artifact_name": before["ArtifactName"],
                "image_id": before["Metadata"]["ImageID"],
                "manifest_digest": CHILD_DIGEST,
                "report_sha256": hashlib.sha256(self.full.read_bytes()).hexdigest(),
            },
            "after": {
                "artifact_name": after["ArtifactName"],
                "image_id": after["Metadata"]["ImageID"],
                "manifest_digest": PATCHED_DIGEST,
                "report_sha256": hashlib.sha256(self.after.read_bytes()).hexdigest(),
            },
        })

    def test_clean_child_is_eligible_with_exact_schema(self):
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["reason"], "clean")
        self.assertEqual(decision["selected_child_digest"], CHILD_DIGEST)
        self.assertEqual(decision["candidate"]["digest"], CANDIDATE_DIGEST)
        self.assertIsNone(decision["published"]["digest"])
        self.assertFalse(decision["provenance"]["merged"])
        spec = importlib.util.spec_from_file_location("evaluate_promotion", EVALUATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_decision(decision)
        with self.assertRaises(ValueError):
            module.validate_decision({**decision, "unexpected": True})

    def test_no_fix_warnings_at_every_severity_remain_eligible(self):
        findings = [
            vuln("CVE-2026-0002", "UNKNOWN", source=""),
            vuln("CVE-2026-0003", "LOW"),
            vuln("CVE-2026-0004", "MEDIUM"),
            vuln("CVE-2026-0005", "HIGH"),
            vuln("CVE-2026-0006", "CRITICAL"),
        ]
        write_json(self.full, report(findings))
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertIn("no-fix", decision["reason"])
        for finding in findings:
            self.assertIn(f"{finding['VulnerabilityID']}:{finding['Severity']}:{finding['SeveritySource']}", decision["reason"])

    def test_trivy_omitted_eosl_field_is_eligible(self):
        value = report()
        del value["Metadata"]["OS"]["EOSL"]
        write_json(self.full, value)
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(self.out.read_text())["eligible"])

    def test_positive_fixable_blocks_until_patch_expansion(self):
        finding = vuln("CVE-2026-0007", "LOW", fixed="1.1")
        write_json(self.full, report([finding]))
        write_json(self.fixable, report([finding]))
        result = self.run_policy()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertIn("fixable", decision["reason"])
        self.assertEqual(decision["before"]["fixable_os"], ["linux/amd64|libexample|CVE-2026-0007"])

    def test_disabled_policy_mirrors_reason_without_waiving_gates(self):
        write_json(self.full, report([vuln("CVE-2026-0008", "CRITICAL")]))
        changes = {
            "--patch-policy": "disabled",
            "--patch-disabled-class": "unsupported",
            "--patch-disabled-detail": "No OS package manager",
        }
        result = self.run_policy(**changes)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertEqual(
            decision["patching"],
            {"disabled": True, "disabled_reason": {"class": "unsupported", "detail": "No OS package manager"}},
        )
        self.assertEqual(decision["copa"]["classification"], "not-required")
        self.assertFalse(decision["copa"]["original_child_input"])

        blocked = {
            "validation": dict(changes, **{"--validation-result": "fail"}),
            "KEV": dict(changes),
        }
        write_json(self.kev, kev_feed(("CVE-2026-0008",)))
        result = self.run_policy(**blocked["KEV"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(self.out.read_text())["reason"], "missing_kev_acceptance")

        result = self.run_policy(**blocked["validation"])
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("validation", json.loads(self.out.read_text())["reason"])

        for classification in ("eol", "gpg", "unknown"):
            with self.subTest(disabled_failure=classification):
                result = self.run_policy(**{
                    **changes,
                    "--copa-classification": classification,
                })
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                decision = json.loads(self.out.read_text())
                self.assertFalse(decision["eligible"])
                self.assertIn(classification, decision["reason"])

        finding = vuln("CVE-2026-0007", "LOW", fixed="1.1")
        write_json(self.full, report([finding]))
        write_json(self.fixable, report([finding]))
        write_json(self.kev, kev_feed(()))
        result = self.run_policy(**changes)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["copa"]["classification"], "not-required")
        self.assertFalse(decision["copa"]["original_child_input"])
        self.assertIn("unsupported", decision["reason"])
        self.assertEqual(decision["before"]["fixable_os"], ["linux/amd64|libexample|CVE-2026-0007"])
        spec = importlib.util.spec_from_file_location("evaluate_promotion", EVALUATOR)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_decision(decision)

    def test_patching_enabled_resolves_fixable_os_at_every_severity(self):
        for severity in ("UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                self.patched([vuln("CVE-2026-0007", severity, fixed="1.1")], [],
                             [package("libexample", "1.0")], [package("libexample", "1.1")])
                result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                decision = json.loads(self.out.read_text())
                self.assertTrue(decision["eligible"])
                self.assertTrue(decision["copa"]["original_child_input"])

    def test_disabled_eosl_blocks_without_an_after_report(self):
        value = report()
        value["Metadata"]["OS"]["EOSL"] = True
        write_json(self.full, value)
        result = self.run_policy(**{"--patch-policy": "disabled", "--patch-disabled-class": "unsupported",
                                    "--patch-disabled-detail": "No OS package manager"})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("EOSL", result.stdout + result.stderr)

    def test_copa_failure_classes_block_closed(self):
        finding = vuln("CVE-2026-0007", "LOW", fixed="1.1")
        write_json(self.full, report([finding]))
        write_json(self.fixable, report([finding]))
        for classification in ("unsupported", "no-fix", "eol", "gpg", "unknown"):
            with self.subTest(classification=classification):
                result = self.run_policy(**{"--copa-classification": classification})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                decision = json.loads(self.out.read_text())
                self.assertFalse(decision["eligible"])
                self.assertIn(classification, decision["reason"])
                self.assertEqual(decision["copa"]["classification"], classification)

    def test_kev_without_acceptance_blocks_without_publisher(self):
        write_json(self.full, report([vuln("CVE-2026-0001")]))
        write_json(self.kev, kev_feed(("CVE-2026-0001",)))
        result = self.run_policy()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertEqual(decision["reason"], "missing_kev_acceptance")
        self.assertEqual(decision["policy"]["kev"]["matched"], ["CVE-2026-0001"])

    def test_exact_unexpired_acceptance_clears_only_the_kev_gate(self):
        write_json(self.full, report([vuln("CVE-2026-0001")]))
        write_json(self.kev, kev_feed(("CVE-2026-0001",)))
        record = acceptance_record()
        self.acceptance = write_json(self.acceptance, record)
        self.github = write_json(self.github, github_evidence(record))
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertIn("no-fix warnings", decision["reason"])
        self.assertEqual(decision["policy"]["acceptance"], {
            "path": json.loads(self.github.read_text())["path"],
            "sha256": hashlib.sha256(self.acceptance.read_bytes()).hexdigest(),
            "candidate_digest": CANDIDATE_DIGEST,
            "kevs": ["CVE-2026-0001"],
            "expires_at": "2026-09-18T00:00:00Z",
            "commit_sha": "c" * 40,
            "pull_request": 42,
            "merged_at": "2026-09-13T00:00:00Z",
            "merged_by": "approver",
            "issue": 77,
        })

        result = self.run_policy(**{"--validation-result": "fail"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertIn("validation", decision["reason"])
        self.assertIsNotNone(decision["policy"]["acceptance"])

        record = acceptance_record(expires_at="2026-09-14T01:00:00Z")
        self.acceptance = write_json(self.acceptance, record)
        self.github = write_json(self.github, github_evidence(record))
        self.out.unlink()
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("expired", result.stdout + result.stderr)
        self.assertFalse(self.out.exists())

        record = acceptance_record(expires_at="2026-09-20T00:00:00Z")
        self.acceptance = write_json(self.acceptance, record)
        self.github = write_json(self.github, github_evidence(record))
        result = self.run_policy()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(json.loads(self.out.read_text())["eligible"])

    def test_acceptance_expiry_digest_kevs_and_issue_fail_closed(self):
        write_json(self.full, report([vuln("CVE-2026-0001"), vuln("CVE-2026-0002")]))
        write_json(self.kev, kev_feed(("CVE-2026-0001", "CVE-2026-0002")))
        cases = {
            "expired": {"expires_at": "2026-09-14T00:30:00Z"},
            "candidate digest": {"candidate_digest": PATCHED_DIGEST},
            "KEV set": {"kevs": ["CVE-2026-0001"]},
            "closed issue": {"issue_state": "closed"},
            "issue is a PR": {"issue_is_pull_request": True},
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                record = acceptance_record(kevs=("CVE-2026-0001", "CVE-2026-0002"))
                evidence = github_evidence(record)
                if "expires_at" in change:
                    record["expiresAt"] = change["expires_at"]
                if "candidate_digest" in change:
                    record["candidateDigest"] = change["candidate_digest"]
                if "kevs" in change:
                    record["kevs"] = change["kevs"]
                self.acceptance = write_json(self.acceptance, record)
                evidence["record_sha256"] = hashlib.sha256(self.acceptance.read_bytes()).hexdigest()
                for key, value in change.items():
                    if key in ("issue_state", "issue_is_pull_request"):
                        evidence["issue"]["state" if key == "issue_state" else "is_pull_request"] = value
                self.github = write_json(self.github, evidence)
                result = self.run_policy()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                expected = {
                    "expired": "expired",
                    "candidate digest": "candidate digest",
                    "KEV set": "KEV set",
                    "closed issue": "tracking issue",
                    "issue is a PR": "tracking issue",
                }[label]
                self.assertIn(expected, result.stdout + result.stderr)
                if label == "expired":
                    self.assertFalse(self.out.exists())

    def test_acceptance_schema_and_trusted_github_identity_fail_closed(self):
        write_json(self.full, report([vuln("CVE-2026-0001")]))
        write_json(self.kev, kev_feed(("CVE-2026-0001",)))
        record = acceptance_record()
        cases = {
            "unknown field": lambda value: value.update(unexpected=True),
            "wrong path": lambda value: value.update(path="risk-acceptances/app/other.json"),
            "ambiguous PR": lambda value: value["associated_pull_requests"].append(dict(value["pull_request"], number=43)),
            "forged merged_by": lambda value: value["pull_request"].update(merged_by={"login": ""}),
            "wrong repository": lambda value: value.update(repository="other/example"),
            "non-main base": lambda value: value["pull_request"].update(base_ref="feature"),
            "unmerged PR": lambda value: value["pull_request"].update(merged=False),
            "commit file mismatch": lambda value: value["commit"].update(blob_sha="d" * 40),
            "acceptance too old": lambda value: value["pull_request"].update(merged_at="2026-09-01T00:00:00Z"),
        }
        expected_messages = {
            "unknown field": "unknown",
            "wrong path": "wrong path",
            "ambiguous PR": "ambiguous",
            "forged merged_by": "merged_by",
            "wrong repository": "wrong repository",
            "non-main base": "does not target repository main",
            "unmerged PR": "is not merged",
            "commit file mismatch": "commit file mismatch",
            "acceptance too old": "acceptance too old",
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                self.acceptance = write_json(self.acceptance, record)
                evidence = github_evidence(record)
                mutate(evidence)
                self.github = write_json(self.github, evidence)
                result = self.run_policy()
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(expected_messages[label], result.stdout + result.stderr)

    def test_malformed_stale_and_missing_kev_fail_closed(self):
        malformed = kev_feed(("CVE-2026-0001",))
        malformed["count"] = 2
        write_json(self.kev, malformed)
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("[policy]", result.stdout + result.stderr)
        self.assertFalse(self.out.exists())

        write_json(self.kev, kev_feed(()))
        result = self.run_policy(**{"--kev-fetched-at": "2026-09-12T00:00:00Z"})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("24 hours", result.stdout + result.stderr)

        result = self.run_policy(**{"--kev": str(self.tmp / "missing.json")})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("KEV", result.stdout + result.stderr)

    def test_index_must_resolve_one_exact_amd64_child(self):
        index = json.loads(self.index.read_text())
        index["manifests"].append(index["manifests"][0])
        self.index = write_json(self.index, index)
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("exactly one linux/amd64", result.stdout + result.stderr)

        index["manifests"].pop()
        index["manifests"][0]["platform"]["variant"] = "v8"
        self.index = write_json(self.index, index)
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("variant", result.stdout + result.stderr)

    def test_descriptor_config_and_platform_disagreement_fail(self):
        index = json.loads(self.index.read_text())
        original = index["manifests"][0]["digest"]
        index["manifests"][0]["digest"] = "sha256:" + "22" * 32
        self.index = write_json(self.index, index)
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("child manifest digest", result.stdout + result.stderr)

        index["manifests"][0]["digest"] = original
        self.index = write_json(self.index, index)
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        config = json.loads(self.config.read_text())
        config["architecture"] = "arm64"
        self.config = write_json(self.config, config)
        child = json.loads(self.child.read_text())
        child["config"]["digest"] = fixture_digest(config)
        child["config"]["size"] = self.config.stat().st_size
        self.child = write_json(self.child, child)
        index = json.loads(self.index.read_text())
        index["manifests"][0]["digest"] = fixture_digest(child)
        index["manifests"][0]["size"] = self.child.stat().st_size
        self.index = write_json(self.index, index)
        self.index_digest = "sha256:" + hashlib.sha256(self.index.read_bytes()).hexdigest()
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("platform", result.stdout + result.stderr)

    def test_validation_failure_blocks(self):
        result = self.run_policy(**{"--validation-result": "fail"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertIn("validation", decision["reason"])

    def test_failed_patched_validation_never_runs_publication(self):
        self.patched(
            [vuln("CVE-2026-0007", fixed="1.1")],
            [],
            [package("libexample", "1.0")],
            [package("libexample", "1.1")],
        )
        result = self.run_policy(**{"--validation-result": "fail", "--candidate-digest": PATCHED_DIGEST})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        spool = self.tmp / "publisher.jsonl"
        publisher = self.tmp / "fake-skopeo"
        publisher.write_text(
            "#!/usr/bin/env python3\nfrom pathlib import Path\nPath(r'" + str(spool) + "').write_text('ran')\n",
            encoding="utf-8",
        )
        publisher.chmod(0o755)
        if decision["eligible"]:
            subprocess.run([str(publisher), "copy", decision["candidate"]["digest"]], check=True)
        self.assertFalse(spool.exists())

    def test_conflicting_duplicate_package_identity_fails_closed(self):
        self.full = write_json(self.full, report([vuln("CVE-2026-0007", fixed="1.1")], [
            package("libexample", "1.0"),
            package("libexample", "1.1"),
        ]))
        result = self.run_policy()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("conflicting duplicate package", result.stdout + result.stderr)

    def test_valid_resolved_change_permits_upgrade_and_new_tooling(self):
        supplied = vuln("CVE-2026-0007", fixed="1.1")
        self.patched(
            [supplied],
            [],
            [package("libexample", "1.0")],
            [package("libexample", "1.1", epoch=1, release="1"), package("copa-tooling", "1.0")],
        )
        result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertTrue(decision["eligible"])
        self.assertEqual(decision["reason"], "patched")
        self.assertEqual(decision["copa"]["classification"], "succeeded")
        self.assertTrue(decision["copa"]["original_child_input"])
        self.assertEqual(decision["delta"]["resolved"], ["linux/amd64|libexample|CVE-2026-0007"])
        self.assertEqual(decision["delta"]["cves"]["resolved"], ["CVE-2026-0007"])
        self.assertEqual(decision["packages"]["changes"], [
            {"ecosystem": "debian", "name": "copa-tooling", "change": "added", "before": None, "after": "1.0"},
            {"ecosystem": "debian", "name": "libexample", "change": "upgraded", "before": "1.0", "after": "1:1.1-1"},
        ])
        self.assertEqual(decision["packages"]["downgrades"], [])

    def test_low_severity_new_application_cve_blocks(self):
        application = {
            "Target": "app (pip)",
            "Class": "lang-pkgs",
            "Type": "pip",
            "Packages": [{"Name": "appdep", "Version": "2.0"}],
            "Vulnerabilities": [vuln("CVE-2026-0008", "LOW", source="pip", pkg_name="appdep")],
        }
        self.patched(
            [vuln("CVE-2026-0007", fixed="1.1")],
            [],
            [package("libexample", "1.0")],
            [package("libexample", "1.1")],
            extra_after_results=[application],
        )
        result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertIn("introduced", decision["reason"])
        self.assertEqual(decision["delta"]["introduced"], ["linux/amd64|appdep|CVE-2026-0008"])
        self.assertEqual(decision["delta"]["cves"]["introduced"], ["CVE-2026-0008"])

    def test_unresolved_supplied_cve_blocks(self):
        supplied = vuln("CVE-2026-0007", fixed="1.1")
        moved = vuln("CVE-2026-0007", fixed="1.1", pkg_name="libother")
        self.patched(
            [supplied],
            [moved],
            [package("libexample", "1.0")],
            [package("libexample", "1.1"), package("libother", "1.0")],
        )
        result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        decision = json.loads(self.out.read_text())
        self.assertFalse(decision["eligible"])
        self.assertIn("unresolved", decision["reason"])
        self.assertEqual(decision["delta"]["unresolved_fixable"], ["linux/amd64|libother|CVE-2026-0007"])

    def test_epoch_release_and_alpine_downgrades_block(self):
        cases = (
            ("debian", "1:2.0-1", "2.0-1"),
            ("redhat", "1:1.0-2.el9", "1:1.0-1.el9"),
            ("alpine", "1.2.3-r2", "1.2.3-r1"),
        )
        for ecosystem, before_version, after_version in cases:
            with self.subTest(ecosystem=ecosystem):
                self.patched(
                    [vuln("CVE-2026-0007", fixed="1.1")],
                    [],
                    [package("libexample", before_version)],
                    [package("libexample", after_version)],
                    result_type=ecosystem,
                )
                result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                decision = json.loads(self.out.read_text())
                self.assertFalse(decision["eligible"])
                self.assertIn("downgrade", decision["reason"])
                self.assertEqual(decision["packages"]["downgrades"], [{
                    "ecosystem": ecosystem,
                    "name": "libexample",
                    "change": "downgraded",
                    "before": before_version,
                    "after": after_version,
                }])

    def test_invalid_package_inventory_fails_closed(self):
        before = [package("libexample", "1.0")]
        cases = {
            "unsupported ecosystem": {"result_type": "fedora"},
            "missing package inventory": {"remove_packages": True},
            "malformed version": {"packages": [package("libexample", "not-a-version")]},
            "ambiguous package identity": {"packages": before + [package("libexample", "1.1")]},
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                self.patched(
                    [vuln("CVE-2026-0007", fixed="1.1")],
                    [],
                    before,
                    change.get("packages", [package("libexample", "1.1")]),
                    result_type=change.get("result_type", "debian"),
                )
                if change.get("remove_packages"):
                    after = json.loads(self.after.read_text())
                    after["Results"][0].pop("Packages")
                    self.after = write_json(self.after, after)
                    receipt = json.loads(self.receipt.read_text())
                    receipt["after"]["report_sha256"] = hashlib.sha256(self.after.read_bytes()).hexdigest()
                    self.receipt = write_json(self.receipt, receipt)
                result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(label, result.stdout + result.stderr)

    def test_report_identity_platform_receipt_and_eosl_are_validated(self):
        self.patched(
            [vuln("CVE-2026-0007", fixed="1.1")],
            [],
            [package("libexample", "1.0")],
            [package("libexample", "1.1")],
        )
        original_after = json.loads(self.after.read_text())
        original_receipt = json.loads(self.receipt.read_text())
        mutations = {
            "platform": lambda after, receipt: after["Metadata"]["ImageConfig"].update(architecture="arm64"),
            "EOSL": lambda after, receipt: after["Metadata"]["OS"].update(EOSL=True),
            "image identity": lambda after, receipt: after.update(ArtifactName="wrong@candidate"),
            "Trivy version": lambda after, receipt: after.update(Trivy={"Version": "0.73.0"}),
            "action receipt": lambda after, receipt: receipt.update(trivy_action_sha="f" * 40),
            "manifest receipt": lambda after, receipt: receipt["after"].update(manifest_digest=CHILD_DIGEST),
            "report receipt": lambda after, receipt: after.update(ArtifactName="tampered@candidate"),
        }
        for label, mutate in mutations.items():
            with self.subTest(check=label):
                after = json.loads(json.dumps(original_after))
                receipt = json.loads(json.dumps(original_receipt))
                mutate(after, receipt)
                self.after = write_json(self.after, after)
                self.receipt = write_json(self.receipt, receipt)
                result = self.run_policy(**{"--candidate-digest": PATCHED_DIGEST})
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(label, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
