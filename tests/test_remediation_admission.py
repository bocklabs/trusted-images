"""Admission trust-boundary behavior."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/remediation_admission.py"


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.ready = self.work / "readiness.json"
        self.output = self.work / "output"
        self.findings = [{"class": "os-pkgs", "id": "CVE-2026-1234", "installed": "1",
                          "package": "openssl", "target": "root", "type": "debian"}]
        need = hashlib.sha256(json.dumps(self.findings, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.env = {**os.environ, "GITHUB_REPOSITORY": "acme/images", "GITHUB_SHA": "a" * 40,
                    "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_WORKFLOW_REF": "acme/images/.github/workflows/promote.yaml@refs/heads/main",
                    "INPUT_APP": "example", "INPUT_REQUEST_ID": "b" * 32,
                    "INPUT_REF": "ghcr.io/acme/example:v1@sha256:" + "c" * 64,
                    "INPUT_NEED_SHA256": need, "INPUT_FORCE_REPROMOTE": "false", "INPUT_RECOVER_TAG": "",
                    "INPUT_RECOVERY_RUN_ID": "", "INPUT_ACCEPTED_CANDIDATE_RUN_ID": "",
                    "REMEDIATION_APP_ID": "99", "GITHUB_OUTPUT": str(self.output),
                    "PYTHONDONTWRITEBYTECODE": "1", "FIXTURE": str(self.work / "github.json")}
        gh = self.work / "gh"
        gh.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
                      "f=json.load(open(os.environ['FIXTURE'])); p=sys.argv[2]\n"
                      "if f.get('api_error'): sys.exit(1)\n"
                      "k='checks' if '/check-runs?' in p else 'artifact' if '/artifacts/' in p else 'run'\n"
                      "print(json.dumps(f[k]))\n")
        gh.chmod(0o755)
        self.env["PATH"] = str(self.work) + os.pathsep + os.environ["PATH"]

    def call(self, command, **updates):
        args = [sys.executable, str(SCRIPT), command, "--output", str(self.ready)]
        if command == "await":
            args += ["--artifact-id", "900", "--timeout", "1"]
        return subprocess.run(args, capture_output=True, text=True, timeout=10, env={**self.env, **updates})

    def fixture(self):
        result = self.call("prepare")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        receipt = json.loads(self.ready.read_text())
        value = {**receipt, "verdict": "proceed", "findings": self.findings, "artifact_id": 900,
                 "issued_at": int(time.time()), "expires_at": int(time.time()) + 120}
        check = {"app": {"id": 99, "slug": "release"}, "head_sha": "a" * 40,
                 "external_id": f"remediation:{receipt['request_id']}:123:1:{receipt['nonce']}",
                 "name": "remediation-admission", "status": "completed", "conclusion": "success",
                 "output": {"summary": json.dumps(value)}}
        run = {"path": ".github/workflows/promote.yaml", "event": "workflow_dispatch", "head_branch": "main",
               "head_sha": "a" * 40, "run_attempt": 1, "status": "in_progress",
               "actor": {"login": "release[bot]"}, "triggering_actor": {"login": "release[bot]"}}
        artifact = {"id": 900, "expired": False,
                    "name": f"remediation-readiness-{receipt['request_id']}-123-1",
                    "workflow_run": {"id": 123, "head_sha": "a" * 40, "head_branch": "main"}}
        return {"run": run, "artifact": artifact, "checks": {"check_runs": [check]}}

    def run_fixture(self, fixture):
        Path(self.env["FIXTURE"]).write_text(json.dumps(fixture))
        self.output.write_text("")
        return self.call("await")

    def test_valid_bound_receipt_releases_candidate_and_preserves_nonce(self):
        fixture = self.fixture()
        before = self.ready.read_bytes()
        result = self.run_fixture(fixture)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("proceed=true", self.output.read_text())
        self.assertIn("force_repromote=true", self.output.read_text())
        self.assertEqual(self.ready.read_bytes(), before)
        self.assertEqual(self.ready.with_name("SHA256SUMS").read_text(),
                         hashlib.sha256(before).hexdigest() + "  readiness.json\n")

    def test_forged_replayed_expired_or_conflicting_receipts_fail_closed(self):
        fixture = self.fixture()
        mutations = {"request_id": "e" * 32, "run_attempt": 2, "nonce": "e" * 64,
                     "workflow_ref": "acme/images/.github/workflows/promote.yaml@refs/heads/feature",
                     "ref": "ghcr.io/acme/example:v1@sha256:" + "e" * 64,
                     "need_sha256": "e" * 64, "producer_sha": "e" * 40,
                     "expires_at": int(time.time()) - 1, "issued_at": 1, "artifact_id": 901,
                     "findings": [{**self.findings[0], "package": "forged"}]}
        for key, value in mutations.items():
            with self.subTest(binding=key):
                altered = copy.deepcopy(fixture)
                check = altered["checks"]["check_runs"][0]
                summary = json.loads(check["output"]["summary"])
                summary[key] = value
                check["output"]["summary"] = json.dumps(summary)
                self.assertNotEqual(self.run_fixture(altered).returncode, 0)
                self.assertNotIn("proceed=true", self.output.read_text())
        for kind in ("app", "actor", "external_id", "duplicate", "api_error"):
            with self.subTest(trust=kind):
                altered = copy.deepcopy(fixture)
                checks = altered["checks"]["check_runs"]
                if kind == "app":
                    checks[0]["app"]["id"] = 100
                elif kind == "actor":
                    altered["run"]["triggering_actor"]["login"] = "operator"
                elif kind == "external_id":
                    checks[0]["external_id"] += "replay"
                elif kind == "duplicate":
                    checks.append(copy.deepcopy(checks[0]))
                else:
                    altered["api_error"] = True
                self.assertNotEqual(self.run_fixture(altered).returncode, 0)
                self.assertNotIn("proceed=true", self.output.read_text())

    def test_manual_entry_and_pending_timeout_need_no_verdict(self):
        result = self.call("prepare", INPUT_REQUEST_ID="", INPUT_REF="", INPUT_NEED_SHA256="")
        self.assertEqual(result.returncode, 0)
        self.assertIn("proceed=true", self.output.read_text())
        self.assertNotIn("force_repromote=true", self.output.read_text())
        fixture = self.fixture()
        fixture["checks"]["check_runs"] = []
        result = self.run_fixture(fixture)
        self.assertEqual(result.returncode, 0)
        self.assertIn("admission timed out", result.stdout)
        self.assertNotIn("proceed=true", self.output.read_text())

    def test_automatic_inputs_cannot_mix_manual_controls_or_other_application(self):
        mutations = {"INPUT_FORCE_REPROMOTE": "true", "INPUT_RECOVER_TAG": "v1-bocklabs.1",
                     "INPUT_RECOVERY_RUN_ID": "123", "INPUT_ACCEPTED_CANDIDATE_RUN_ID": "123",
                     "INPUT_NEED_SHA256": "", "GITHUB_RUN_ATTEMPT": "2",
                     "INPUT_REF": "ghcr.io/acme/another:v1@sha256:" + "c" * 64}
        for key, value in mutations.items():
            with self.subTest(input=key):
                self.output.write_text("")
                self.assertNotEqual(self.call("prepare", **{key: value}).returncode, 0)
                self.assertNotIn("proceed=true", self.output.read_text())


if __name__ == "__main__":
    unittest.main()
