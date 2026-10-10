"""Digest-bound signing gate and publisher contract."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "sha256:" + "a" * 64
IMAGE = f"ghcr.io/bocklabs/example@{DIGEST}"
IDENTITY = ROOT / "config/signing-identity.json"
GATE = ROOT / "scripts/promote_signing_gate.py"
COSIGN_RELEASE = next(step["with"]["cosign-release"] for step in yaml.safe_load(
    (ROOT / ".github/workflows/promote-publish.yaml").read_text()
)["jobs"]["promote"]["steps"] if step["name"] == "Install pinned Cosign")


def bundle(content):
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {"rawBytes": "Y2VydA=="},
            "tlogEntries": [{
                "logIndex": "42", "logId": {"keyId": "bG9n"},
                "inclusionPromise": {"signedEntryTimestamp": "c2V0"},
            }],
        },
        **content,
    }


class SigningGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.subject_digest = {"sha256": DIGEST[7:]}
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "ghcr.io/bocklabs/example", "digest": self.subject_digest}],
            "predicateType": "https://cyclonedx.org/bom",
            "predicate": {"bomFormat": "CycloneDX", "specVersion": "1.6"},
        }
        self.signature_statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"digest": {"sha256": DIGEST[7:]}}],
            "predicateType": "https://sigstore.dev/cosign/sign/v1", "predicate": {},
        }
        self.signature = bundle({"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json",
            "payload": base64.b64encode(json.dumps(self.signature_statement).encode()).decode(),
            "signatures": [{"sig": "c2ln"}]}})
        self.attestation = bundle({"dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(json.dumps(self.statement).encode()).decode(), "signatures": [{"sig": "c2ln"}]}})
        (self.dir / "sign-bundle.json").write_text(json.dumps(self.signature))
        (self.dir / "sbom-bundle.json").write_text(json.dumps(self.attestation))
        (self.dir / "sbom.json").write_text(json.dumps(self.statement["predicate"]))
        fake = self.dir / "cosign"
        fake.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
scenario = os.environ.get("SCENARIO", "success")
root = pathlib.Path.cwd()
if args[0] in ("verify", "verify-attestation"):
    if "--certificate-identity" not in args or "--certificate-oidc-issuer" not in args:
        sys.exit(1)
    if args[args.index("--certificate-identity") + 1] != os.environ["EXPECTED_IDENTITY"] or args[args.index("--certificate-oidc-issuer") + 1] != os.environ["EXPECTED_ISSUER"]:
        sys.exit(1)
if args[0] == "version":
    print("GitVersion: broken" if scenario == "bad-version" else "GitVersion: " + os.environ["EXPECTED_COSIGN_VERSION"])
elif args[0] == "verify" and scenario in ("missing-signature", "command-error"):
    sys.exit(1)
elif args[0] == "verify":
    print(json.dumps([{"critical": {"image": {"docker-manifest-digest": os.environ["DIGEST"]}, "type": "https://sigstore.dev/cosign/sign/v1"}}]))
elif args[0] == "verify-attestation" and scenario == "missing-attestation":
    sys.exit(1)
elif args[0] == "verify-attestation":
    statement = json.loads((root / "statement.json").read_text())
    if scenario == "multiple":
        older = json.loads(json.dumps(statement))
        older["predicate"]["specVersion"] = "1.5"
        print(json.dumps({"payload": __import__("base64").b64encode(json.dumps(older).encode()).decode()}))
    print(json.dumps({"payload": __import__("base64").b64encode(json.dumps(statement).encode()).decode()}))
elif args[:2] == ["download", "attestation"]:
    path = "sign-bundle.json" if args[args.index("--predicate-type") + 1] == "https://sigstore.dev/cosign/sign/v1" else "sbom-bundle.json"
    attachment = json.loads((root / path).read_text())
    if scenario == "detached-attachment":
        attachment["dsseEnvelope"]["signatures"][0]["sig"] = "b3RoZXI="
    elif scenario == "wrong-download-digest":
        payload = json.loads(__import__("base64").b64decode(attachment["dsseEnvelope"]["payload"]))
        payload["subject"][0]["digest"]["sha256"] = "b" * 64
        attachment["dsseEnvelope"]["payload"] = __import__("base64").b64encode(json.dumps(payload).encode()).decode()
    elif scenario == "malformed-download":
        attachment = {"dsseEnvelope": {"payload": []}}
    if scenario == "multiple":
        older = json.loads(json.dumps(attachment))
        older["dsseEnvelope"]["signatures"][0]["sig"] = "b2xk"
        print(json.dumps(older))
    print(json.dumps(attachment))
else:
    sys.exit(2)
''')
        fake.chmod(0o755)
        (self.dir / "statement.json").write_text(json.dumps(self.statement))

    def run_gate(self, scenario="success", image=IMAGE):
        identity = json.loads(IDENTITY.read_text())
        env = {**os.environ, "PATH": str(self.dir) + os.pathsep + os.environ["PATH"], "SCENARIO": scenario, "DIGEST": DIGEST,
               "EXPECTED_IDENTITY": identity["certificate_identity"], "EXPECTED_ISSUER": identity["certificate_oidc_issuer"],
               "EXPECTED_COSIGN_VERSION": COSIGN_RELEASE}
        return subprocess.run([
            sys.executable, str(GATE), "--image", image,
            "--identity-config", str(IDENTITY), "--sign-bundle", "sign-bundle.json",
            "--sbom-bundle", "sbom-bundle.json", "--predicate", "sbom.json",
            "--out", "signing-evidence.json",
        ], cwd=self.dir, env=env, capture_output=True, text=True)

    def test_success_records_digest_identity_and_attachments(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.dir / "signing-evidence.json").read_text())
        self.assertEqual(evidence["result"], "pass")
        self.assertEqual(evidence["image"], IMAGE)
        self.assertEqual(evidence["digest"], DIGEST)
        self.assertEqual(evidence["certificate_identity"], json.loads(IDENTITY.read_text())["certificate_identity"])
        self.assertEqual(evidence["certificate_oidc_issuer"], json.loads(IDENTITY.read_text())["certificate_oidc_issuer"])
        self.assertEqual(evidence["cosign_version"], COSIGN_RELEASE)
        self.assertEqual(evidence["signature"]["rekor"]["log_index"], 42)
        self.assertEqual(evidence["sbom_attestation"]["predicate_type"], "https://cyclonedx.org/bom")
        self.assertEqual(evidence["sbom_attestation"]["predicate_sha256"], hashlib.sha256((self.dir / "sbom.json").read_bytes()).hexdigest())
        for section in ("signature", "sbom_attestation"):
            self.assertEqual(len(evidence[section]["bundle_sha256"]), 64)
        self.assertEqual(evidence["signature"]["attachment_sha256"], hashlib.sha256((self.dir / "signature-attachment.json").read_bytes()).hexdigest())
        self.assertEqual(evidence["sbom_attestation"]["attachment_sha256"], hashlib.sha256((self.dir / "sbom-attestation-attachment.json").read_bytes()).hexdigest())

    def test_multiple_attestations_select_current_bundle_and_stable_attachment_bytes(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = json.loads((self.dir / "signing-evidence.json").read_text())
        result = self.run_gate("multiple")
        self.assertEqual(result.returncode, 0, result.stderr)
        current = json.loads((self.dir / "signing-evidence.json").read_text())
        for section in ("signature", "sbom_attestation"):
            self.assertEqual(current[section]["attachment_sha256"], original[section]["attachment_sha256"])
        self.assertEqual(len((self.dir / "signature-attachment.json").read_bytes().splitlines()), 1)
        self.assertEqual(len((self.dir / "sbom-attestation-attachment.json").read_bytes().splitlines()), 1)

    def test_missing_artifacts_and_command_error_fail(self):
        for scenario in ("missing-signature", "missing-attestation", "command-error", "detached-attachment", "wrong-download-digest", "malformed-download", "bad-version"):
            with self.subTest(scenario=scenario):
                result = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0)
                evidence = json.loads((self.dir / "signing-evidence.json").read_text())
                self.assertEqual(evidence["result"], "fail")
                self.assertNotIn("signature", evidence)
                if scenario == "malformed-download":
                    self.assertIn("not a DSSE envelope", evidence["reason"])
                elif scenario == "wrong-download-digest":
                    self.assertIn("differs from local bundle", evidence["reason"])
                elif scenario == "detached-attachment":
                    self.assertIn("differs from local bundle", evidence["reason"])

    def test_bad_digest_or_bundle_fails(self):
        self.subject_digest["sha256"] = "b" * 64
        (self.dir / "statement.json").write_text(json.dumps(self.statement))
        self.assertNotEqual(self.run_gate().returncode, 0)
        self.signature["verificationMaterial"]["tlogEntries"] = []
        (self.dir / "sign-bundle.json").write_text(json.dumps(self.signature))
        self.assertNotEqual(self.run_gate().returncode, 0)
        (self.dir / "sign-bundle.json").write_text("{")
        self.assertNotEqual(self.run_gate().returncode, 0)
        self.assertNotEqual(self.run_gate(image="ghcr.io/bocklabs/example:latest").returncode, 0)

    def example_record(self):
        record = json.loads((ROOT / "provenance/postgres-exporter/current.json").read_bytes())
        record.update(app="example", upstream={**record["upstream"], "tag": "v1"})
        record["internal"].update(package="ghcr.io/bocklabs/example", tag="v1-bocklabs.1", digest=DIGEST)
        record["signing"]["image_signature"]["attachment_sha256"] = hashlib.sha256((json.dumps(self.signature) + "\n").encode()).hexdigest()
        record["signing"]["sbom_attestation"]["attachment_sha256"] = hashlib.sha256((json.dumps(self.attestation) + "\n").encode()).hexdigest()
        return record

    def test_provenance_writeback_preserves_existing_main_record(self):
        steps = yaml.safe_load((ROOT / ".github/workflows/promote-publish.yaml").read_text())["jobs"]["promote"]["steps"]
        writeback = next(step["run"] for step in steps if step["name"] == "Open provenance PR for operator review")
        writeback = writeback.replace("${{ steps.app-token.outputs.token }}", "test-token")
        record = self.dir / "provenance/example/current.json"
        record.parent.mkdir(parents=True)
        history = self.dir / "history.json"
        history.write_text(json.dumps(self.example_record()) + "\n")
        spool = self.dir / "git-calls"
        fake = self.dir / "git"
        fake.write_text('#!/bin/sh\necho "$1" >> "$SPOOL"\ncase "$1" in\nshow) cat "$HISTORY";;\nrev-parse) printf "%040d\\n" 1;;\nls-tree) echo provenance/example/current.json;;\nconfig|fetch|merge-base) exit 0;;\n*) exit 9;;\nesac\n')
        fake.chmod(0o755)
        env = {**os.environ, "PATH": str(self.dir) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"],
               "APP": "example", "INTERNAL_TAG": "v1-bocklabs.1", "REPO": "bocklabs/trusted-images",
               "SKIP_COPY": "true", "RECOVER_TAG": "", "CANDIDATE_DIGEST": DIGEST,
               "EXPECTED_IDENTITY": json.loads(IDENTITY.read_text())["certificate_identity"],
               "EXPECTED_ISSUER": json.loads(IDENTITY.read_text())["certificate_oidc_issuer"], "DIGEST": DIGEST,
               "HISTORY": str(history), "SPOOL": str(spool),
               "GITHUB_STEP_SUMMARY": str(self.dir / "summary"), "GITHUB_OUTPUT": str(self.dir / "output")}
        (self.dir / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        for data, expected in ((history.read_text(), 0),):
            record.write_text(data)
            spool.write_text("")
            result = subprocess.run(["bash", "-c", writeback], cwd=self.dir, env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertNotIn("push", spool.read_text().splitlines())
            self.assertNotIn("commit", spool.read_text().splitlines())
            if expected:
                self.assertIn("immutable provenance", result.stdout)
        signing = next(step["run"] for step in steps if step["name"] == "Sign and attest published digest")
        gate = next(step["run"] for step in steps if step["name"] == "Verify signing evidence")
        for reuse, expected in (("true", 0), ("false", 1)):
            result = subprocess.run(["bash", "-c", signing], cwd=self.dir,
                                    env={**env, "SKIP_COPY": reuse, "CANDIDATE_DIGEST": DIGEST},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(record.read_bytes(), history.read_bytes())
        for scenario, expected in (("success", 0), ("missing-signature", 1)):
            result = subprocess.run(["bash", "-c", gate], cwd=self.dir,
                                    env={**env, "SCENARIO": scenario}, capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(json.loads((self.dir / "signing-evidence.json").read_text())["result"], "pass" if expected == 0 else "fail")
            self.assertEqual(record.read_bytes(), history.read_bytes())

    def test_workflow_contract(self):
        caller_text = (ROOT / ".github/workflows/promote.yaml").read_text()
        publisher_text = (ROOT / ".github/workflows/promote-publish.yaml").read_text()
        candidate = yaml.safe_load((ROOT / ".github/workflows/promote-candidate.yaml").read_text())
        caller = yaml.safe_load(caller_text)
        publisher = yaml.safe_load(publisher_text)
        self.assertEqual(json.loads(IDENTITY.read_text()), {
            "certificate_identity": "https://github.com/bocklabs/trusted-images/.github/workflows/promote-publish.yaml@refs/heads/main",
            "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
        })
        self.assertEqual(caller["permissions"]["id-token"], "write")
        self.assertEqual(publisher["permissions"]["id-token"], "write")
        self.assertEqual(publisher["jobs"]["promote"]["permissions"]["id-token"], "write")
        self.assertNotIn("id-token", candidate["jobs"]["validate"]["permissions"])
        steps = publisher["jobs"]["promote"]["steps"]
        names = [step["name"] for step in steps]
        self.assertLess(names.index("Anonymous-pull probe"), names.index("Sign and attest published digest"))
        self.assertLess(names.index("Sign and attest published digest"), names.index("Verify signing evidence"))
        self.assertLess(names.index("Verify signing evidence"), names.index("Write the verified publication digest into the decision"))
        by_name = {step["name"]: step for step in steps}
        sign = by_name["Sign and attest published digest"]
        gate = by_name["Verify signing evidence"]
        decision = by_name["Write the verified publication digest into the decision"]
        self.assertNotIn("continue-on-error", sign)
        self.assertNotIn("continue-on-error", gate)
        self.assertEqual(decision["if"], "${{ success() && steps.signing-gate.outcome == 'success' }}")
        self.assertIn('IMAGE="ghcr.io/bocklabs/${APP}@${CANDIDATE_DIGEST}"', sign["run"])
        self.assertIn('cosign sign --yes --bundle sign-bundle.json "${IMAGE}"', sign["run"])
        self.assertIn('cosign attest --yes --bundle sbom-bundle.json', sign["run"])
        self.assertIn('--image "${IMAGE}"', gate["run"])
        self.assertIn('config/signing-identity.json', gate["run"])
        upload = by_name["Upload signing evidence artifact"]
        self.assertEqual(upload["if"], "always()")
        self.assertIn("signing-evidence.json", upload["with"]["path"])
        summary = by_name["Job summary evidence panel"]
        self.assertIn("SIGNING_GATE_RESULT", summary["env"])
        self.assertIn("SIGNING_LINE", summary["run"])
        self.assertIn("REASON", summary["run"])
        self.assertRegex(publisher_text, r"sigstore/cosign-installer@[a-f0-9]{40}")
        self.assertRegex(COSIGN_RELEASE, r"^v\d+\.\d+\.\d+$")

    def test_changed_current_uses_owned_pr_lease_and_exact_auto_merge(self):
        steps = yaml.safe_load((ROOT / ".github/workflows/promote-publish.yaml").read_text())["jobs"]["promote"]["steps"]
        writeback = next(s["run"] for s in steps if s["name"] == "Open provenance PR for operator review").replace("${{ steps.app-token.outputs.token }}", "fixture-token")
        auto_merge = next(s["run"] for s in steps if s["name"] == "Auto-merge signed provenance PR")
        previous = self.example_record()
        generated = json.loads(json.dumps(previous))
        generated["internal"]["tag"] = "v1-bocklabs.2"
        generated["promoted_at"] = "2099-01-01T00:00:00Z"
        record = self.dir / "provenance/example/current.json"
        record.parent.mkdir(parents=True)
        record.write_text(json.dumps(previous))
        (self.dir / "previous.json").write_text(json.dumps(previous))
        (self.dir / "inventory").symlink_to(ROOT / "inventory", target_is_directory=True)
        from tests.test_provenance import valid_decision
        decision = valid_decision()
        decision["policy"]["kev"]["catalog"] = {"url": "https://example.test/kev", "sha256": "a" * 64,
            "catalog_version": "1", "date_released": "2026-01-01T00:00:00Z", "fetched_at": "2026-01-01T00:00:00Z"}
        (self.dir / "candidate-decision.json").write_text(json.dumps(decision))
        (self.dir / "scripts").symlink_to(ROOT / "scripts", target_is_directory=True)
        git = self.dir / "git"
        git.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
a=sys.argv[1:]; root=pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root/'calls').open('a') as f: f.write(json.dumps(['git',*a])+'\\n')
if a[0]=='rev-parse': print(('3' if a[1]=='HEAD' else '1')*40)
elif a[0]=='ls-remote': print('2'*40+'\trefs/heads/provenance/current/example')
elif a[0]=='ls-tree': print('provenance/example/current.json' if a[-1].endswith('/current.json') else '')
elif a[0]=='show': sys.stdout.write((root/('pending.json' if a[1].startswith('FETCH_HEAD:') else 'previous.json')).read_text())
elif a[0]=='log' and '--format=%ae' in a: print('bocklabs-release[bot]@invalid.test' if os.environ.get('FOREIGN') else '302587774+bocklabs-release[bot]@users.noreply.github.com')
elif a[0]=='diff' and '--name-only' in a: print('provenance/example/current.json')
elif a[0]=='diff' and '--quiet' in a: sys.exit(1)
''')
        gh = self.dir / "gh"
        gh.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
a=sys.argv[1:]; root=pathlib.Path(os.environ['FIXTURE_ROOT'])
with (root/'calls').open('a') as f: f.write(json.dumps(['gh',*a])+'\\n')
if a[:2]==['pr','list']: print('https://example.test/pull/1')
elif a[:2]==['pr','view']: print('true')
''')
        git.chmod(0o755)
        gh.chmod(0o755)
        env = {**os.environ, "PATH": f"{self.dir}:{Path(sys.executable).parent}:{os.environ['PATH']}",
               "FIXTURE_ROOT": str(self.dir), "APP": "example", "INTERNAL_TAG": "v1-bocklabs.2",
               "CANDIDATE_DIGEST": DIGEST, "SKIP_COPY": "false", "RECOVER_TAG": "", "REPO": "bocklabs/trusted-images",
               "RUN_URL": "https://example.test/runs/2", "GITHUB_OUTPUT": str(self.dir / "output"),
               "GITHUB_STEP_SUMMARY": str(self.dir / "summary")}
        pending = json.loads(json.dumps(generated))
        pending["pipeline"]["run_url"] = "https://example.test/original-publication"
        for scenario in ("owned", "foreign", "stale"):
            (self.dir / "generated-provenance.json").write_text(json.dumps(generated))
            (self.dir / "pending.json").write_text(json.dumps(pending))
            (self.dir / "calls").write_text("")
            before = record.read_bytes()
            if scenario == "stale":
                newer = json.loads(json.dumps(pending))
                newer["internal"]["tag"] = "v1-bocklabs.3"
                newer["promoted_at"] = "2100-01-01T00:00:00Z"
                (self.dir / "pending.json").write_text(json.dumps(newer))
            result = subprocess.run(["bash", "-c", writeback], cwd=self.dir, env={**env, "FOREIGN": "1" if scenario == "foreign" else ""}, capture_output=True, text=True)
            calls = [json.loads(line) for line in (self.dir / "calls").read_text().splitlines()]
            if scenario != "owned":
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(any(c[:2] == ["git", "push"] for c in calls))
                self.assertEqual(record.read_bytes(), before)
                continue
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(record.read_bytes()), pending)
            self.assertTrue(any(c[:2] == ["git", "push"] and '--force-with-lease=refs/heads/provenance/current/example:' + '2'*40 in c for c in calls))
            self.assertTrue(any(c[:3] == ["gh", "pr", "edit"] and "--title" in c for c in calls))
            result = subprocess.run(["bash", "-c", auto_merge], cwd=self.dir, env={**env, "HEAD_SHA": "3" * 40, "PR_URL": "https://example.test/pull/1"}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(["gh", "pr", "merge", "--auto", "--merge", "--match-head-commit", "3" * 40, "https://example.test/pull/1"], [json.loads(line) for line in (self.dir / "calls").read_text().splitlines()])
        publisher_text = (ROOT / ".github/workflows/promote-publish.yaml").read_text()
        self.assertIn("config/signing-identity.json", publisher_text)
        self.assertIn("--type cyclonedx", publisher_text)
        self.assertIn("@${CANDIDATE_DIGEST}", publisher_text)
        self.assertIn("signing-evidence.json", publisher_text)
        self.assertIn("SIGNING_RESULT", publisher_text)
        self.assertNotIn("--insecure-ignore-tlog", publisher_text)
        self.assertNotIn("gh api -X DELETE", publisher_text)
        self.assertNotIn("https://github.com/bocklabs/trusted-images/.github/workflows/promote-publish.yaml@refs/heads/main", publisher_text)

    def test_validation_reverifies_only_cosign_pin_changes(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/validate.yaml").read_text())
        self.assertNotIn("schedule", workflow.get("on", workflow.get(True, {})))
        self.assertNotIn("paths-ignore", (workflow.get("on", workflow.get(True))["pull_request"] or {}))
        self.assertIn("inventory", workflow["jobs"])
        steps = workflow["jobs"]["inventory"]["steps"]
        names = [step["name"] for step in steps]
        self.assertEqual(steps[names.index("Checkout")]["with"]["fetch-depth"], 0)
        self.assertIn("Detect Cosign verifier pin change", names)
        self.assertIn("Reverify signed provenance", names)
        history = steps[names.index("Check historical provenance")]
        self.assertNotIn("if", history)
        self.assertIn("--history-only", history["run"])
        detect = steps[names.index("Detect Cosign verifier pin change")]["run"]
        verify = steps[names.index("Reverify signed provenance")]
        self.assertIn("sigstore/cosign-installer", detect)
        self.assertIn("cosign-release", detect)
        self.assertIn(".github/workflows/validate.yaml", detect)
        self.assertIn('BASE="${BEFORE}"', detect)
        self.assertEqual(steps[names.index("Detect Cosign verifier pin change")]["env"]["BEFORE"], "${{ github.event.before }}")
        self.assertNotIn("trivy-action", detect)
        self.assertEqual(verify["if"], "steps.cosign-pin.outputs.changed == 'true'")
        install = steps[names.index("Install candidate Cosign")]
        self.assertEqual(install["with"]["cosign-release"], "${{ steps.cosign-pin.outputs.version }}")
        self.assertIn("cosign-release:", detect)
        self.assertIn("python3 scripts/reverify_signing.py --base", verify["run"])
        self.assertNotIn("<<", verify["run"])
        self.assertNotIn("continue-on-error", verify)

    def test_historical_verifier_checks_public_digest_and_attachment_hashes(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing

        identity = json.loads(IDENTITY.read_text())
        signature = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}}]).encode()
        attestation = json.dumps({"payload": base64.b64encode(json.dumps(self.statement).encode()).decode()}).encode()
        attachment = (json.dumps(self.attestation) + "\n").encode()
        expected_hash = hashlib.sha256(attachment).hexdigest()
        flags = ("--certificate-identity", identity["certificate_identity"],
                 "--certificate-oidc-issuer", identity["certificate_oidc_issuer"])

        def fake_cosign(*args):
            if args[0] == "verify":
                self.assertEqual(args, ("verify", *flags, IMAGE))
                return signature
            if args[0] == "verify-attestation":
                self.assertEqual(args, ("verify-attestation", "--type", "cyclonedx", *flags, IMAGE))
                return attestation
            self.assertIn(args, (("download", "attestation", "--predicate-type", "https://sigstore.dev/cosign/sign/v1", IMAGE),
                                 ("download", "attestation", "--predicate-type", "https://cyclonedx.org/bom", IMAGE)))
            newer = json.loads(json.dumps(self.attestation))
            newer["dsseEnvelope"]["signatures"][0]["sig"] = "bmV3"
            return attachment + (json.dumps(newer) + "\n").encode()

        with mock.patch.object(reverify_signing, "cosign", side_effect=fake_cosign):
            reverify_signing.verify(IMAGE, expected_hash, expected_hash, identity)
            with self.assertRaisesRegex(ValueError, "attachment mismatch"):
                reverify_signing.verify(IMAGE, "0" * 64, expected_hash, identity)

    def test_historical_verifier_accepts_bound_record_and_rejects_wrong_identity(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing

        identity = json.loads(IDENTITY.read_text())
        signature_bytes = (json.dumps(self.signature) + "\n").encode()
        attestation_bytes = (json.dumps(self.attestation) + "\n").encode()
        run_url = "https://github.com/bocklabs/trusted-images/actions/runs/1"
        image_signature = {**identity, "bundle_sha256": "a" * 64,
                           "attachment_sha256": hashlib.sha256(signature_bytes).hexdigest()}
        record = {
            "schema": "trusted-images.bocklabs.dev/provenance-v1", "app": "example",
            "upstream": {"tag": "v1"}, "promoted_at": "2026-09-14T01:00:00Z", "validation": {"result": "pass"},
            "pipeline": {"run_url": run_url},
            "internal": {"package": "ghcr.io/bocklabs/example", "digest": DIGEST, "tag": "v1-bocklabs.1", "platforms": ["linux/amd64"]},
            "policy": {"eligible": True},
            "signing": {
                "result": "pass",
                "image_signature": image_signature,
                "sbom_attestation": {"predicate_type": "https://cyclonedx.org/bom",
                                     "bundle_sha256": "b" * 64, "predicate_sha256": "c" * 64,
                                     "attachment_sha256": hashlib.sha256(attestation_bytes).hexdigest()},
                "tools": {"cosign": COSIGN_RELEASE, "trivy": "0.74.0"},
                "rekor": {key: {"log_index": 42, "log_id": "log", "signed_entry_timestamp": "proof"}
                          for key in ("signature", "sbom_attestation")},
            },
        }
        (self.dir / "config").mkdir()
        (self.dir / "config/signing-identity.json").write_text(json.dumps(identity))
        path = self.dir / "provenance/example/current.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(record))
        verified_signature = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}}]).encode()
        verified_attestation = json.dumps({"payload": base64.b64encode(json.dumps(self.statement).encode()).decode()}).encode()
        outputs = [verified_signature, verified_attestation, signature_bytes, attestation_bytes]
        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(
            reverify_signing, "check_history", return_value={"provenance/example/current.json"}
        ), mock.patch.object(reverify_signing, "cosign", side_effect=outputs) as verifier, mock.patch.object(
            sys, "argv", ["reverify_signing.py", "--base", "base"]
        ):
            self.assertEqual(reverify_signing.main(), 0)
            verifier.side_effect = outputs
            receipt = self.dir / "reuse-evidence.json"
            with mock.patch.object(sys, "argv", ["reverify_signing.py", "--record", str(path), "--out", str(receipt)]):
                self.assertEqual(reverify_signing.main(), 0)
                self.assertEqual(json.loads(receipt.read_text())["original_run_url"], run_url)
            image_signature["certificate_identity"] = "https://wrong.example/workflow"
            path.write_text(json.dumps(record))
            self.assertEqual(reverify_signing.main(), 1)

    def test_malformed_nested_objects_report_failure_and_allow_healthy_refresh(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing
        from tests.test_refresh_current_provenance import CurrentRefreshTests, refresh

        identity = json.loads(IDENTITY.read_bytes())
        record = self.example_record()
        for field in ("internal", "upstream", "policy", "validation"):
            malformed = json.loads(json.dumps(record))
            malformed[field] = []
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                reverify_signing.record_identity(malformed, "example")
        for field in ("signing", "image_signature", "sbom_attestation", "tools", "rekor"):
            malformed = json.loads(json.dumps(record))
            target = malformed if field == "signing" else malformed["signing"]
            target[field] = []
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, field):
                reverify_signing.signed_record(malformed, self.dir / "record.json", identity)
        with self.assertRaisesRegex(ValueError, "object"):
            reverify_signing.signed_record([], self.dir / "record.json", identity)
        malformed = json.loads(json.dumps(record))
        malformed["internal"] = []
        path, output = self.dir / "malformed.json", self.dir / "failed-signing.json"
        path.write_text(json.dumps(malformed))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/reverify_signing.py"), "--record", str(path), "--out", str(output)],
                                cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("internal", json.loads(output.read_bytes())["reason"])
        self.assertEqual(json.loads(output.read_bytes())["result"], "fail")
        quarantine = json.loads(json.dumps(record))
        quarantine["policy"] = {}
        quarantine["signing"] = {"result": "fail", "failure": "probe"}
        with self.assertRaisesRegex(ValueError, "invalid quarantine record"):
            reverify_signing.verified_record(quarantine, "example", identity)
        path.write_text(json.dumps(quarantine))
        result = subprocess.run([sys.executable, str(ROOT / "scripts/reverify_signing.py"), "--compare", str(path)],
                                cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("invalid quarantine record", result.stderr)
        cohort = CurrentRefreshTests()
        cohort.setUp()
        self.addCleanup(cohort.doCleanups)
        cohort.pulls = [cohort.owned, cohort.healthy]
        cohort.candidates["postgres-exporter"]["internal"] = []
        with self.assertRaisesRegex(ValueError, "PR 55.*internal"):
            refresh.refresh("bocklabs/trusted-images")
        self.assertEqual([call for call in cohort.calls if "PUT" in call], [("gh", "api", "--method", "PUT",
            "repos/bocklabs/trusted-images/pulls/56/update-branch", "-f", "expected_head_sha=" + "4" * 40)])
        cohort.calls.clear()
        quarantined = json.loads(json.dumps(cohort.records["postgres-exporter"]))
        quarantined["policy"] = {}
        quarantined["signing"] = {"result": "fail", "failure": "probe"}
        cohort.candidates["postgres-exporter"] = quarantined
        with self.assertRaisesRegex(ValueError, "PR 55.*invalid quarantine record"):
            refresh.refresh("bocklabs/trusted-images")
        self.assertEqual([call for call in cohort.calls if "PUT" in call], [("gh", "api", "--method", "PUT",
            "repos/bocklabs/trusted-images/pulls/56/update-branch", "-f", "expected_head_sha=" + "4" * 40)])

    def test_historical_provenance_rewrite_is_rejected(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing

        name = "provenance/example/current.json"
        original = (json.dumps(self.example_record()) + "\n").encode()
        path = self.dir / name
        path.parent.mkdir(parents=True)
        path.write_bytes(original)
        (self.dir / "config").mkdir()
        (self.dir / "config/signing-identity.json").write_bytes(IDENTITY.read_bytes())

        def git_output(args, **_kwargs):
            return (name + "\n").encode() if args[1] == "ls-tree" else original

        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(
            reverify_signing.subprocess, "check_output", side_effect=git_output
        ), mock.patch.object(reverify_signing, "signed_record", return_value=("image", "sig", "sbom")):
            self.assertEqual(reverify_signing.signed_records("base", {}), [("image", "sig", "sbom")])
            changed = json.loads(original)
            changed["pipeline"]["run_url"] = "https://changed.test/run"
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "same identity"):
                reverify_signing.signed_records("base", {})
            changed["internal"]["tag"] = "v1-bocklabs.2"
            changed["promoted_at"] = "2099-01-01T00:00:00Z"
            path.write_text(json.dumps(changed))
            self.assertEqual(reverify_signing.signed_records("base", {}), [("image", "sig", "sbom")])
            path.unlink()
            with self.assertRaisesRegex(ValueError, "current provenance missing"):
                reverify_signing.signed_records("base", {})

    def test_migration_selects_signed_current_and_preserves_unsigned_legacy_bytes(self):
        import reverify_signing
        identity = json.loads(IDENTITY.read_bytes())
        (self.dir / "config").mkdir()
        (self.dir / "config/signing-identity.json").write_bytes(IDENTITY.read_bytes())
        signed = self.example_record()
        signed["promoted_at"] = "2026-10-01T00:00:00Z"
        unsigned = json.loads(json.dumps(signed))
        unsigned.pop("signing")
        unsigned["internal"]["tag"] = "v1-bocklabs.2"
        unsigned["promoted_at"] = "2026-10-02T00:00:00Z"
        legacy = json.loads(json.dumps(unsigned))
        legacy.update(app="legacy", upstream={**legacy["upstream"], "tag": "nonroot"})
        legacy["internal"].update(package="ghcr.io/bocklabs/legacy", tag="nonroot-bocklabs.1")
        inputs = {"provenance/example/v1-bocklabs.1.json": (json.dumps(signed) + "\n").encode(),
                  "provenance/example/v1-bocklabs.2.json": (json.dumps(unsigned) + "\n").encode(),
                  "provenance/legacy/nonroot-bocklabs.1.json": (json.dumps(legacy) + "\n").encode()}
        for name, data in inputs.items():
            path = self.dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        def git_output(*args):
            return ("\n".join(inputs) + "\n").encode() if args[0] == "ls-tree" else inputs[args[1].split(":", 1)[1]]
        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(reverify_signing, "git", side_effect=git_output):
            selected = reverify_signing.migrate_current(identity)
            self.assertEqual(selected["example"], inputs["provenance/example/v1-bocklabs.1.json"])
            self.assertEqual(selected["legacy"], inputs["provenance/legacy/nonroot-bocklabs.1.json"])
            self.assertEqual(reverify_signing.check_history("base"), {"provenance/example/current.json"})
            self.assertEqual(sorted(str(p.relative_to(self.dir)) for p in (self.dir / "provenance").rglob("*.json")),
                             ["provenance/example/current.json", "provenance/legacy/current.json"])
            (self.dir / "provenance/example/v1-bocklabs.2.json").write_bytes(inputs["provenance/example/v1-bocklabs.2.json"])
            with self.assertRaisesRegex(ValueError, "one regular current"):
                reverify_signing.check_history("base")
    def test_historical_verifier_empty_window(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing

        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(
            reverify_signing, "check_history", return_value=set()
        ):
            self.assertEqual(reverify_signing.signed_records("base", json.loads(IDENTITY.read_text())), [])
            quarantined = self.dir / "provenance/example/one.json"
            quarantined.parent.mkdir(parents=True)
            quarantined.write_text(json.dumps({"signing": {"result": "fail", "failure": "verification failed"}, "policy": {"eligible": False}}))
            self.assertEqual(reverify_signing.signed_records("base", json.loads(IDENTITY.read_text())), [])



if __name__ == "__main__":
    unittest.main()
