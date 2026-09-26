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
        self.statement = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": "ghcr.io/bocklabs/example", "digest": {"sha256": DIGEST[7:]}}],
            "predicateType": "https://cyclonedx.org/bom",
            "predicate": {"bomFormat": "CycloneDX", "specVersion": "1.6"},
        }
        self.signature = bundle({"messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": "YQ=="}, "signature": "c2ln"}})
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
    print(json.dumps([{"critical": {"image": {"docker-manifest-digest": os.environ["DIGEST"]}}}]))
elif args[0] == "verify-attestation" and scenario == "missing-attestation":
    sys.exit(1)
elif args[0] == "verify-attestation":
    statement = json.loads((root / "statement.json").read_text())
    print(json.dumps([{"payload": __import__("base64").b64encode(json.dumps(statement).encode()).decode()}]))
elif args[:2] == ["download", "signature"]:
    signature = json.loads((root / "sign-bundle.json").read_text())["messageSignature"]["signature"]
    payload = {"Critical": {"Image": {"Docker-manifest-digest": "sha256:" + "b" * 64 if scenario == "wrong-download-digest" else os.environ["DIGEST"]}}}
    if scenario == "detached-attachment":
        signature = "b3RoZXI="
    print(json.dumps({"Base64Signature": []} if scenario == "malformed-download" else {"Base64Signature": signature, "Payload": __import__("base64").b64encode(json.dumps(payload).encode()).decode()}))
elif args[:2] == ["download", "attestation"]:
    print(json.dumps(json.loads((root / "sbom-bundle.json").read_text())["dsseEnvelope"]))
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

    def test_missing_artifacts_and_command_error_fail(self):
        for scenario in ("missing-signature", "missing-attestation", "command-error", "detached-attachment", "wrong-download-digest", "malformed-download", "bad-version"):
            with self.subTest(scenario=scenario):
                result = self.run_gate(scenario)
                self.assertNotEqual(result.returncode, 0)
                evidence = json.loads((self.dir / "signing-evidence.json").read_text())
                self.assertEqual(evidence["result"], "fail")
                self.assertNotIn("signature", evidence)
                if scenario == "malformed-download":
                    self.assertIn("lacks signature or payload", evidence["reason"])
                elif scenario == "wrong-download-digest":
                    self.assertIn("subject digest differs", evidence["reason"])
                elif scenario == "detached-attachment":
                    self.assertIn("differs from local bundle", evidence["reason"])

    def test_bad_digest_or_bundle_fails(self):
        self.statement["subject"][0]["digest"]["sha256"] = "b" * 64
        (self.dir / "statement.json").write_text(json.dumps(self.statement))
        self.assertNotEqual(self.run_gate().returncode, 0)
        self.signature["verificationMaterial"]["tlogEntries"] = []
        (self.dir / "sign-bundle.json").write_text(json.dumps(self.signature))
        self.assertNotEqual(self.run_gate().returncode, 0)
        (self.dir / "sign-bundle.json").write_text("{")
        self.assertNotEqual(self.run_gate().returncode, 0)
        self.assertNotEqual(self.run_gate(image="ghcr.io/bocklabs/example:latest").returncode, 0)

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
        self.assertIn("inventory", workflow["jobs"])
        steps = workflow["jobs"]["inventory"]["steps"]
        names = [step["name"] for step in steps]
        self.assertEqual(steps[names.index("Checkout")]["with"]["fetch-depth"], 0)
        self.assertIn("Detect Cosign verifier pin change", names)
        self.assertIn("Reverify signed provenance", names)
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
        attestation = json.dumps([{"payload": base64.b64encode(json.dumps(self.statement).encode()).decode()}]).encode()
        attachment = b"public attachment\n"
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
            self.assertIn(args, (("download", "signature", IMAGE),
                                 ("download", "attestation", "--predicate-type", "https://cyclonedx.org/bom", IMAGE)))
            return attachment

        with mock.patch.object(reverify_signing, "cosign", side_effect=fake_cosign):
            reverify_signing.verify(IMAGE, expected_hash, expected_hash, identity)
            with self.assertRaisesRegex(ValueError, "attachment mismatch"):
                reverify_signing.verify(IMAGE, "0" * 64, expected_hash, identity)

    def test_historical_verifier_empty_window_and_record_loss(self):
        sys.path.insert(0, str(ROOT / "scripts"))
        self.addCleanup(sys.path.remove, str(ROOT / "scripts"))
        import reverify_signing

        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(
            reverify_signing, "old_signed_paths", return_value=set()
        ):
            self.assertEqual(reverify_signing.signed_records("base", json.loads(IDENTITY.read_text())), [])
            quarantined = self.dir / "provenance/example/one.json"
            quarantined.parent.mkdir(parents=True)
            quarantined.write_text(json.dumps({"signing": {"result": "fail", "failure": "verification failed"}, "policy": {"eligible": False}}))
            self.assertEqual(reverify_signing.signed_records("base", json.loads(IDENTITY.read_text())), [])
        with mock.patch.object(reverify_signing, "ROOT", self.dir), mock.patch.object(
            reverify_signing, "old_signed_paths", return_value={"provenance/example/one.json"}
        ):
            with self.assertRaisesRegex(ValueError, "lost its evidence"):
                reverify_signing.signed_records("base", json.loads(IDENTITY.read_text()))
            quarantined.unlink()
            with self.assertRaisesRegex(ValueError, "missing signed record"):
                reverify_signing.signed_records("base", json.loads(IDENTITY.read_text()))


if __name__ == "__main__":
    unittest.main()
