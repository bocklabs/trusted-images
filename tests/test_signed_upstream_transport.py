"""Signed registry images remain digest-preserving when copied to OCI storage."""

import shlex
import unittest
from pathlib import Path

import yaml


class SignedUpstreamTransportTests(unittest.TestCase):
    def test_upstream_oci_copies_exclude_unsupported_signature_attachments(self) -> None:
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/promote-candidate.yaml").read_text())
        steps = workflow["jobs"]["validate"]["steps"]
        for name in ("Resolve the exact linux/amd64 child", "Export checksum-bound candidate artifact"):
            run = next(step["run"] for step in steps if step["name"] == name)
            command = next(line.strip() for line in run.splitlines() if line.lstrip().startswith("copy "))
            arguments = shlex.split(command.rstrip("\\"))
            self.assertIn("--preserve-digests", arguments)
            self.assertIn("--remove-signatures", arguments)
