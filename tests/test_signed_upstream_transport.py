"""Signed registry images remain digest-preserving when copied to OCI storage."""

import unittest
from pathlib import Path

from tests.workflow_helpers import load_workflow


class SignedUpstreamTransportTests(unittest.TestCase):
    def test_upstream_oci_copies_exclude_unsupported_signature_attachments(self) -> None:
        root = Path(__file__).parents[1]
        workflow = load_workflow(root / ".github/workflows/promote-candidate.yaml")
        steps = workflow["jobs"]["validate"]["steps"]
        for name in ("Resolve the exact linux/amd64 child", "Export checksum-bound candidate artifact"):
            run = next(step["run"] for step in steps if step["name"] == name)
            self.assertIn("copy_source_oci", run)
        registry = (root / "scripts/lib/registry.sh").read_text(encoding="utf-8")
        self.assertIn("copy --retry-times 3 --preserve-digests --remove-signatures", registry)
