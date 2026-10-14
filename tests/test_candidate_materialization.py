import shlex
import unittest
from pathlib import Path

import yaml


class CandidateMaterializationTests(unittest.TestCase):
    def test_scan_and_runtime_archive_are_materialized_from_final_oci(self) -> None:
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/promote-candidate.yaml").read_text())
        steps = workflow["jobs"]["validate"]["steps"]
        run = next(step["run"] for step in steps if step.get("id") == "patched")
        command = next(line.strip() for line in run.replace("\\\n", "").splitlines()
                       if "copy --format v2s2 oci:" in line)
        self.assertEqual(shlex.split(command)[-2:], ["oci:/workspace/candidate-oci:candidate",
                                                   "docker-archive:/workspace/candidate-final.tar:copa:final"])
        ordered = [run.index(token) for token in ("rm candidate-final.tar", "copy --format v2s2 oci:",
                   "docker load --input candidate-final.tar", "FINAL_IMAGE_ID=", '[ "${FINAL_IMAGE_ID}" = "$(jq -er .config.digest candidate-manifest.json)" ]',
                   'echo "image_id=${FINAL_IMAGE_ID}"')]
        self.assertEqual(ordered, sorted(ordered))
        scan = next(step for step in steps if step.get("id") == "scanafter")
        self.assertEqual(scan["with"]["input"], "candidate-final.tar")
