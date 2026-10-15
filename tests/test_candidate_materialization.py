import copy
import hashlib
import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from finalize_candidate_config import finalize
from validate_image import label_drift


class CandidateMaterializationTests(unittest.TestCase):
    def test_finalizer_removes_only_new_tool_labels_and_rebinds_descriptors(self) -> None:
        original: dict = {"Labels": {"sh.copa.chisel.version": "original"}}
        candidate: dict = {"architecture": "amd64", "config": {"Labels": {
            "sh.copa.chisel.version": "changed", "sh.copa.chisel.release": "ubuntu-24.04",
            "unknown.extra": "keep"}}, "rootfs": {"diff_ids": ["sha256:" + "a" * 64]}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            blobs = root / "blobs/sha256"
            blobs.mkdir(parents=True)
            def put(value: dict, media_type: str) -> dict:
                raw = json.dumps(value).encode()
                digest = hashlib.sha256(raw).hexdigest()
                (blobs / digest).write_bytes(raw)
                return {"digest": "sha256:" + digest, "size": len(raw), "mediaType": media_type}
            manifest: dict = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": put(candidate, "application/vnd.oci.image.config.v1+json"),
                        "layers": [{"digest": "sha256:" + "a" * 64, "size": 123}]}
            index = {"schemaVersion": 2, "manifests": [put(manifest, manifest["mediaType"])]}
            (root / "index.json").write_text(json.dumps(index))
            baseline = root / "original.json"
            baseline.write_text(json.dumps({"config": original}))
            finalize(root, baseline)
            descriptor = json.loads((root / "index.json").read_bytes())["manifests"][0]
            final_manifest_raw = (blobs / descriptor["digest"][7:]).read_bytes()
            self.assertEqual((len(final_manifest_raw), "sha256:" + hashlib.sha256(final_manifest_raw).hexdigest()),
                             (descriptor["size"], descriptor["digest"]))
            final_manifest = json.loads(final_manifest_raw)
            config_descriptor = final_manifest["config"]
            final_config_raw = (blobs / config_descriptor["digest"][7:]).read_bytes()
            self.assertEqual((len(final_config_raw), "sha256:" + hashlib.sha256(final_config_raw).hexdigest()),
                             (config_descriptor["size"], config_descriptor["digest"]))
            expected = copy.deepcopy(candidate)
            del expected["config"]["Labels"]["sh.copa.chisel.release"]
            self.assertEqual(json.loads(final_config_raw), expected)
            self.assertEqual(final_manifest["layers"], manifest["layers"])
            drift = label_drift(original, expected["config"], "", "")
            self.assertTrue(any("sh.copa.chisel.version" in item for item in drift))
            self.assertTrue(any("unknown.extra" in item for item in drift))
            unchanged = {path.name: path.read_bytes() for path in blobs.iterdir()}
            index_bytes = (root / "index.json").read_bytes()
            finalize(root, baseline)
            self.assertEqual((root / "index.json").read_bytes(), index_bytes)
            self.assertEqual({path.name: path.read_bytes() for path in blobs.iterdir()}, unchanged)
            broken = json.loads(index_bytes)
            broken["manifests"][0]["size"] += 1
            (root / "index.json").write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, "digest or size mismatch"):
                finalize(root, baseline)
            broken["manifests"].append(broken["manifests"][0])
            (root / "index.json").write_text(json.dumps(broken))
            with self.assertRaisesRegex(ValueError, "one image manifest"):
                finalize(root, baseline)

    def test_scan_and_runtime_archive_are_materialized_from_final_oci(self) -> None:
        workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/promote-candidate.yaml").read_text())
        steps = workflow["jobs"]["validate"]["steps"]
        run = next(step["run"] for step in steps if step.get("id") == "patched")
        self.assertLess(run.index("python3 scripts/finalize_candidate_config.py candidate-oci child-config.json"),
                        run.index("CANDIDATE_MANIFEST_DIGEST="))
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
